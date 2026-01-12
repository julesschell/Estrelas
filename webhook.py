# webhook.py
import os, re, json, hmac, base64, hashlib, requests, io, tempfile, subprocess, shlex, mimetypes, time, uuid
from datetime import datetime
from dotenv import load_dotenv
from flask import Flask, request, abort, jsonify, render_template, url_for
from typing import Optional, Tuple
from collections import defaultdict, deque

from PIL import Image  # Pillow

load_dotenv()
app = Flask(__name__)

# Bucket privé B2 : upload -> (file_id, file_name), lien signé à la demande
from b2_utils import upload_file_to_b2, get_signed_download_url

# ========================
# Config Shopify (ENV)
# ========================
SHOPIFY_SECRET = os.getenv("SHOPIFY_SECRET")
if not SHOPIFY_SECRET:
    raise RuntimeError("SHOPIFY_SECRET doit être défini dans .env")

SHOPIFY_SHOP = os.getenv("SHOPIFY_SHOP")
SHOPIFY_ADMIN_TOKEN = os.getenv("SHOPIFY_ADMIN_TOKEN")
SHOPIFY_API_VERSION = os.getenv("SHOPIFY_API_VERSION")

# ========================
# === Anti brute-force (in-memory, par IP/UUID) ===
#     Variables d'env optionnelles :
#       RATE_WINDOW_SEC   (défaut 60)
#       RATE_MAX_PER_IP   (défaut 120)   -> toutes routes publiques confondues
#       RATE_MAX_PER_UUID (défaut 40)    -> par IP ET par UUID /b/<uuid>
#       RATE_BAN_SEC      (défaut 300)
# ========================
RATE_WINDOW_SEC   = int(os.getenv("RATE_WINDOW_SEC", "60"))
RATE_MAX_PER_IP   = int(os.getenv("RATE_MAX_PER_IP", "120"))
RATE_MAX_PER_UUID = int(os.getenv("RATE_MAX_PER_UUID", "40"))
RATE_BAN_SEC      = int(os.getenv("RATE_BAN_SEC", "300"))
app.config["MAX_CONTENT_LENGTH"] = 320 * 1024 * 1024  # à ajuster

class SlidingLimiter:
    def __init__(self):
        self.hits = defaultdict(deque)  # key -> deque[timestamps]
        self.bans = {}                  # key -> banned_until (epoch)

    def check(self, key: str, limit: int, window_sec: int, ban_sec: int) -> tuple[bool, int]:
        now = time.time()
        until = self.bans.get(key)
        if until and now < until:
            return False, max(1, int(until - now))

        dq = self.hits[key]
        # prune hors fenêtre
        while dq and now - dq[0] > window_sec:
            dq.popleft()

        if len(dq) >= limit:
            self.bans[key] = now + ban_sec
            dq.clear()
            return False, ban_sec

        dq.append(now)
        # GC léger : éviter de grossir inutilement
        if len(dq) > limit * 2:
            while dq and len(dq) > limit * 2:
                dq.popleft()
        return True, 0

limiter = SlidingLimiter()

def client_ip() -> str:
    xf = request.headers.get("X-Forwarded-For", "")
    if xf:
        return xf.split(",")[0].strip()
    return request.remote_addr or "unknown"

def ratelimit_or_429(keys_limits: list[tuple[str,int,int,int]]):
    """
    keys_limits: liste de (key, limit, window_sec, ban_sec).
    Retourne None si OK, sinon une réponse 429.
    """
    retry_after = 0
    for key, limit, win, ban in keys_limits:
        ok, wait = limiter.check(key, limit, win, ban)
        if not ok:
            retry_after = max(retry_after, wait)
    if retry_after > 0:
        msg = f"Trop de requêtes. Réessaie dans ~{retry_after}s."
        return (msg, 429, {"Retry-After": str(retry_after)})
    return None

# ========================
# API Admin Shopify
# ========================
def shopify_admin(path: str, method="GET", payload=None, timeout=20, attempts=3):
    """
    Appel REST Admin Shopify signé. Exemples:
      - 'orders/123.json'
      - 'orders/123/metafields.json'
      - 'metafields/456.json'
    """
    if not (SHOPIFY_SHOP and SHOPIFY_ADMIN_TOKEN):
        print("[SHOPIFY] SHOP/TOKEN manquants (.env)", flush=True)
        return None

    import time as _time, requests as _requests
    url = f"https://{SHOPIFY_SHOP}/admin/api/{SHOPIFY_API_VERSION}/{path.lstrip('/')}"
    headers = {
        "X-Shopify-Access-Token": SHOPIFY_ADMIN_TOKEN,
        "Content-Type": "application/json",
        "Accept": "application/json",
    }

    for attempt in range(1, attempts + 1):
        try:
            r = _requests.request(method, url, headers=headers, json=payload, timeout=timeout)
            if r.status_code in (429, 500, 502, 503, 504):
                wait = min(2 ** attempt, 8)
                print(f"[SHOPIFY] {method} {path} -> {r.status_code}, retry in {wait}s", flush=True)
                _time.sleep(wait)
                continue
            if r.status_code >= 400:
                print(f"[SHOPIFY] {method} {path} -> {r.status_code} {r.text[:300]}", flush=True)
                return None
            return r.json() if r.content else {}
        except Exception as e:
            print(f"[SHOPIFY] Exception {method} {path}: {e}", flush=True)
            return None
    return None

def _get_order_note(order_id: int) -> str:
    data = shopify_admin(f"orders/{order_id}.json")
    return (data or {}).get("order", {}).get("note") or ""

def _set_order_note(order_id: int, note_text: str):
    shopify_admin(f"orders/{order_id}.json", method="PUT",
                  payload={"order": {"id": order_id, "note": note_text}})

def attach_urls_to_shopify_order_note_only(order_id: int, entries: list[dict]):
    if not order_id or not entries:
        return
    # Lire note actuelle
    cur_note = _get_order_note(order_id) or ""
    lines = [ln for ln in cur_note.splitlines() if ln.strip()]
    existing = {ln.split("→", 1)[-1].strip() for ln in lines if "→" in ln}

    changed = False
    for e in entries:
        url = e["url"]
        if url not in existing:
            lines.append(f"Bracelet {e['uuid']} → {url}")
            existing.add(url)
            changed = True

    if changed:
        _set_order_note(order_id, "\n".join(lines))

# ========================
# DB helpers
# ========================
import mysql.connector
def db_connect():
    return mysql.connector.connect(
        host=os.getenv("DB_HOST"),
        user=os.getenv("DB_USER"),
        password=os.getenv("DB_PASSWORD"),
        database=os.getenv("DB_NAME")
    )

def create_unique_bracelet_uuid() -> str:
    """
    Génère un identifiant court et lisible (ex: BR-3F9E1A2BC4D7)
    et vérifie qu'il n'existe pas déjà en DB.
    """
    conn = db_connect(); cur = conn.cursor()
    try:
        while True:
            cand = "BR-" + uuid.uuid4().hex[:12].upper()
            cur.execute("SELECT 1 FROM bracelets WHERE uuid = %s", (cand,))
            if not cur.fetchone():
                return cand
    finally:
        cur.close(); conn.close()


def get_or_create_uuid_for_line_item(order_id: int, line_item_id: int, produit: str) -> str:
    """
    Idempotent: si un UUID est déjà associé à (order_id, line_item_id),
    on le réutilise. Sinon on en crée un nouveau et on crée le bracelet (vide).
    """
    # 1) Déjà mappé ?
    conn = db_connect(); cur = conn.cursor(dictionary=True)
    try:
        cur.execute(
            "SELECT bracelet_uuid FROM bracelet_items "
            "WHERE shopify_order_id=%s AND shopify_line_item_id=%s",
            (order_id, line_item_id)
        )
        row = cur.fetchone()
        if row and row.get("bracelet_uuid"):
            return row["bracelet_uuid"]
    finally:
        cur.close(); conn.close()

    # 2) Nouveau UUID
    new_uuid = create_unique_bracelet_uuid()

    # 3) Créer le bracelet vide
    ensure_bracelet_and_assets(new_uuid, produit, [])

    # 4) Mapper la line item à cet UUID (protégé par UNIQUE)
    conn = db_connect(); cur = conn.cursor()
    try:
        cur.execute(
            "INSERT IGNORE INTO bracelet_items "
            "(bracelet_uuid, shopify_order_id, shopify_line_item_id, quantity, created_at) "
            "VALUES (%s, %s, %s, %s, %s)",
            (new_uuid, order_id, line_item_id, 1, datetime.now())
        )
        conn.commit()

        # Si doublon (webhook rejoué), relire l'UUID existant
        if cur.rowcount == 0:
            cur.close(); conn.close()
            conn = db_connect(); cur = conn.cursor(dictionary=True)
            cur.execute(
                "SELECT bracelet_uuid FROM bracelet_items "
                "WHERE shopify_order_id=%s AND shopify_line_item_id=%s",
                (order_id, line_item_id)
            )
            row = cur.fetchone()
            if row and row.get("bracelet_uuid"):
                return row["bracelet_uuid"]
    finally:
        cur.close(); conn.close()

    return new_uuid

# ========================
# Traitements média (image/vidéo)
# ========================
def _compute_source_rect_from_meta(meta, nat_w, nat_h):
    """
    Inverse le rendu front (scale+offset dans un viewport 9:16) pour obtenir
    le rectangle source à extraire dans l'image originale.
    meta attendu:
      { "scale": float, "offset": {"x": px, "y": px}, "frame": {"w": px, "h": px} }
    """
    scale = float(meta.get("scale", 1.0))
    off = meta.get("offset") or {}
    off_x = float(off.get("x", 0.0))
    off_y = float(off.get("y", 0.0))

    frame = meta.get("frame") or {}
    frame_w = int(frame.get("w") or 220)
    frame_h = int(frame.get("h") or int(round(220 * 16 / 9)))

    # Position de l'image (après scale + offset) dans le frame
    pos_x = (frame_w / 2.0 + off_x) - (nat_w * scale) / 2.0
    pos_y = (frame_h / 2.0 + off_y) - (nat_h * scale) / 2.0

    # Rect visible du frame, en coords source (avant scale)
    sx = max(0.0, (0.0 - pos_x) / scale)
    sy = max(0.0, (0.0 - pos_y) / scale)
    sw = min(nat_w - sx, frame_w / scale)
    sh = min(nat_h - sy, frame_h / scale)

    # clamp final
    sx = max(0.0, min(sx, nat_w - 1))
    sy = max(0.0, min(sy, nat_h - 1))
    sw = max(1.0, min(sw, nat_w - sx))
    sh = max(1.0, min(sh, nat_h - sy))
    return (int(round(sx)), int(round(sy)), int(round(sw)), int(round(sh)))

def process_image_with_crop(content_bytes: bytes, mime_type: str, meta: dict,
                            out_w=900, out_h: Optional[int]=None) -> Tuple[bytes, str, str]:
    """
    Compose l'image dans un canvas 9:16 selon scale/offset (comme l'UI).
    Supporte le dézoom (letterbox blanc si l'image ne remplit pas tout).
    Retourne (bytes JPEG, 'image/jpeg', '-cropped.jpg').
    """
    if out_h is None:
        out_h = int(round(out_w * 16 / 9))

    with Image.open(io.BytesIO(content_bytes)) as im:
        im = im.convert("RGBA")
        nat_w, nat_h = im.width, im.height

        # Lecture des meta envoyées par le front
        scale = float(meta.get("scale", 1.0))
        off = meta.get("offset") or {}
        off_x = float(off.get("x", 0.0))
        off_y = float(off.get("y", 0.0))

        frame = meta.get("frame") or {}
        frame_w = int(frame.get("w") or 220)
        frame_h = int(frame.get("h") or int(round(220 * 16 / 9)))

        # Dimensions dessinées dans le frame (comme le front)
        draw_w = nat_w * scale
        draw_h = nat_h * scale
        pos_x = (frame_w / 2.0 + off_x) - draw_w / 2.0
        pos_y = (frame_h / 2.0 + off_y) - draw_h / 2.0

        # Mise à l'échelle frame -> sortie finale 9:16
        kf = out_w / float(frame_w)  # (out_h/frame_h) identique car 9:16

        # Prépare le fond blanc + conversion en RGB
        if im.mode == "RGBA":
            src_rgb = Image.new("RGB", (nat_w, nat_h), (255, 255, 255))
            src_rgb.paste(im, mask=im.split()[-1])
        else:
            src_rgb = im.convert("RGB")

        # Redimensionne l'image selon le zoom demandé
        dw = max(1, int(round(draw_w * kf)))
        dh = max(1, int(round(draw_h * kf)))
        dx = int(round(pos_x * kf))
        dy = int(round(pos_y * kf))

        resized = src_rgb.resize((dw, dh), Image.LANCZOS)

        # Compose dans un canvas final 9:16 (letterbox si nécessaire)
        canvas = Image.new("RGB", (out_w, out_h), (255, 255, 255))
        # La pastille peut dépasser : PIL tronque automatiquement les bords hors-cadre
        canvas.paste(resized, (dx, dy))

        out_io = io.BytesIO()
        canvas.save(out_io, format="JPEG", quality=92, optimize=True)
        return out_io.getvalue(), "image/jpeg", "-cropped.jpg"


def process_video_with_ffmpeg(content_bytes: bytes, meta: dict,
                              out_w=900, out_h: Optional[int]=None) -> Tuple[bytes, str, str]:
    if out_h is None:
        out_h = int(round(out_w * 16 / 9))

    passthrough = bool(meta.get("passthrough"))
    keep_audio  = True if meta.get("keepAudio") is None else bool(meta.get("keepAudio"))

    # Construire le filtre vidéo (letterbox→zoom crop 9:16 sans distorsion)
    vf = f"scale={out_w}:{out_h}:force_original_aspect_ratio=increase,crop={out_w}:{out_h},setsar=1"

    # Construire la partie trim uniquement si demandé
    trim_args = ""
    if not passthrough and ("start" in meta or "end" in meta):
        start = float(meta.get("start") or 0.0)
        if "end" in meta and meta.get("end") is not None:
            end = float(meta.get("end"))
            duration = max(0.01, end - start)
            trim_args = f"-ss {start:.3f} -t {duration:.3f} "
        else:
            # start sans end → on part de start jusqu’à la fin
            trim_args = f"-ss {start:.3f} "

    with tempfile.TemporaryDirectory() as tmp:
        in_path  = os.path.join(tmp, "in.bin")
        out_path = os.path.join(tmp, "out.mp4")
        with open(in_path, "wb") as f:
            f.write(content_bytes)

        maps = "-map 0:v:0 "
        if keep_audio:
            maps += "-map 0:a:0? "

        cmd = (
            f'ffmpeg -hide_banner -loglevel error '
            f'{trim_args}-i {shlex.quote(in_path)} '
            f'-vf {shlex.quote(vf)} '
            f'{maps}'
            f'-c:v libx264 -preset veryfast -crf 23 '
            f'{"-c:a aac -b:a 192k " if keep_audio else "-an "}'
            f'-movflags +faststart {shlex.quote(out_path)}'
        )

        subprocess.run(cmd, shell=True, check=True)
        with open(out_path, "rb") as f:
            out_bytes = f.read()

    return out_bytes, "video/mp4", ("-proc.mp4" if passthrough or not trim_args else "-trim.mp4")

# ========================
# Sauvegarde (avec traitement)
# ========================
def save_souvenirs(uuid, souvenirs):
    conn = db_connect()
    cursor = conn.cursor()
    try:
        insert_sql = (
            # ⬇️ UPSERT: si doublon (uuid,file_name) -> on met à jour qq champs
            "INSERT INTO souvenirs (bracelet_uuid, titre, description, file_id, file_name, mime_type) "
            "VALUES (%(bracelet_uuid)s, %(titre)s, %(description)s, %(file_id)s, %(file_name)s, %(mime_type)s) "
            "ON DUPLICATE KEY UPDATE "
            "  titre=VALUES(titre), "
            "  description=VALUES(description), "
            "  mime_type=VALUES(mime_type)"
        )

        for s in souvenirs:
            src_url = (s.get("fichier") or "").strip()
            titre   = (s.get("titre") or "").strip()
            descr   = (s.get("description") or "").strip()
            crop    = s.get("crop")

            file_id = file_name = mime_type = None
            upload_bytes = None

            if src_url:
                try:
                    r = requests.get(src_url, timeout=30)
                    if r.status_code == 200:
                        content   = r.content
                        mime_type = r.headers.get("Content-Type") or mimetypes.guess_type(src_url)[0] or "application/octet-stream"
                        base_name = os.path.basename(src_url.split("?", 1)[0])

                        try:
                            if crop and isinstance(crop, dict):
                                if mime_type.startswith("image/"):
                                    upload_bytes, mime_type, suffix = process_image_with_crop(content, mime_type, crop)
                                    base_name = re.sub(r"\.[^.]+$", "", base_name) + suffix
                                elif mime_type.startswith("video/"):
                                    upload_bytes, mime_type, suffix = process_video_with_ffmpeg(content, crop)
                                    base_name = re.sub(r"\.[^.]+$", "", base_name) + suffix
                        except Exception as e:
                            print(f"[PROC] Erreur traitement media (fallback original): {e}", flush=True)
                            upload_bytes = None

                        if upload_bytes is None:
                            upload_bytes = content  # pas de crop/trim -> upload original

                        file_name_key = f"{uuid}/{base_name}"
                        res = upload_file_to_b2(upload_bytes, file_name_key, content_type=mime_type)
                        if res:
                            file_id   = res["file_id"]
                            file_name = res["file_name"]  # nom réel côté B2
                            print(f"✅ Upload B2 OK: {file_name}", flush=True)
                        else:
                            print(f"⚠️ Upload B2 échec: {file_name_key}", flush=True)
                    else:
                        print(f"⚠️ Download Shopify échec: {src_url} ({r.status_code})", flush=True)
                except Exception as e:
                    print(f"⚠️ Exception download/upload: {e}", flush=True)

            # ⬇️ IMPORTANT: n’insère pas si pas de fichier uploadé (évite lignes “vides”)
            if not file_name:
                print(f"[DB] Skip insert: pas de file_name pour {src_url}", flush=True)
                continue

            data = {
                "bracelet_uuid": uuid,
                "titre": titre,
                "description": descr,
                "file_id": file_id,
                "file_name": file_name,
                "mime_type": mime_type
            }
            try:
                cursor.execute(insert_sql, data)
            except Exception as e:
                print(f"[DB] INSERT/UPSERT KO uuid={uuid}, file_name={file_name} err={e}", flush=True)

        conn.commit()
    except Exception as e:
        conn.rollback()
        print(f"❌ DB error (souvenirs): {e}", flush=True)
        raise
    finally:
        cursor.close()
        conn.close()


# ========================
# Ensure bracelet + assets
# ========================
def ensure_bracelet_and_assets(uuid, produit, souvenirs):
    # créer le bracelet si absent
    conn = db_connect(); cur = conn.cursor()
    try:
        cur.execute(
            "INSERT IGNORE INTO bracelets (uuid, produit, date_creation) VALUES (%s, %s, %s)",
            (uuid, produit, datetime.now())
        )
        conn.commit()
    finally:
        cur.close(); conn.close()

    # si aucun souvenir enregistré pour ce uuid, on charge les fichiers et on insère
    conn = db_connect(); cur = conn.cursor()
    try:
        cur.execute("SELECT COUNT(*) FROM souvenirs WHERE bracelet_uuid=%s", (uuid,))
        (cnt,) = cur.fetchone()
    finally:
        cur.close(); conn.close()

    if not cnt or cnt == 0:
        save_souvenirs(uuid, souvenirs)

# ========================
# URL publique
# ========================
def build_public_url_for_uuid(uuid: str) -> str:
    base = os.getenv("PUBLIC_BASE_URL")
    if base:
        return base.rstrip("/") + f"/b/{uuid}"
    try:
        return url_for("view_bracelet_public_uuid", uuid=uuid, _external=True)
    except RuntimeError:
        return f"/b/{uuid}"

@app.post("/webhook/order-created")
def webhook_order_created():
    # Vérif HMAC (body brut)
    hmac_header = request.headers.get("X-Shopify-Hmac-Sha256", "")
    raw = request.get_data()  # bytes
    digest = hmac.new(SHOPIFY_SECRET.encode("utf-8"), raw, hashlib.sha256).digest()
    computed = base64.b64encode(digest).decode()
    if not hmac_header or not hmac.compare_digest(computed, hmac_header):
        abort(403)

    # (Optionnel) s'assurer qu'on traite bien orders/create
    topic = request.headers.get("X-Shopify-Topic", "")
    if topic and topic != "orders/create":
        return jsonify({"ok": True, "ignored_topic": topic}), 200

    # Récup payload JSON
    payload = request.get_json(silent=True) or {}
    order_id = payload.get("id")
    line_items = payload.get("line_items") or []

    if not order_id or not isinstance(line_items, list):
        return jsonify({"ok": False, "error": "missing_order_id_or_line_items"}), 400

    entries = []
    for item in line_items:
        produit = item.get("title") or "Bracelet"
        try:
            qty = int(item.get("quantity") or 1)
        except Exception:
            qty = 1
        qty = max(1, qty)

        for _ in range(qty):
            br_uuid = create_unique_bracelet_uuid()
            conn = db_connect(); cur = conn.cursor()
            try:
                cur.execute(
                    "INSERT IGNORE INTO bracelets (uuid, produit, date_creation) VALUES (%s, %s, NOW())",
                    (br_uuid, produit)
                )
                conn.commit()
            finally:
                cur.close(); conn.close()

            entries.append({"uuid": br_uuid, "url": build_public_url_for_uuid(br_uuid)})

    if entries:
        attach_urls_to_shopify_order_note_only(order_id, entries)

    return jsonify({"ok": True, "order_id": order_id, "links": entries}), 200



# ========================
# Lien signé temporaire pour un fichier (bucket privé)
# ========================

@app.route("/api/bracelets/<uuid>/lock", methods=["POST"])
def lock_bracelet(uuid):
    """Idempotent : marque le bracelet comme verrouillé une bonne fois."""
    conn = db_connect(); cur = conn.cursor()
    try:
        cur.execute(
            "UPDATE bracelets SET locked_at = COALESCE(locked_at, %s) WHERE uuid = %s",
            (datetime.now(), uuid)
        )
        conn.commit()
        return jsonify({"ok": True}), 200
    finally:
        cur.close(); conn.close()
@app.post("/api/bracelets/<uuid>/engrave")

def engrave(uuid):
    # 0) existe / déjà verrouillé ?
    conn = db_connect(); cur = conn.cursor(dictionary=True)
    try:
        cur.execute("SELECT uuid, produit, locked_at FROM bracelets WHERE uuid=%s", (uuid,))
        br = cur.fetchone()
        if not br:
            # crée le bracelet si besoin
            cur2 = conn.cursor()
            cur2.execute(
                "INSERT IGNORE INTO bracelets (uuid, produit, date_creation) VALUES (%s, %s, NOW())",
                (uuid, "Bracelet")
            )
            conn.commit()
            cur2.close()
        elif br["locked_at"]:
            return jsonify({"ok": False, "error": "already_locked"}), 409
    finally:
        cur.close(); conn.close()

    # 1) Parcourir les N blocs envoyés
    souvenirs = []
    # Si tu envoies 'count', sinon détecte dynamiquement
    count = 0
    try:
        count = int(request.form.get("count") or "0")
    except:
        count = 0

    # fallback: détecter dynamiquement
    if count <= 0:
        for i in range(1, 11):
            if any(k.startswith(f"titre{i}") or k.startswith(f"description{i}") or k.startswith(f"crop{i}") for k in request.form.keys()) \
               or f"fichier{i}" in request.files:
                count = max(count, i)

    # 2) Pour chaque index, uploader et insérer
    try:
        conn = db_connect()
        cur  = conn.cursor()

        insert_sql = (
            "INSERT INTO souvenirs (bracelet_uuid, titre, description, file_id, file_name, mime_type) "
            "VALUES (%s, %s, %s, %s, %s, %s)"
        )

        for i in range(1, count+1):
            titre = (request.form.get(f"titre{i}") or "").strip()
            desc  = (request.form.get(f"description{i}") or "").strip()
            crop_raw = request.form.get(f"crop{i}")
            crop = None
            try:
                if crop_raw:
                    crop = json.loads(crop_raw)
            except:
                crop = None

            up = request.files.get(f"fichier{i}")
            file_id = file_name = mime_type = None

            if up and up.filename:
                raw_bytes = up.read()
                mime_type = up.mimetype or "application/octet-stream"
                base_name = os.path.basename(up.filename)

                # traitement image/vidéo si crop/meta
                try:
                    if crop and isinstance(crop, dict):
                        if mime_type.startswith("image/"):
                            raw_bytes, mime_type, suffix = process_image_with_crop(raw_bytes, mime_type, crop)
                            base_name = re.sub(r"\.[^.]+$", "", base_name) + suffix
                        elif mime_type.startswith("video/"):
                            raw_bytes, mime_type, suffix = process_video_with_ffmpeg(raw_bytes, crop)
                            base_name = re.sub(r"\.[^.]+$", "", base_name) + suffix
                except Exception as e:
                    print(f"[PROC] media process failed, keep original: {e}", flush=True)

                # upload B2
                file_name_on_b2 = f"{uuid}/{base_name}"
                res = upload_file_to_b2(raw_bytes, file_name_on_b2, content_type=mime_type)
                if res:
                    file_id   = res["file_id"]
                    file_name = res["file_name"]
                    print(f"✅ Upload B2 OK: {file_name}", flush=True)
                else:
                    print(f"⚠️ Upload B2 FAILED: {file_name_on_b2}", flush=True)

            cur.execute(insert_sql, (uuid, titre, desc, file_id, file_name, mime_type))

        # 3) Lock
        cur.execute("UPDATE bracelets SET locked_at=NOW() WHERE uuid=%s AND locked_at IS NULL", (uuid,))
        conn.commit()
    except Exception as e:
        try:
            conn.rollback()
        except: pass
        print(f"❌ engrave error: {e}", flush=True)
        return jsonify({"ok": False, "error": str(e)}), 500
    finally:
        try:
            cur.close(); conn.close()
        except: pass

    return jsonify({"ok": True, "redirect": f"/b/{uuid}"}), 200
   
        
@app.route("/files/<int:souvenir_id>/temp-url", methods=["GET"])
def get_temp_url(souvenir_id):
    # 🔒 Rate-limit par IP et par id de fichier
    ip = client_ip()
    rl = ratelimit_or_429([
        (f"ip:{ip}", RATE_MAX_PER_IP, RATE_WINDOW_SEC, RATE_BAN_SEC),
        (f"file:{souvenir_id}:{ip}", RATE_MAX_PER_UUID, RATE_WINDOW_SEC, RATE_BAN_SEC),
    ])
    if rl: return rl

    ttl = int(request.args.get("ttl", "900"))  # 15 min par défaut
    conn = db_connect()
    cursor = conn.cursor(dictionary=True)
    try:
        cursor.execute("SELECT file_name FROM souvenirs WHERE id = %s", (souvenir_id,))
        row = cursor.fetchone()
        if not row or not row.get("file_name"):
            return jsonify({"error": "Fichier introuvable"}), 404

        url = get_signed_download_url(row["file_name"], ttl_seconds=ttl)
        if not url:
            return jsonify({"error": "Impossible de générer l'URL"}), 500

        return jsonify({"url": url, "expires_in": ttl}), 200
    finally:
        cursor.close()
        conn.close()

# ========================
# Page publique /b/<uuid>
# ========================
@app.route("/b/<uuid>", methods=["GET"])
def view_bracelet_public_uuid(uuid):
    ip = client_ip()
    rl = ratelimit_or_429([
        (f"ip:{ip}", RATE_MAX_PER_IP, RATE_WINDOW_SEC, RATE_BAN_SEC),
        (f"uuid:{uuid}:{ip}", RATE_MAX_PER_UUID, RATE_WINDOW_SEC, RATE_BAN_SEC),
    ])
    if rl: return rl

    ttl = int(os.getenv("B2_SIGNED_TTL", "1800"))

    conn = db_connect(); cur = conn.cursor(dictionary=True)
    try:
        cur.execute(
            "SELECT uuid, produit, date_creation, locked_at FROM bracelets WHERE uuid=%s",
            (uuid,)
        )
        br = cur.fetchone()
        if not br:
            return render_template("404.html"), 404

        cur.execute(
            "SELECT id, titre, description, file_name, mime_type "
            "FROM souvenirs WHERE bracelet_uuid=%s ORDER BY id ASC",
            (uuid,)
        )
        items = cur.fetchall()
    finally:
        cur.close(); conn.close()

    cards = []
    for it in items:
        if not it.get("file_name"):
            continue
        file_url = get_signed_download_url(it["file_name"], ttl_seconds=ttl)
        mt = it.get("mime_type") or mimetypes.guess_type(it.get("file_name") or "")[0]
        kind = "image" if (mt and mt.startswith("image/")) else ("video" if (mt and mt.startswith("video/")) else "file")
        cards.append({
            "id": it["id"],
            "titre": it.get("titre") or "",
            "description": it.get("description") or "",
            "file_url": file_url,
            "kind": kind,
            "mime": mt or "application/octet-stream"
        })

    locked = bool(br.get("locked_at"))

    # ⬇️ Si locked -> rendu TikTok only | Sinon -> page de configuration (formulaire)
    if locked:
        return render_template(
            "tiktok.html",   # <-- nouveau template ci-dessous
            produit=br["produit"] or "Souvenirs",
            uuid=uuid,
            cards=cards
        )
    else:
        return render_template(
            "setup.html",    # <-- ta page formulaire (celle avec “Graver”)
            produit=br["produit"] or "Souvenirs",
            uuid=uuid,
            cards=cards,
            claimed=False
        )


# ========================
# Helpers API
# ========================
@app.route("/api/bracelets/<uuid>/link", methods=["GET"])
def get_link_for_uuid(uuid):
    # 🔒 léger rate-limit pour éviter l'abus sur cette petite API
    ip = client_ip()
    rl = ratelimit_or_429([
        (f"ip:{ip}", RATE_MAX_PER_IP, RATE_WINDOW_SEC, RATE_BAN_SEC),
        (f"api-link:{uuid}:{ip}", RATE_MAX_PER_UUID, RATE_WINDOW_SEC, RATE_BAN_SEC),
    ])
    if rl: return rl

    return jsonify({"uuid": uuid, "url": build_public_url_for_uuid(uuid)}), 200

@app.route("/", methods=["GET"])
def home():
    return "ok", 200

@app.route("/robots.txt")
def robots():
    return "User-agent: *\nDisallow: /\n", 200, {"Content-Type": "text/plain"}
