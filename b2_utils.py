# b2_utils.py
from __future__ import annotations

from typing import Optional, Tuple, Dict
import os
import time
import threading

from dotenv import load_dotenv
from b2sdk.v2 import InMemoryAccountInfo, B2Api

load_dotenv()

# ─────────────────────────────────────────────────────────────
#   Configuration d'environnement requise
#     B2_KEY_ID, B2_APP_KEY, B2_BUCKET_NAME
# ─────────────────────────────────────────────────────────────
KEY_ID = os.getenv("B2_KEY_ID")
APP_KEY = os.getenv("B2_APP_KEY")
BUCKET_NAME = os.getenv("B2_BUCKET_NAME")

if not (KEY_ID and APP_KEY and BUCKET_NAME):
    raise RuntimeError("Veuillez définir B2_KEY_ID, B2_APP_KEY et B2_BUCKET_NAME dans votre .env")

# ─────────────────────────────────────────────────────────────
#   Initialisation du client B2 (b2sdk v2)
# ─────────────────────────────────────────────────────────────
_info = InMemoryAccountInfo()
b2_api = B2Api(_info)
b2_api.authorize_account("production", KEY_ID, APP_KEY)

bucket = b2_api.get_bucket_by_name(BUCKET_NAME)
if bucket is None:
    raise RuntimeError(f"Bucket '{BUCKET_NAME}' introuvable")

# ─────────────────────────────────────────────────────────────
#   Cache de tokens d'auth de téléchargement par PRÉFIXE "UUID/"
#   key   -> "prefix:BR-XXXXXX/"
#   value -> (token, expires_at_epoch)
# ─────────────────────────────────────────────────────────────
_prefix_token_cache: Dict[str, Tuple[str, float]] = {}
_cache_lock = threading.Lock()
_SAFETY_MARGIN_SECONDS = 30  # marge avant expiration effective du token


def _now() -> float:
    return time.time()


def _get_prefix_from_file_name(file_name: str) -> str:
    """
    Extrait le préfixe dossier ("UUID/") à partir d'un chemin "UUID/filename.ext".
    Retourne "" si le fichier n'est pas dans un sous-dossier.
    """
    if not file_name:
        return ""
    parts = file_name.split("/", 1)
    if len(parts) == 2 and parts[0]:
        return parts[0].rstrip("/") + "/"
    return ""


def _fetch_download_token_for_prefix(prefix: str, ttl_seconds: int) -> Optional[str]:
    """
    Demande à B2 un token valable pour tout fichier dont le nom commence par `prefix`.
    Compatible avec différentes versions (valid_duration_seconds vs valid_duration_in_seconds).
    """
    if not prefix:
        return None
    try:
        return bucket.get_download_authorization(
            file_name_prefix=prefix,
            valid_duration_seconds=ttl_seconds
        )
    except TypeError:
        # Certaines versions utilisent valid_duration_in_seconds
        return bucket.get_download_authorization(
            file_name_prefix=prefix,
            valid_duration_in_seconds=ttl_seconds
        )


def _get_cached_token(prefix: str, ttl_seconds: int) -> Optional[str]:
    """
    Renvoie un token de cache s'il reste suffisamment de validité,
    sinon en génère un nouveau et met à jour le cache.
    """
    if not prefix:
        return None

    key = f"prefix:{prefix}"
    now = _now()

    with _cache_lock:
        cached = _prefix_token_cache.get(key)
        if cached:
            token, exp = cached
            if exp - now > _SAFETY_MARGIN_SECONDS:
                return token

        # (Re)génère un token pour ce préfixe
        token = _fetch_download_token_for_prefix(prefix, ttl_seconds)
        if not token:
            return None
        _prefix_token_cache[key] = (token, now + ttl_seconds)
        return token


def clear_download_token_cache(prefix: Optional[str] = None) -> None:
    """
    Vide le cache des tokens.
    - prefix=None  -> tout le cache
    - prefix="BR-XXXX/" -> uniquement ce préfixe
    """
    with _cache_lock:
        if prefix is None:
            _prefix_token_cache.clear()
        else:
            _prefix_token_cache.pop(f"prefix:{prefix}", None)


def upload_file_to_b2(
    file_content: bytes,
    file_name: str,
    content_type: Optional[str] = None
) -> Optional[dict]:
    """
    Upload binaire vers B2 (bucket privé).
    Retour: {"file_id": "...", "file_name": "..."} ou None si échec.
    """
    try:
        uploaded = bucket.upload_bytes(
            file_content,
            file_name,
            content_type=content_type,
            file_info={"source": "webhook"}
        )
        return {"file_id": uploaded.id_, "file_name": uploaded.file_name}
    except Exception as e:
        print(f"[B2] Erreur d'upload: {e}")
        return None


def get_signed_download_url(file_name: str, ttl_seconds: int = 900) -> Optional[str]:
    """
    Génère une URL signée temporaire pour `file_name` depuis le bucket privé.
    Optimisation: si `file_name` est sous "UUID/...", on demande un token *par préfixe*
    (réutilisable pour tous les fichiers du même bracelet) afin de réduire les appels de classe C.

    :param file_name: chemin B2 (ex: "BR-ABCDEF1234/photo-1.jpg")
    :param ttl_seconds: durée de validité du token (défaut 15 min)
    """
    if not file_name:
        return None

    # 1) token par PRÉFIXE "UUID/" si possible
    prefix = _get_prefix_from_file_name(file_name)
    token = _get_cached_token(prefix, ttl_seconds) if prefix else None

    # 2) fallback: token pour ce seul fichier (si pas de dossier/prefix)
    if not token:
        try:
            token = bucket.get_download_authorization(
                file_name_prefix=file_name,
                valid_duration_seconds=ttl_seconds
            )
        except TypeError:
            try:
                token = bucket.get_download_authorization(
                    file_name_prefix=file_name,
                    valid_duration_in_seconds=ttl_seconds
                )
            except Exception as e2:
                print(f"[B2] Erreur lien signé (fallback): {e2}")
                return None
        except Exception as e:
            print(f"[B2] Erreur lien signé: {e}")
            return None

    try:
        base = b2_api.account_info.get_download_url()  # ex: https://f000.backblazeb2.com
        return f"{base}/file/{bucket.name}/{file_name}?Authorization={token}"
    except Exception as e:
        print(f"[B2] Erreur construction URL signée: {e}")
        return None
