
import hashlib
import hmac
import os
import base64
from typing import Optional, Tuple, Generator

# Default chunk size for file hashing
DEFAULT_CHUNK_SIZE = 8192  # bytes


def _get_hash_obj(algorithm: str):
    """
    Devuelve el constructor del hash para el algoritmo solicitado.
    Raise ValueError si el algoritmo no está soportado.
    """
    algo = algorithm.lower()
    if algo in ("sha256", "sha-256"):
        return hashlib.sha256()
    if algo in ("sha1", "sha-1"):
        return hashlib.sha1()
    if algo in ("sha512", "sha-512"):
        return hashlib.sha512()
    if algo in ("blake2b", "blake2"):
        # blake2b variable digest_size — usaremos la por defecto (64 bytes).
        return hashlib.blake2b()
    raise ValueError(f"Algoritmo no soportado: {algorithm}")


def hash_text(text: str, algorithm: str = "sha256", encoding: str = "utf-8") -> str:
    """
    Calcula el hash de un texto y devuelve el resultado en hex.
    """
    h = _get_hash_obj(algorithm)
    h.update(text.encode(encoding))
    return h.hexdigest()


def hash_bytes(data: bytes, algorithm: str = "sha256") -> str:
    """
    Hash directo de bytes.
    """
    h = _get_hash_obj(algorithm)
    h.update(data)
    return h.hexdigest()


def hash_file_chunked(file_obj, algorithm: str = "sha256", chunk_size: int = DEFAULT_CHUNK_SIZE) -> str:
    """
    Calcula el hash de un archivo leyendo por chunks.
    - file_obj debe ser un objeto con .read(), posicionado al inicio.
    - Retorna hex digest.
    Esto permite hashing de ficheros grandes sin cargar todo en memoria.
    """
    h = _get_hash_obj(algorithm)
    while True:
        chunk = file_obj.read(chunk_size)
        if not chunk:
            break
        # Asegúrate de trabajar con bytes
        if isinstance(chunk, str):
            chunk = chunk.encode("utf-8")
        h.update(chunk)
    # volver al inicio por si se necesita reutilizar el archivo en la app
    try:
        file_obj.seek(0)
    except Exception:
        pass
    return h.hexdigest()


def generate_salt(length: int = 16) -> str:
    """
    Genera una salt segura en base64 (recomendado 16+ bytes).
    """
    return base64.b64encode(os.urandom(length)).decode("utf-8")


def apply_salt(text: str, salt_b64: str) -> str:
    """
    Combina texto y salt (salt en base64) para hashing.
    Retorna la cadena combinada por convención (salt + texto) — esto es un ejemplo didáctico.
    Nota: la salt puede almacenarse junto al hash.
    """
    # Convierte salt a bytes
    salt = base64.b64decode(salt_b64.encode("utf-8"))
    return salt + text.encode("utf-8")


def apply_pepper(text: str, pepper: Optional[str]) -> bytes:
    """
    Aplica pepper (secreto) al texto antes de hashear.
    Se devuelve bytes listos para pasar a hashlib.
    """
    if pepper is None:
        return text.encode("utf-8")
    return (text + pepper).encode("utf-8")


def hmac_text(text: str, key: str, algorithm: str = "sha256") -> str:
    """
    Calcula HMAC sobre texto (retorna hex).
    key: string (se recomienda almacenarla en st.secrets)
    """
    algo = algorithm.lower()
    if algo in ("sha256", "sha-256"):
        digestmod = hashlib.sha256
    elif algo in ("sha1", "sha-1"):
        digestmod = hashlib.sha1
    elif algo in ("sha512", "sha-512"):
        digestmod = hashlib.sha512
    else:
        # Para BLAKE2 no hay hmac built-in en stdlib; se hace HMAC usando hashlib.blake2b via functools? 
        # Aquí simplificamos: usar SHA family para HMAC.
        digestmod = hashlib.sha256

    return hmac.new(key.encode("utf-8"), text.encode("utf-8"), digestmod).hexdigest()


def compare_hashes(hash_a: str, hash_b: str) -> bool:
    """
    Comparación segura (const-time) de hashes representados en hex.
    """
    # Convertir a bytes y usar hmac.compare_digest para evitar timing attacks
    try:
        a = bytes.fromhex(hash_a)
        b = bytes.fromhex(hash_b)
    except Exception:
        # Si no son hex válidos, comparar en UTF-8
        return hmac.compare_digest(hash_a, hash_b)
    return hmac.compare_digest(a, b)
