import streamlit as st
import io
import csv
from datetime import datetime
from typing import Optional

import hash_utils as hu

# ---------- Configuración de la app ----------
st.set_page_config(page_title="Hash Demo", page_icon="🔐", layout="centered")

st.title("🔐 Demo educativa de funciones Hash")
st.caption("SHA-256 por defecto • Salt, Pepper (st.secrets) • HMAC • Hash incremental de ficheros")

# Try to fetch secrets (PEPPER and HMAC_KEY). If absent, show a gentle warning.
PEPPER = st.secrets.get("PEPPER") if hasattr(st, "secrets") else None
HMAC_KEY = st.secrets.get("HMAC_KEY") if hasattr(st, "secrets") else None

if not PEPPER:
    st.info("PEPPER no configurado en st.secrets — la demostración de pepper será omisa. (Configurar en Streamlit Cloud > Secrets)")
if not HMAC_KEY:
    st.info("HMAC_KEY no configurado en st.secrets — la demo de HMAC requerirá la clave.")


# ---------- Sidebar: opciones globales ----------
st.sidebar.header("Opciones")
algorithm = st.sidebar.selectbox("Algoritmo", options=["sha256", "sha1", "sha512", "blake2b"], index=0)
max_file_mb = st.sidebar.number_input("Límite de archivo (MB)", min_value=1, max_value=100, value=10)
chunk_size = st.sidebar.number_input("Chunk size (bytes)", min_value=1024, max_value=65536, value=8192)
st.sidebar.markdown("**Nota:** BlAke2b requiere stdlib `hashlib` y está limitado a lo que el entorno soporte.")

# ---------- Sección 1: Hash de texto ----------
st.header("1. Hash de texto")
with st.expander("Entrada de texto y opciones"):
    txt = st.text_area("Texto a hashear", value="Ejemplo: hola mundo", height=120)
    use_salt = st.checkbox("Aplicar salt (generar nueva salt)", value=False)
    salt_value = None
    if use_salt:
        salt_value = hu.generate_salt(16)
        st.text_input("Salt (base64) (generada)", value=salt_value, key="salt_display")
        st.markdown("La salt se muestra aquí para fines pedagógicos; normalmente se almacena junto al hash.")
    use_pepper = st.checkbox("Aplicar pepper (desde st.secrets)", value=False)
    if use_pepper and not PEPPER:
        st.warning("PEPPER no encontrado en st.secrets — activa st.secrets en Streamlit Cloud para usar pepper.")

if st.button("Calcular hash del texto"):
    to_hash_bytes = txt.encode("utf-8")
    note = ""
    # apply salt if requested
    if use_salt and salt_value:
        to_hash_bytes = hu.apply_salt(txt, salt_value)
        note += f"Salt aplicada (base64, {len(salt_value)} chars). "
    # apply pepper if requested and available
    if use_pepper and PEPPER:
        to_hash_bytes = hu.apply_pepper(txt, PEPPER)
        note += "Pepper aplicada. "
    # Compute hash: use direct bytes path for unified behavior
    h = hu.hash_bytes(to_hash_bytes, algorithm=algorithm)
    st.code(f"Hash ({algorithm}): {h}")
    if note:
        st.caption(note)


# ---------- Sección 2: Hash de archivos ----------
st.header("2. Hash de archivo")
st.markdown("Sube un archivo (máx. definido en la barra lateral). La app hace hashing por chunks y muestra una barra de progreso.")

uploaded = st.file_uploader("Subir archivo", type=None)
if uploaded is not None:
    # Limit size check (Streamlit file objects tienen .size en algunos casos)
    try:
        size_bytes = uploaded.size
    except Exception:
        # fallback: leer en memoria (no ideal)
        uploaded.seek(0, io.SEEK_END)
        size_bytes = uploaded.tell()
        uploaded.seek(0)

    size_mb = size_bytes / (1024 * 1024)
    if size_mb > max_file_mb:
        st.error(f"Archivo demasiado grande: {size_mb:.2f} MB > límite {max_file_mb} MB")
    else:
        st.write(f"Archivo: {uploaded.name} • {size_mb:.2f} MB")
        progress = st.progress(0)
        # Use chunked hashing
        def gen_chunks(f, chunk_size):
            while True:
                chunk = f.read(chunk_size)
                if not chunk:
                    break
                yield chunk

        # Ensure we're at the start
        uploaded.seek(0)
        h_obj = None
        # We'll reuse hash_utils implementation for consistency: pass file-like object
        result_hash = hu.hash_file_chunked(uploaded, algorithm=algorithm, chunk_size=int(chunk_size))
        progress.progress(100)
        st.code(f"Hash ({algorithm}): {result_hash}")

        # Offer download of result as CSV
        csv_output = io.StringIO()
        writer = csv.writer(csv_output)
        writer.writerow(["filename", "algorithm", "hash", "size_bytes", "timestamp"])
        writer.writerow([uploaded.name, algorithm, result_hash, size_bytes, datetime.utcnow().isoformat()+"Z"])
        csv_bytes = csv_output.getvalue().encode("utf-8")
        st.download_button("Descargar resultado (CSV)", data=csv_bytes, file_name=f"{uploaded.name}.hash.csv", mime="text/csv")


# ---------- Sección 3: Comparar hashes ----------
st.header("3. Comparador de hashes")
with st.expander("Comparar dos hashes"):
    h1 = st.text_input("Hash A (hex)", key="h1")
    h2 = st.text_input("Hash B (hex)", key="h2")
    if st.button("Comparar"):
        if not h1 or not h2:
            st.warning("Introduce ambos hashes para comparar.")
        else:
            match = hu.compare_hashes(h1.strip(), h2.strip())
            if match:
                st.success("✅ Los hashes coinciden (compare_digest).")
            else:
                st.error("❌ Los hashes NO coinciden.")


# ---------- Sección 4: HMAC ----------
st.header("4. HMAC (requiere HMAC_KEY en st.secrets)")
with st.expander("Calcular HMAC de un texto"):
    hmac_text_input = st.text_area("Texto para HMAC", "Mensaje para HMAC")
    hmac_algo = st.selectbox("Algoritmo HMAC (digest)", options=["sha256", "sha1", "sha512"], index=0)
    if st.button("Calcular HMAC"):
        if not HMAC_KEY:
            st.error("HMAC_KEY no configurada en st.secrets — configura la clave y redeploy.")
        else:
            hmac_result = hu.hmac_text(hmac_text_input, HMAC_KEY, algorithm=hmac_algo)
            st.code(f"HMAC ({hmac_algo}): {hmac_result}")


# ---------- Footer: notas didácticas ----------
st.markdown("---")
st.subheader("Notas didácticas y limitaciones")
st.markdown(
    """
- **Hash ≠ cifrado.** Un hash no es reversible.  
- **Salt** evita tablas precalculadas; la salt suele almacenarse junto al hash.  
- **Pepper** es un secreto adicional; debe guardarse fuera de la base de datos (ej. en `st.secrets` o un vault).  
- **HMAC** provee integridad y autenticidad cuando se usa una clave secreta.  
- **SHA-1**: vulnerable a colisiones — usar solo para compatibilidad.  
- Para protección de contraseñas preferir PBKDF2/Argon2/scrypt con iteraciones; esto excede la demo pero se menciona como buena práctica.
"""
)

st.markdown("**¿Quieres exportar todo el historial?** Implementar un logger y restricciones de privacidad antes de almacenar hashes en un backend.")
