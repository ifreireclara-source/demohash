# Tests (ejemplos manuales) para `hash_utils.py`

1. Hash de texto
- Entrada: "hello"
- Comando esperado (SHA-256): `hu.hash_text("hello", "sha256")`
- Resultado (ejemplo conocido): `2cf24dba5...` (compara con tu ejecución en la app)

2. Salt + hash
- Genera salt: `s = hu.generate_salt(16)`
- Aplica: `b = hu.apply_salt("password", s)`
- Hash: `hu.hash_bytes(b, "sha256")`

3. HMAC
- Key: "key"
- Texto: "The quick brown fox"
- Ejecuta: `hu.hmac_text("The quick brown fox", "key", "sha256")`
- Compara con la salida de la app en la sección HMAC.

Nota: estos "tests" son para verificación manual en la app web.
