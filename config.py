# ---------------- PARÁMETROS ----------------
    # ALGORITMO HASH: SHA-256
    # Nº CARACTERES HASH: 40 bits
    # Nº CARACTERES CONTRASEÑA: 5 caracteres

ALPHABET = "abcdefghijklmnopqrstuvwxyz"
PSW_LEN = 5  # 5 caracteres
HASH_LEN = 40  # 40 bits (5 bytes)
TRUNC_LEN = 8
ALPHABET_SIZE = len(ALPHABET)
SPACE_SIZE = ALPHABET_SIZE ** PSW_LEN  # 26^5 = 11,881,376

# Parámetros de la tabla
t = 1000  # Longitud de cadena
n = 11813  # Número de entradas
