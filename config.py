import hashlib

# ---------------- PARÁMETROS ----------------
    # ALGORITMO HASH: SHA-256
    # Nº CARACTERES HASH: 40 bits
    # Nº CARACTERES CONTRASEÑA: 5 caracteres

ALPHABET = "abcdefghijklmnopqrstuvwxyz"
# ALPHABET = "abcdefghijklmnopqrstuvwxyz"
PSW_LEN = 5  # 5 caracteres
HASH_LEN = 40  # 40 bits (5 bytes)
TRUNC_LEN = 8
ALPHABET_SIZE = len(ALPHABET)
SPACE_SIZE = ALPHABET_SIZE ** PSW_LEN  # 26^5 = 11,881,376

# Parámetros de la tabla
t = 500  # Longitud de cadena
n = 22000  # Número de entradas

# ---------------- FUNCIONES ----------------

# CREAR HASH --------------------------

def hash_function(password: str) -> bytes:
    """  
    Args: password: String a hashear
    
    Returns: Hash truncado de 5 bytes (40 bits)
    """
    full_hash = hashlib.sha256(password.encode()).digest()
    # Truncar a 40 bits (5 bytes)
    return full_hash[:5]


# FUNCION DE REDUCCIÓN -------------------

def reduction_function(hash_bytes: bytes, iteration: int = 0) -> str:
    """
    Función de recodificación determinista que mapea un hash a un password.
    Divide el hash de 40 bits en 8 trozos de 5 bits cada uno.
    
    Args:
        hash_bytes: Hash de 5 bytes (40 bits)
        iteration: Número de iteración para variar la función de reducción
    
    Returns:
        Password de PSW_LEN caracteres del alfabeto
    """
    # Convertir bytes a entero
    hash_int = int.from_bytes(hash_bytes, byteorder='big')
    
    # Añadir la iteración para hacer la función dependiente de la posición
    hash_int = (hash_int + iteration) % (2**40)
    
    password = []
    
    # Dividir en 8 trozos de 5 bits y mapear a caracteres
    for i in range(TRUNC_LEN):
        # Extraer 5 bits
        chunk = (hash_int >> (i * 5)) & 0x1F  # 0x1F = 31 = 0b11111
        # Mapear al alfabeto (módulo para asegurar que está en rango)
        char_idx = chunk % ALPHABET_SIZE
        password.append(ALPHABET[char_idx])
    
    # Tomar solo PSW_LEN caracteres
    return ''.join(password[:PSW_LEN])