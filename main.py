# Require: Una función resumen h y una función recodificante r
# Require: t longitud de la secuencia
# Require: n número de entradas
# Ensure: Una tabla rainbow para la función h.


import hashlib
import random
import math
import time

# ---------------- PARÁMETROS ----------------

    # ALGORITMO HASH: SHA-256
    # Nº CARACTERES HASH: 40 bits
    # Nº CARACTERES CONTRASEÑA: 5 caracteres
    # FUNCION REDUCCION: 

ALPHABET = "abcdefghijklmnopqrstuvwxyz"
PSW_LEN = 5  # 5 caracteres
HASH_LEN = 40  # 40 bits (5 bytes)
TRUNC_LEN = 8
ALPHABET_SIZE = len(ALPHABET)
SPACE_SIZE = ALPHABET_SIZE ** PSW_LEN  # 26^5 = 11,881,376

# ---------------- FUNCIONES INICIALES ----------------

def hash_function(password):
    # Calcula SHA-256 y trunca a 40 bits (5 bytes)
    hasher = hashlib.sha256()
    hasher.update(password.encode('utf-8'))
    full_hash = hasher.digest()
    truncated_hash = full_hash[:5]  # 5 bytes = 40 bits
    return truncated_hash


def reduction_function(hash_bytes, step=0):
    # Función de reducción determinista: mapea 40 bits a una contraseña de 5 caracteres.
    # step: permite variar la función por paso en la cadena (para evitar colisiones internas).
    
    # Convertir hash a entero de 40 bits
    hash_int = int.from_bytes(hash_bytes, byteorder='big')
    # Combinar con el paso para hacerla dependiente de la posición
    hash_int = (hash_int + step) % SPACE_SIZE
    # Convertir el entero a una contraseña de 5 caracteres
    password = []
    temp = hash_int
    for _ in range(PSW_LEN):
        temp, index = divmod(temp, ALPHABET_SIZE)
        password.append(ALPHABET[index])
    return ''.join(reversed(password))


# ---------------- CONSTRUCCION ----------------

def build_rainbow_table(n, t):
    # Construye una tabla arco iris con n cadenas de longitud t.
    # La tabla es un diccionario indexado por el hash final (como entero de 40 bits).
    
    rainbow_table = {}
    for _ in range(n):
        # Generar password inicial aleatorio
        start_pwd = ''.join(random.choice(ALPHABET) for _ in range(PSW_LEN))
        current = start_pwd
        # Recorrer la cadena de reducciones
        for j in range(t - 1):
            current_hash = hash_function(current)
            current = reduction_function(current_hash, j)
        # Calcular hash final y almacenar
        final_hash = hash_function(current)
        final_hash_int = int.from_bytes(final_hash, byteorder='big')
        if final_hash_int not in rainbow_table:
            rainbow_table[final_hash_int] = []
        rainbow_table[final_hash_int].append(start_pwd)
    return rainbow_table

# ---------------- BUSQUEDA ----------------

def find_collision(target_hash, rainbow_table, t):
    # Busca una colisión para target_hash en la tabla arco iris.
    # target_hash: hash de 40 bits (5 bytes) del password objetivo.
    # rainbow_table: tabla construida con build_rainbow_table.
    # t: longitud de las cadenas en la tabla.
    
    target_int = int.from_bytes(target_hash, byteorder='big')
    # Probar desde cada paso posible en la cadena
    for i in range(t):
        current_hash = target_hash
        # Avanzar hasta el final de la cadena (paso i a t-1)
        for j in range(i, t - 1):
            reduced = reduction_function(current_hash, j)
            current_hash = hash_function(reduced)
        # Verificar si el hash final está en la tabla
        current_int = int.from_bytes(current_hash, byteorder='big')
        if current_int in rainbow_table:
            # Para cada password inicial que llevó a este hash final, recomprobar
            for start_pwd in rainbow_table[current_int]:
                candidate = start_pwd
                # Recomprobar toda la cadena
                for step in range(t - 1):
                    candidate_hash = hash_function(candidate)
                    if candidate_hash == target_hash:
                        return candidate
                    candidate = reduction_function(candidate_hash, step)
    return None


# ----------- EJEMPLO DE USO ----------------
if __name__ == "__main__":
    # Parámetros
    n = 100000  # Número de cadenas en la tabla
    t = 10000   # Longitud de cada cadena

    # Construir la tabla arcoíris
    print("Construyendo tabla arcoíris...")
    table = build_rainbow_table(n, t)
    print(f"Tabla construida. Entradas únicas: {len(table)}")

    # Password objetivo
    target_password = "hello"
    target_hash = hash_function(target_password)
    print(f"Password objetivo: {target_password}")
    print(f"Hash objetivo (40 bits): {target_hash.hex()}")

    # Buscar colisión
    print("Buscando colisión...")
    collision = find_collision(target_hash, table, t)
    if collision:
        print(f"Colisión encontrada: {collision}")
        print(f"Hash de la colisión: {hash_function(collision).hex()}")
        print(f"¿Los hashes coinciden? {hash_function(collision) == target_hash}")
    else:
        print("No se encontró colisión. Puede aumentar n o t.")

# tabla = tabla vacia
# while La tabla no contenga n entradas do
    # Escoger Pi un password al azar.
    # P = Pi
    # for j = 1 to t − 1 do
        # P = r(h(P))
    # end for
    # Almacenar ⟨P1, h(P)⟩ en la tabla
# end while


# SHA-256
# TRUNCAR

# funcion de reconstruccion =
# dominio = 5 caracteres letras minusculas

# 40 bits en 5 minusculas
# cada 8 bits saco una letra minuscula
#  
# 40 bits de hash
# el password tiene 5 caracteres