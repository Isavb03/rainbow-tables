# Require: Una función resumen h y una función recodificante r
# Require: t longitud de la secuencia
# Require: n número de entradas

import random
import csv
import os
import time
from datetime import datetime

# ---------------- PARÁMETROS ----------------

from config import (
    hash_function,
    reduction_function,
    ALPHABET, PSW_LEN, HASH_LEN, TRUNC_LEN,
    ALPHABET_SIZE, SPACE_SIZE, t, n
)

# -------------- GENERAR PASSWORD RANDOM -------------------

def generate_random_password() -> str:
    """
    Genera un password aleatorio del espacio de claves.
    
    Returns:
        Password aleatorio de PSW_LEN caracteres
    """
    return ''.join(random.choices(ALPHABET, k=PSW_LEN))


# ----------- CADENA INICIAL ------------------------

def build_chain(initial_password: str, chain_length: int) -> tuple[str, bytes]:
    """
    Construye una cadena desde un password inicial.
    
    Args:
        initial_password: Password inicial Pi
        chain_length: Longitud de la cadena (t)
    
    Returns:
        Tupla (password_inicial, hash_final)
    """
    P = initial_password
    
    # Iterar t-1 veces aplicando h y r
    for j in range(chain_length - 1):
        h_P = hash_function(P)
        P = reduction_function(h_P, iteration=j)
    
    # Calcular el hash final
    final_hash = hash_function(P)
    
    return (initial_password, final_hash)


# ----------------- CREAR TABLA ------------------------

def build_rainbow_table(chain_length: int, num_entries: int, verbose: bool = True) -> dict[bytes, str]:
    """
    Construye una tabla arcoíris completa.
    
    Args:
        chain_length: Longitud de cada cadena (t)
        num_entries: Número de entradas en la tabla (n)
        verbose: Si True, muestra el progreso
    
    Returns:
        Diccionario con estructura {hash_final: password_inicial}
    """
    start_time = time.time()  # Inicio del temporizador

    tabla = {}
    attempts = 0
    max_attempts = num_entries * 10  # Límite de intentos para evitar bucles infinitos
    
    if verbose:
        print(f"Construyendo tabla arcoíris...")
        print(f"  - Longitud de cadena (t): {chain_length}")
        print(f"  - Número de entradas (n): {num_entries}")
        print(f"  - Espacio de claves: {SPACE_SIZE:,}")
        print(f"  - Cobertura aproximada: {(num_entries * chain_length / SPACE_SIZE * 100):.2f}%\n")
    
    while len(tabla) < num_entries and attempts < max_attempts:
        attempts += 1
        
        # Generar password inicial aleatorio
        Pi = generate_random_password()
        
        # Construir la cadena
        initial_psw, final_hash = build_chain(Pi, chain_length)
        
        # Almacenar en la tabla (solo si no existe ya ese hash final)
        if final_hash not in tabla:
            tabla[final_hash] = initial_psw
            
            if verbose and len(tabla) % 1000 == 0:
                print(f"  Progreso: {len(tabla):,}/{num_entries:,} entradas " + f"({len(tabla)/num_entries*100:.1f}%) - Intentos: {attempts:,}")
    
    # Calcular tiempo total
    total_time = time.time() - start_time  # en segundos

    if verbose:
        print(f"\n✓ Tabla construida con éxito!")
        print(f"  - Entradas únicas: {len(tabla):,}")
        print(f"  - Intentos totales: {attempts:,}")
        print(f"  - Eficiencia: {len(tabla)/attempts*100:.2f}%")
    
    # Devolvemos también el tiempo total si se desea usar más adelante
    tabla["_build_time"] = total_time  

    return tabla


def save_rainbow_table(tabla: dict[bytes, str], chain_length: int, num_entries: int, folder: str = "tables") -> str:
    """
    Guarda la tabla arcoíris en un archivo CSV.
    
    Args:
        tabla: Diccionario con la tabla arcoíris
        chain_length: Longitud de cadena usada
        num_entries: Número de entradas objetivo
        folder: Carpeta donde guardar el archivo
    
    Returns:
        Ruta del archivo guardado
    """
    # Crear carpeta si no existe
    os.makedirs(folder, exist_ok=True)
    
    # Generar nombre de archivo con timestamp
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"rainbow_table_t{chain_length}_n{num_entries}_{timestamp}.csv"
    filepath = os.path.join(folder, filename)
    
    total_time = tabla.pop("_build_time", None)  # Recuperar si existe

    # Guardar en CSV
    with open(filepath, 'w', newline='', encoding='utf-8') as csvfile:
        writer = csv.writer(csvfile)
        
        # Escribir encabezado con metadatos
        writer.writerow(['# Rainbow Table'])
        writer.writerow(['# Chain Length (t)', chain_length])
        writer.writerow(['# Target Entries (n)', num_entries])
        writer.writerow(['# Actual Entries', len(tabla)])
        writer.writerow(['# Alphabet', ALPHABET])
        writer.writerow(['# Password Length', PSW_LEN])
        writer.writerow(['# Hash Length (bits)', HASH_LEN])
        writer.writerow(['# Space Size', SPACE_SIZE])
        writer.writerow(['# Coverage (%)', f"{len(tabla) * chain_length / SPACE_SIZE * 100:.4f}"])
        writer.writerow(['# Timestamp', timestamp])
        writer.writerow([])  # Línea vacía

        if total_time is not None:
            writer.writerow(['# Build Time (s)', f"{total_time:.2f}"])  # ⏱️
        writer.writerow([])


        # Escribir encabezado de datos
        writer.writerow(['initial_password', 'final_hash_hex'])
        
        # Escribir datos
        for final_hash, initial_psw in tabla.items():
            writer.writerow([initial_psw, final_hash.hex()])
    
    print(f"\n✓ Tabla guardada en: {filepath}")
    print(f"  - Tiempo de construcción: {total_time:.2f} s" if total_time else "")
    print(f"  - Tamaño del archivo: {os.path.getsize(filepath) / 1024:.2f} KB")
    
    return filepath

# --------------------- MAIN -------------------------

if __name__ == "__main__":   
    # Construir la tabla
    rainbow_table = build_rainbow_table(chain_length=t, num_entries=n)
    
    # Guardar la tabla en CSV
    filepath = save_rainbow_table(rainbow_table, chain_length=t, num_entries=n)
    
    # Mostrar algunas entradas de ejemplo
    print("\n" + "="*60)
    print("Ejemplo de entradas en la tabla:")
    print("="*60)
    for i, (final_hash, initial_psw) in enumerate(list(rainbow_table.items())[:5]):
        print(f"{i+1}. Password inicial: '{initial_psw}' -> Hash final: {final_hash.hex()}")
    
    print(f"\n... ({len(rainbow_table) - 5:,} entradas más)")


# Ensure: Una tabla rainbow para la función h.
# tabla = tabla vacia
# while La tabla no contenga n entradas do
# Escoger Pi un password al azar.
# P = Pi
# for j = 1 to t − 1 do
# P = r(h(P))
# end for
# Almacenar ⟨P1, h(P)⟩ en la tabla
# end while