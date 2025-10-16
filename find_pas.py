import hashlib
import csv
import os
from typing import Dict, Tuple, Optional

# Parámetros (deben coincidir con los de construcción)
from config import (
    ALPHABET, PSW_LEN, HASH_LEN, TRUNC_LEN,
    ALPHABET_SIZE, SPACE_SIZE
)

def hash_function(password: str) -> bytes:
    """
    Función resumen que trunca SHA-256 a 40 bits (5 bytes).
    Debe ser idéntica a la usada en la construcción.
    """
    full_hash = hashlib.sha256(password.encode()).digest()
    return full_hash[:5]

def reduction_function(hash_bytes: bytes, iteration: int = 0) -> str:
    """
    Función de recodificación determinista.
    Debe ser idéntica a la usada en la construcción.
    """
    hash_int = int.from_bytes(hash_bytes, byteorder='big')
    hash_int = (hash_int + iteration) % (2**40)
    
    password = []
    for i in range(TRUNC_LEN):
        chunk = (hash_int >> (i * 5)) & 0x1F
        char_idx = chunk % ALPHABET_SIZE
        password.append(ALPHABET[char_idx])
    
    return ''.join(password[:PSW_LEN])

def load_rainbow_table(filepath: str) -> Tuple[Dict[bytes, str], int]:
    """
    Carga una tabla arcoíris desde un archivo CSV.
    
    Returns:
        Tupla (tabla, chain_length)
    """
    tabla = {}
    chain_length = 0
    
    with open(filepath, 'r', encoding='utf-8') as csvfile:
        reader = csv.reader(csvfile)
        
        # Leer metadatos
        for row in reader:
            if not row:
                break
            if row[0] == '# Chain Length (t)':
                chain_length = int(row[1])
        
        # Encontrar inicio de datos
        csvfile.seek(0)
        reader = csv.reader(csvfile)
        for row in reader:
            if row and row[0] == 'initial_password':
                break
        
        # Leer datos
        for row in reader:
            initial_psw, final_hash_hex = row
            final_hash = bytes.fromhex(final_hash_hex)
            tabla[final_hash] = initial_psw
    
    print(f"✓ Tabla cargada: {len(tabla):,} entradas, t={chain_length}")
    return tabla, chain_length

def search_collision(p0: bytes, rainbow_table: Dict[bytes, str], 
                    chain_length: int, verbose: bool = False) -> Optional[str]:
    """
    Busca una colisión para el hash p0 usando la tabla arcoíris.
    
    Este algoritmo está adaptado para Tablas Arcoíris (reducción variable)
    en lugar del Algoritmo 2 simple (reducción constante).
    
    Fase 1: Proyecta p0 desde diferentes posiciones hasta el final
    Fase 2: Reconstruye la cadena desde el inicio hasta encontrar p0
    
    Args:
        p0: Hash del password original (resumen a atacar)
        rainbow_table: Diccionario {hash_final: password_inicial}
        chain_length: Longitud de las cadenas (t)
        verbose: Mostrar información detallada
    
    Returns:
        Password que produce el hash p0, o None si no se encuentra
    """
    if verbose:
        print(f"\nBuscando colisión para hash: {p0.hex()}")
    
    found_entry = None
    
    # FASE 1: Proyección y búsqueda
    # Asumimos que p0 podría ser h(P_{i+1}) en cualquier posición i de la cadena
    # y proyectamos hasta el final para ver si coincide con algún hash final en la tabla
    for i in range(chain_length):
        if verbose and i % 100 == 0:
            print(f"  Iteración {i}/{chain_length}...")
        
        # Proyectar desde la posición i hasta el final
        p = p0
        for j in range(i, chain_length - 1):
            p = hash_function(reduction_function(p, iteration=j))
        
        # Verificar si este hash final está en la tabla
        if p in rainbow_table:
            found_entry = rainbow_table[p]
            if verbose:
                print(f"  ✓ Encontrado en iteración {i}")
                print(f"    Password inicial de la cadena: '{found_entry}'")
            
            # FASE 2: Reconstrucción de la cadena
            pwd = found_entry
            
            if verbose:
                print(f"\n  Reconstruyendo cadena desde '{pwd}'...")
            
            # CORRECCIÓN CRÍTICA: Solo hacer t-1 reducciones (índices 0 a t-2)
            # Una cadena de longitud t tiene t passwords pero solo t-1 reducciones
            for step in range(chain_length - 1):
                # Verificar si este password produce el hash buscado
                if hash_function(pwd) == p0:
                    if verbose:
                        print(f"  ✓ ¡Colisión encontrada en el paso {step}!")
                        print(f"    Password: '{pwd}'")
                        print(f"    Hash: {hash_function(pwd).hex()}")
                    return pwd
                
                # Avanzar en la cadena: P_{step+1} -> P_{step+2}
                if verbose and step % 100 == 0:
                    print(f"    Paso {step}: pwd='{pwd}'")
                
                pwd = reduction_function(hash_function(pwd), iteration=step)
            
            # Después del bucle (t-1 iteraciones): pwd contiene P_t
            # Verificar el último elemento de la cadena (P_t)
            if hash_function(pwd) == p0:
                if verbose:
                    print(f"  ✓ ¡Colisión encontrada al final de la cadena (P_t)!")
                    print(f"    Password: '{pwd}'")
                    print(f"    Hash: {hash_function(pwd).hex()}")
                return pwd
            
            # Si no se encuentra, es una falsa alarma - continuar buscando
            if verbose:
                print(f"  ✗ Falsa alarma en esta cadena, continuando búsqueda...")
    
    # No se encontró en ninguna cadena
    if verbose:
        print("  ✗ No encontrado en la tabla")
    
    return None

def test_search_random(rainbow_table: Dict[bytes, str], chain_length: int, 
                       num_tests: int = 10):
    """
    Prueba el algoritmo de búsqueda con passwords COMPLETAMENTE aleatorios.
    Esta prueba simula un ataque real donde no sabemos si el password está en la tabla.
    """
    import random
    
    print("\n" + "="*70)
    print(f"PRUEBA 1: BÚSQUEDA CON PASSWORDS ALEATORIOS (Ataque Real)")
    print("="*70)
    print("Nota: Se esperan tasas de éxito bajas (~84% cobertura teórica)\n")
    
    success_count = 0
    total_time = 0
    
    for test_num in range(1, num_tests + 1):
        # Generar password aleatorio
        original_pwd = ''.join(random.choices(ALPHABET, k=PSW_LEN))
        original_hash = hash_function(original_pwd)
        
        print(f"[Test {test_num}/{num_tests}] Password: '{original_pwd}' Hash: {original_hash.hex()}")
        
        # Buscar colisión
        import time
        start = time.time()
        found_pwd = search_collision(original_hash, rainbow_table, 
                                     chain_length, verbose=False)
        elapsed = time.time() - start
        total_time += elapsed
        
        # Verificar resultado
        if found_pwd:
            found_hash = hash_function(found_pwd)
            is_collision = (found_hash == original_hash)
            
            print(f"  ✓ Encontrado: '{found_pwd}' ({elapsed:.4f}s)", end="")
            
            if is_collision:
                if found_pwd == original_pwd:
                    print(" [Idéntico]")
                else:
                    print(" [Alternativo]")
                success_count += 1
            else:
                print(" [ERROR: hash no coincide]")
        else:
            print(f"  ✗ No encontrado ({elapsed:.4f}s)")
    
    # Resumen
    print("\n" + "-"*70)
    print(f"Éxitos: {success_count}/{num_tests} ({success_count/num_tests*100:.2f}%)")
    print(f"Tiempo promedio: {total_time/num_tests:.4f}s | Total: {total_time:.2f}s")
    
    return success_count, num_tests

def test_search_from_table(rainbow_table: Dict[bytes, str], chain_length: int, 
                           num_tests: int = 10):
    """
    Prueba el algoritmo generando passwords DESDE las cadenas de la tabla.
    Esta prueba verifica que el algoritmo funciona correctamente.
    """
    import random
    import time
    
    print("\n" + "="*70)
    print(f"PRUEBA 2: BÚSQUEDA CON PASSWORDS DE LA TABLA (Verificación)")
    print("="*70)
    print("Nota: Se espera 100% de éxito porque los passwords están en la tabla\n")
    
    success_count = 0
    alternative_count = 0
    total_time = 0
    
    # Seleccionar cadenas aleatorias de la tabla
    sample_entries = random.sample(list(rainbow_table.items()), 
                                  min(num_tests, len(rainbow_table)))
    
    for test_num, (final_hash, initial_pwd) in enumerate(sample_entries, 1):
        # Generar un password intermedio en la cadena
        pwd = initial_pwd
        steps = random.randint(0, chain_length - 1)
        
        for i in range(steps):
            pwd = reduction_function(hash_function(pwd), iteration=i)
        
        target_hash = hash_function(pwd)
        
        print(f"[Test {test_num}/{num_tests}] Target: '{pwd}' (paso {steps}) Hash: {target_hash.hex()}")
        
        # Buscar colisión
        start = time.time()
        found_pwd = search_collision(target_hash, rainbow_table, 
                                     chain_length, verbose=False)
        elapsed = time.time() - start
        total_time += elapsed
        
        # Verificar resultado
        if found_pwd:
            found_hash = hash_function(found_pwd)
            is_collision = (found_hash == target_hash)
            
            print(f"  ✓ Encontrado: '{found_pwd}' ({elapsed:.4f}s)", end="")
            
            if is_collision:
                if found_pwd == pwd:
                    print(" [Idéntico]")
                else:
                    print(" [Alternativo]")
                    alternative_count += 1
                success_count += 1
            else:
                print(" [ERROR: hash no coincide]")
        else:
            print(f"  ✗ No encontrado ({elapsed:.4f}s) [ERROR CRÍTICO]")
    
    # Resumen
    print("\n" + "-"*70)
    print(f"Éxitos: {success_count}/{num_tests} ({success_count/num_tests*100:.2f}%)")
    print(f"  - Idénticos: {success_count - alternative_count}")
    print(f"  - Alternativos: {alternative_count}")
    print(f"Tiempo promedio: {total_time/num_tests:.4f}s | Total: {total_time:.2f}s")
    
    return success_count, num_tests

# Ejemplo de uso
if __name__ == "__main__":
    # Cargar la tabla (ajusta la ruta según tu archivo)
    table_folder = "tables"
    
    # Listar archivos disponibles
    if os.path.exists(table_folder):
        csv_files = [f for f in os.listdir(table_folder) if f.endswith('.csv')]
        
        if csv_files:
            print("Archivos de tabla disponibles:")
            for i, f in enumerate(csv_files, 1):
                print(f"  {i}. {f}")
            
            # Usar el archivo más reciente
            latest_file = max([os.path.join(table_folder, f) for f in csv_files],
                            key=os.path.getmtime)
            print(f"\nUsando: {latest_file}\n")
            
            # Cargar tabla
            rainbow_table, t = load_rainbow_table(latest_file)
            
            # PRUEBA 1: Verificar que el algoritmo funciona con passwords de la tabla
            success1, total1 = test_search_from_table(rainbow_table, t, num_tests=20)
            
            # PRUEBA 2: Simular ataque real con passwords aleatorios
            success2, total2 = test_search_random(rainbow_table, t, num_tests=50)
            
            # Resumen global
            print("\n" + "="*70)
            print("RESUMEN GLOBAL")
            print("="*70)
            print(f"Tabla: {len(rainbow_table):,} cadenas × {t} pasos = ~{len(rainbow_table)*t:,} passwords")
            print(f"Espacio total: {SPACE_SIZE:,} passwords posibles")
            print(f"Cobertura teórica: {len(rainbow_table)*t/SPACE_SIZE*100:.2f}%")
            print()
            print(f"Prueba 1 (verificación): {success1}/{total1} ({success1/total1*100:.1f}%) ✓")
            print(f"Prueba 2 (ataque real): {success2}/{total2} ({success2/total2*100:.1f}%)")
            print()
            print("💡 La Prueba 1 debe dar ~100% (verifica que el código funciona)")
            print("💡 La Prueba 2 refleja la efectividad real del ataque")
        else:
            print(f"No se encontraron archivos CSV en '{table_folder}'")
            print("Primero ejecuta el script de construcción de tabla.")
    else:
        print(f"La carpeta '{table_folder}' no existe.")
        print("Primero ejecuta el script de construcción de tabla.")