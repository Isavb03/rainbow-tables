import hashlib
import random
import time
import matplotlib.pyplot as plt
from collections import defaultdict
import statistics

# ----------- PARÁMETROS ----------------
ALPHABET = "abcdefghijklmnopqrstuvwxyz"
PSW_LEN = 5
HASH_LEN = 40  # bits
CHAIN_LENGTH = 1000  # t en el algoritmo
TABLE_SIZE = 10000   # n en el algoritmo

class RainbowTable:
    def __init__(self, chain_length=CHAIN_LENGTH, table_size=TABLE_SIZE):
        self.chain_length = chain_length
        self.table_size = table_size
        self.table = {}  # Diccionario indexado por hash final
        self.debug = True  # Para diagnóstico
        
    def hash_function(self, password):
        """
        Función resumen h: SHA-256 truncado a 40 bits
        """
        sha256_hash = hashlib.sha256(password.encode()).hexdigest()
        # Truncar a 40 bits (5 bytes = 10 caracteres hex)
        truncated = sha256_hash[:10]
        return truncated
    
    def reduction_function(self, hash_value, iteration=0):
        """
        Función de reducción r: determinista
        Convierte un hash de 40 bits a una contraseña de 5 caracteres
        CORREGIDA: Mejor distribución
        """
        # Convertir hash hex a entero
        hash_int = int(hash_value, 16)
        
        # Usar la iteración para crear diferentes funciones de reducción
        # Esto evita que las cadenas se fusionen
        seed = (hash_int + iteration * 0x12345678) % (2**40)
        
        # Convertir a contraseña de 5 caracteres
        password = ""
        current = seed
        for i in range(PSW_LEN):
            password = ALPHABET[current % 26] + password
            current //= 26
            
        return password
    
    def generate_random_password(self):
        """Genera una contraseña aleatoria de 5 caracteres"""
        return ''.join(random.choice(ALPHABET) for _ in range(PSW_LEN))
    
    def build_table(self):
        """
        Construcción de la tabla arco iris
        CORREGIDA: Mejor manejo de colisiones
        """
        print(f"Construyendo tabla arco iris...")
        print(f"Parámetros: cadenas={self.chain_length}, entradas={self.table_size}")
        
        start_time = time.time()
        entries_added = 0
        collisions = 0
        
        while len(self.table) < self.table_size:
            # Escoger Pi un password al azar
            pi = self.generate_random_password()
            p = pi
            
            # Generar la cadena
            for j in range(self.chain_length - 1):
                hash_p = self.hash_function(p)
                p = self.reduction_function(hash_p, j)  # Usar j como iteración
            
            # Calcular hash final
            final_hash = self.hash_function(p)
            
            # Verificar si ya existe esta entrada
            if final_hash not in self.table:
                self.table[final_hash] = pi
                entries_added += 1
                
                if entries_added % 1000 == 0:
                    print(f"Entradas añadidas: {entries_added}")
                    if self.debug and entries_added <= 3000:
                        print(f"  Ejemplo: '{pi}' -> ... -> hash final: {final_hash}")
            else:
                collisions += 1
        
        build_time = time.time() - start_time
        print(f"Tabla construida en {build_time:.2f} segundos")
        print(f"Tamaño final de la tabla: {len(self.table)}")
        print(f"Colisiones evitadas: {collisions}")
        
        # Diagnóstico de la tabla
        if self.debug:
            self.diagnose_table()
        
        return build_time
    
    def diagnose_table(self):
        """Diagnóstico de la tabla construida"""
        print("\n=== DIAGNÓSTICO DE LA TABLA ===")
        
        # Mostrar algunos ejemplos de la tabla
        sample_entries = list(self.table.items())[:5]
        print("Ejemplos de entradas en la tabla:")
        for final_hash, start_pwd in sample_entries:
            print(f"  {final_hash} <- '{start_pwd}'")
        
        # Verificar que las cadenas se construyan correctamente
        print("\nVerificación de cadenas:")
        test_entry = sample_entries[0]
        final_hash, start_pwd = test_entry
        
        p = start_pwd
        print(f"Verificando cadena desde '{start_pwd}':")
        for j in range(min(3, self.chain_length - 1)):  # Solo primeros 3 pasos
            hash_p = self.hash_function(p)
            p_new = self.reduction_function(hash_p, j)
            print(f"  Paso {j}: '{p}' -> {hash_p} -> '{p_new}'")
            p = p_new
        
        # Verificar hash final
        p = start_pwd
        for j in range(self.chain_length - 1):
            hash_p = self.hash_function(p)
            p = self.reduction_function(hash_p, j)
        
        computed_final = self.hash_function(p)
        print(f"Hash final computado: {computed_final}")
        print(f"Hash final almacenado: {final_hash}")
        print(f"¿Coinciden? {'✓' if computed_final == final_hash else '✗'}")
    
    def search_collision(self, target_hash, timeout=30):
        """
        Búsqueda de colisión - CORREGIDA
        """
        start_time = time.time()
        
        if self.debug:
            print(f"Buscando colisión para hash: {target_hash}")
        
        # Intentar cada posición en la cadena
        for pos in range(self.chain_length):
            if time.time() - start_time > timeout:
                return None, time.time() - start_time
            
            # Construir sufijo desde la posición pos
            current_hash = target_hash
            
            # Aplicar las funciones restantes hasta el final
            for j in range(pos, self.chain_length - 1):
                reduced = self.reduction_function(current_hash, j)
                current_hash = self.hash_function(reduced)
            
            if self.debug and pos < 3:
                print(f"  Pos {pos}: target -> ... -> {current_hash}")
            
            # ¿Este hash final está en nuestra tabla?
            if current_hash in self.table:
                if self.debug:
                    print(f"  ✓ Hash encontrado en tabla en posición {pos}")
                
                # Reconstruir la cadena desde el principio
                start_pwd = self.table[current_hash]
                current_pwd = start_pwd
                
                # Avanzar hasta la posición donde debería estar nuestro target
                for j in range(pos):
                    hash_val = self.hash_function(current_pwd)
                    current_pwd = self.reduction_function(hash_val, j)
                
                # Verificar si encontramos la colisión
                computed_hash = self.hash_function(current_pwd)
                if computed_hash == target_hash:
                    search_time = time.time() - start_time
                    if self.debug:
                        print(f"  ✓ Colisión confirmada: '{current_pwd}'")
                    return current_pwd, search_time
                elif self.debug:
                    print(f"  ✗ Falsa alarma: esperaba {target_hash}, obtuve {computed_hash}")
        
        search_time = time.time() - start_time
        if self.debug:
            print(f"  ✗ No se encontró colisión después de {self.chain_length} posiciones")
        return None, search_time

def test_basic_functionality():
    """Prueba básica de funcionalidad"""
    print("=== PRUEBA BÁSICA DE FUNCIONALIDAD ===")
    
    # Crear tabla pequeña para pruebas
    rt = RainbowTable(chain_length=100, table_size=500)
    rt.debug = True
    
    print("\n1. Probando funciones hash y reducción:")
    test_pwd = "hello"
    test_hash = rt.hash_function(test_pwd)
    reduced = rt.reduction_function(test_hash, 0)
    
    print(f"'{test_pwd}' -> {test_hash} -> '{reduced}'")
    
    print("\n2. Construyendo tabla pequeña:")
    rt.build_table()
    
    print("\n3. Probando búsqueda con contraseña conocida:")
    # Tomar una contraseña que sabemos está en una cadena
    sample_hash, sample_start = list(rt.table.items())[0]
    
    # Reconstruir parte de la cadena para obtener una contraseña intermedia
    p = sample_start
    for i in range(10):  # Avanzar 10 pasos
        hash_val = rt.hash_function(p)
        p = rt.reduction_function(hash_val, i)
    
    target_hash = rt.hash_function(p)
    print(f"Buscando contraseña '{p}' con hash {target_hash}")
    
    result, search_time = rt.search_collision(target_hash, timeout=10)
    
    if result:
        print(f"✓ Encontrada: '{result}' en {search_time:.4f}s")
        # Verificar que el hash coincide
        verify_hash = rt.hash_function(result)
        print(f"Verificación: {verify_hash} == {target_hash} ? {'✓' if verify_hash == target_hash else '✗'}")
    else:
        print(f"✗ No encontrada en {search_time:.4f}s")

def run_experiments_improved(num_tests=50, timeout=10):
    """Versión mejorada de experimentos"""
    print("=== EXPERIMENTOS MEJORADOS ===")
    
    # Usar parámetros más pequeños para mejor cobertura
    rainbow_table = RainbowTable(chain_length=500, table_size=5000)
    rainbow_table.debug = False  # Desactivar debug para experimentos masivos
    
    build_time = rainbow_table.build_table()
    
    # Estrategia mixta: algunas contraseñas de cadenas conocidas + aleatorias
    test_passwords = []
    
    # 1. Generar algunas contraseñas que sabemos están en cadenas (debería tener éxito)
    print("Generando contraseñas de test...")
    sample_entries = list(rainbow_table.table.items())[:num_tests//3]
    
    for final_hash, start_pwd in sample_entries:
        # Tomar una contraseña de la mitad de una cadena conocida
        p = start_pwd
        mid_point = rainbow_table.chain_length // 2
        for i in range(mid_point):
            hash_val = rainbow_table.hash_function(p)
            p = rainbow_table.reduction_function(hash_val, i)
        test_passwords.append(p)
    
    # 2. Rellenar con contraseñas completamente aleatorias
    while len(test_passwords) < num_tests:
        test_passwords.append(rainbow_table.generate_random_password())
    
    print(f"Probando {len(test_passwords)} contraseñas...")
    
    results = {
        'successful_attacks': 0,
        'failed_attacks': 0,
        'search_times': [],
        'successful_times': [],
        'test_passwords': [],
        'found_passwords': [],
        'target_hashes': []
    }
    
    for i, password in enumerate(test_passwords):
        target_hash = rainbow_table.hash_function(password)
        print(f"Test {i+1:2d}: '{password}' -> {target_hash} ", end="")
        
        found_pwd, search_time = rainbow_table.search_collision(target_hash, timeout)
        
        results['search_times'].append(search_time)
        results['test_passwords'].append(password)
        results['target_hashes'].append(target_hash)
        
        if found_pwd:
            results['successful_attacks'] += 1
            results['successful_times'].append(search_time)
            results['found_passwords'].append(found_pwd)
            
            if found_pwd == password:
                print(f"✓ Original ({search_time:.4f}s)")
            else:
                print(f"✓ Alternativa: '{found_pwd}' ({search_time:.4f}s)")
        else:
            results['failed_attacks'] += 1
            results['found_passwords'].append(None)
            print(f"✗ ({search_time:.4f}s)")
    
    # Estadísticas finales
    success_rate = (results['successful_attacks'] / num_tests) * 100
    avg_search_time = statistics.mean(results['search_times'])
    
    print(f"\n=== RESULTADOS FINALES ===")
    print(f"Contraseñas probadas: {num_tests}")
    print(f"Ataques exitosos: {results['successful_attacks']}")
    print(f"Ataques fallidos: {results['failed_attacks']}")
    print(f"Tasa de éxito: {success_rate:.2f}%")
    print(f"Tiempo promedio de búsqueda: {avg_search_time:.4f} segundos")
    
    if results['successful_times']:
        avg_successful = statistics.mean(results['successful_times'])
        print(f"Tiempo promedio de ataques exitosos: {avg_successful:.4f} segundos")
    
    print(f"Tiempo de construcción de tabla: {build_time:.2f} segundos")
    print(f"Parámetros: cadenas={rainbow_table.chain_length}, tabla={rainbow_table.table_size}")
    
    return results, rainbow_table

if __name__ == "__main__":
    print("=== DIAGNÓSTICO Y CORRECCIÓN DE TABLAS ARCO IRIS ===\n")
    
    # Ejecutar prueba básica primero
    test_basic_functionality()
    
    print("\n" + "="*60 + "\n")
    
    # Ejecutar experimentos mejorados
    results, rainbow_table = run_experiments_improved(num_tests=30, timeout=15)
    
    # Si queremos también probar la versión original grande:
    print("\n¿Quieres probar también con parámetros grandes? (esto tomará varios minutos)")
    response = input("Escribe 'si' para continuar: ").strip().lower()
    
    if response == 'si':
        print("\nProbando con parámetros originales...")
        rt_large = RainbowTable(chain_length=1000, table_size=10000)
        rt_large.debug = False
        rt_large.build_table()
        
        # Probar solo algunas contraseñas con la tabla grande
        test_pwds = [rt_large.generate_random_password() for _ in range(10)]
        success_count = 0
        
        for pwd in test_pwds:
            target = rt_large.hash_function(pwd)
            result, time_taken = rt_large.search_collision(target, timeout=20)
            if result:
                success_count += 1
                print(f"'{pwd}' -> ✓ '{result}' ({time_taken:.3f}s)")
            else:
                print(f"'{pwd}' -> ✗ ({time_taken:.3f}s)")
        
        print(f"Tabla grande: {success_count}/10 éxitos ({success_count*10}%)")