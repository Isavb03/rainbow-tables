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
TRUNC_LEN = 5  # bytes (40 bits / 8 = 5 bytes)
CHAIN_LENGTH = 1000  # t en el algoritmo
TABLE_SIZE = 10000   # n en el algoritmo

class RainbowTable:
    def __init__(self, chain_length=CHAIN_LENGTH, table_size=TABLE_SIZE):
        self.chain_length = chain_length
        self.table_size = table_size
        self.table = {}  # Diccionario indexado por hash final
        
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
        """
        # Convertir hash hex a entero
        hash_int = int(hash_value, 16)
        # Agregar la iteración para hacer la función diferente en cada paso
        hash_int = (hash_int + iteration) % (26 ** PSW_LEN)
        
        # Convertir a contraseña de 5 caracteres
        password = ""
        for _ in range(PSW_LEN):
            password = ALPHABET[hash_int % 26] + password
            hash_int //= 26
            
        return password
    
    def generate_random_password(self):
        """Genera una contraseña aleatoria de 5 caracteres"""
        return ''.join(random.choice(ALPHABET) for _ in range(PSW_LEN))
    
    def build_table(self):
        """
        Construcción de la tabla arco iris
        Algoritmo: AtaqueArcoiris-Construcción
        """
        print(f"Construyendo tabla arco iris...")
        print(f"Parámetros: cadenas={self.chain_length}, entradas={self.table_size}")
        
        start_time = time.time()
        entries_added = 0
        
        while len(self.table) < self.table_size:
            # Escoger Pi un password al azar
            pi = self.generate_random_password()
            p = pi
            
            # Generar la cadena
            for j in range(self.chain_length - 1):
                hash_p = self.hash_function(p)
                p = self.reduction_function(hash_p, j)
            
            # Calcular hash final
            final_hash = self.hash_function(p)
            
            # Almacenar <Pi, hash(P_final)> en la tabla
            # Usamos el hash final como clave para indexación rápida
            if final_hash not in self.table:
                self.table[final_hash] = pi
                entries_added += 1
                
                if entries_added % 1000 == 0:
                    print(f"Entradas añadidas: {entries_added}")
        
        build_time = time.time() - start_time
        print(f"Tabla construida en {build_time:.2f} segundos")
        print(f"Tamaño final de la tabla: {len(self.table)}")
        return build_time
    
    def search_collision(self, target_hash, timeout=30):
        """
        Búsqueda de colisión
        Algoritmo: AtaqueArcoiris-BúsquedaColisión
        """
        start_time = time.time()
        p = target_hash
        
        # Buscar en la tabla
        for i in range(self.chain_length):
            # Verificar timeout
            if time.time() - start_time > timeout:
                return None, time.time() - start_time
            
            # Verificar si existe en la tabla
            if p in self.table:
                # Reconstruir la cadena desde el inicio
                pwd = self.table[p]
                
                # Seguir la cadena hasta encontrar la colisión
                for j in range(self.chain_length):
                    if self.hash_function(pwd) == target_hash:
                        search_time = time.time() - start_time
                        return pwd, search_time
                    
                    hash_pwd = self.hash_function(pwd)
                    pwd = self.reduction_function(hash_pwd, j)
                
                # Si llegamos aquí, es una falsa alarma
                break
            
            # Continuar la búsqueda
            p_reduced = self.reduction_function(p, self.chain_length - 1 - i)
            p = self.hash_function(p_reduced)
        
        search_time = time.time() - start_time
        return None, search_time

def run_experiments(num_tests=100, timeout=30):
    """
    Ejecuta experimentos con la tabla arco iris
    """
    print("=== INICIANDO EXPERIMENTOS ===")
    
    # Construir tabla arco iris
    rainbow_table = RainbowTable()
    build_time = rainbow_table.build_table()
    
    # Generar contraseñas de prueba
    test_passwords = []
    for _ in range(num_tests):
        test_passwords.append(rainbow_table.generate_random_password())
    
    print(f"\n=== PROBANDO {num_tests} CONTRASEÑAS ===")
    
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
        print(f"\nTest {i+1}/{num_tests}")
        print(f"Contraseña objetivo: {password}")
        print(f"Hash objetivo: {target_hash}")
        
        # Buscar colisión
        found_pwd, search_time = rainbow_table.search_collision(target_hash, timeout)
        
        results['search_times'].append(search_time)
        results['test_passwords'].append(password)
        results['target_hashes'].append(target_hash)
        
        if found_pwd:
            results['successful_attacks'] += 1
            results['successful_times'].append(search_time)
            results['found_passwords'].append(found_pwd)
            print(f"✓ Colisión encontrada: {found_pwd}")
            print(f"  Tiempo de búsqueda: {search_time:.4f} segundos")
            
            # Verificar que realmente es una colisión
            found_hash = rainbow_table.hash_function(found_pwd)
            if found_hash == target_hash:
                if found_pwd == password:
                    print(f"  → Contraseña original recuperada")
                else:
                    print(f"  → Contraseña alternativa encontrada")
            else:
                print(f"  ⚠ ERROR: Los hashes no coinciden")
        else:
            results['failed_attacks'] += 1
            results['found_passwords'].append(None)
            print(f"✗ No se encontró colisión")
            print(f"  Tiempo agotado: {search_time:.4f} segundos")
    
    # Calcular estadísticas
    success_rate = (results['successful_attacks'] / num_tests) * 100
    avg_search_time = statistics.mean(results['search_times'])
    
    if results['successful_times']:
        avg_successful_time = statistics.mean(results['successful_times'])
        median_successful_time = statistics.median(results['successful_times'])
    else:
        avg_successful_time = 0
        median_successful_time = 0
    
    print(f"\n=== RESULTADOS FINALES ===")
    print(f"Contraseñas probadas: {num_tests}")
    print(f"Ataques exitosos: {results['successful_attacks']}")
    print(f"Ataques fallidos: {results['failed_attacks']}")
    print(f"Tasa de éxito: {success_rate:.2f}%")
    print(f"Tiempo promedio de búsqueda: {avg_search_time:.4f} segundos")
    print(f"Tiempo promedio de ataques exitosos: {avg_successful_time:.4f} segundos")
    print(f"Tiempo mediano de ataques exitosos: {median_successful_time:.4f} segundos")
    print(f"Tiempo de construcción de tabla: {build_time:.2f} segundos")
    print(f"Tamaño de tabla: {len(rainbow_table.table)} entradas")
    print(f"Timeout configurado: {timeout} segundos")
    
    return results, rainbow_table

def plot_results(results):
    """
    Genera gráficas de los resultados
    """
    fig, ((ax1, ax2), (ax3, ax4)) = plt.subplots(2, 2, figsize=(15, 10))
    
    # Gráfica 1: Tasa de éxito
    success_rate = (results['successful_attacks'] / len(results['test_passwords'])) * 100
    labels = ['Exitosos', 'Fallidos']
    sizes = [results['successful_attacks'], results['failed_attacks']]
    colors = ['lightgreen', 'lightcoral']
    
    ax1.pie(sizes, labels=labels, colors=colors, autopct='%1.1f%%', startangle=90)
    ax1.set_title('Tasa de Éxito de los Ataques')
    
    # Gráfica 2: Distribución de tiempos de búsqueda
    ax2.hist(results['search_times'], bins=20, alpha=0.7, color='skyblue')
    ax2.set_xlabel('Tiempo de búsqueda (segundos)')
    ax2.set_ylabel('Frecuencia')
    ax2.set_title('Distribución de Tiempos de Búsqueda')
    
    # Gráfica 3: Tiempos de ataques exitosos vs fallidos
    successful_times = results['successful_times'] if results['successful_times'] else [0]
    failed_times = [t for i, t in enumerate(results['search_times']) 
                   if results['found_passwords'][i] is None]
    
    ax3.boxplot([successful_times, failed_times], 
               labels=['Exitosos', 'Fallidos'])
    ax3.set_ylabel('Tiempo (segundos)')
    ax3.set_title('Comparación de Tiempos: Exitosos vs Fallidos')
    
    # Gráfica 4: Evolución temporal de los ataques
    attack_numbers = list(range(1, len(results['search_times']) + 1))
    colors = ['green' if pwd is not None else 'red' 
             for pwd in results['found_passwords']]
    
    ax4.scatter(attack_numbers, results['search_times'], c=colors, alpha=0.6)
    ax4.set_xlabel('Número de ataque')
    ax4.set_ylabel('Tiempo de búsqueda (segundos)')
    ax4.set_title('Evolución Temporal de los Ataques')
    ax4.legend(['Exitoso', 'Fallido'])
    
    plt.tight_layout()
    plt.show()

if __name__ == "__main__":
    print("=== ATAQUE CON TABLAS ARCO IRIS ===")
    print("Parámetros:")
    print(f"- Algoritmo hash: SHA-256 truncado a {HASH_LEN} bits")
    print(f"- Longitud contraseña: {PSW_LEN} caracteres")
    print(f"- Alfabeto: {ALPHABET}")
    print(f"- Longitud cadena: {CHAIN_LENGTH}")
    print(f"- Tamaño tabla: {TABLE_SIZE}")
    
    # Ejecutar experimentos
    results, rainbow_table = run_experiments(num_tests=50, timeout=10)
    
    # Generar gráficas
    plot_results(results)
    
    # Ejemplo de uso individual
    print("\n=== EJEMPLO DE USO INDIVIDUAL ===")
    test_pwd = "hello"
    target_hash = rainbow_table.hash_function(test_pwd)
    print(f"Buscando colisión para: {test_pwd} (hash: {target_hash})")
    
    found_pwd, search_time = rainbow_table.search_collision(target_hash, timeout=10)
    if found_pwd:
        print(f"Colisión encontrada: {found_pwd} en {search_time:.4f} segundos")
    else:
        print(f"No se encontró colisión en {search_time:.4f} segundos")