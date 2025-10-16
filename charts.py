import hashlib
import csv
import os
import random
import time
import matplotlib.pyplot as plt
import numpy as np
from typing import Dict, List, Tuple

# Parámetros (deben coincidir con tu configuración)
ALPHABET = "abcdefghijklmnopqrstuvwxyz0123456789"
PSW_LEN = 5
HASH_LEN = 40
TRUNC_LEN = 8
ALPHABET_SIZE = len(ALPHABET)
SPACE_SIZE = ALPHABET_SIZE ** PSW_LEN

def hash_function(password: str) -> bytes:
    full_hash = hashlib.sha256(password.encode()).digest()
    return full_hash[:5]

def reduction_function(hash_bytes: bytes, iteration: int = 0) -> str:
    hash_int = int.from_bytes(hash_bytes, byteorder='big')
    hash_int = (hash_int + iteration) % (2**40)
    
    password = []
    for i in range(TRUNC_LEN):
        chunk = (hash_int >> (i * 5)) & 0x1F
        char_idx = chunk % ALPHABET_SIZE
        password.append(ALPHABET[char_idx])
    
    return ''.join(password[:PSW_LEN])

def load_rainbow_table(filepath: str) -> Tuple[Dict[bytes, str], int]:
    tabla = {}
    chain_length = 0
    
    with open(filepath, 'r', encoding='utf-8') as csvfile:
        reader = csv.reader(csvfile)
        for row in reader:
            if not row:
                break
            if row[0] == '# Chain Length (t)':
                chain_length = int(row[1])
        
        csvfile.seek(0)
        reader = csv.reader(csvfile)
        for row in reader:
            if row and row[0] == 'initial_password':
                break
        
        for row in reader:
            initial_psw, final_hash_hex = row
            final_hash = bytes.fromhex(final_hash_hex)
            tabla[final_hash] = initial_psw
    
    return tabla, chain_length

def search_collision(p0: bytes, rainbow_table: Dict[bytes, str], 
                    chain_length: int) -> Tuple[bool, float]:
    """Retorna (encontrado, tiempo_en_segundos)"""
    start_time = time.time()
    
    for i in range(chain_length):
        p = p0
        for j in range(i, chain_length - 1):
            p = hash_function(reduction_function(p, iteration=j))
        
        if p in rainbow_table:
            found_entry = rainbow_table[p]
            pwd = found_entry
            
            for step in range(chain_length - 1):
                if hash_function(pwd) == p0:
                    elapsed = time.time() - start_time
                    return True, elapsed
                pwd = reduction_function(hash_function(pwd), iteration=step)
            
            if hash_function(pwd) == p0:
                elapsed = time.time() - start_time
                return True, elapsed
    
    elapsed = time.time() - start_time
    return False, elapsed

def generate_test_data(rainbow_table: Dict[bytes, str], chain_length: int, 
                      num_tests: int = 100) -> Tuple[List[bool], List[float]]:
    """Genera datos de prueba para gráficas"""
    print(f"\nGenerando {num_tests} tests...")
    
    successes = []
    times = []
    
    for i in range(num_tests):
        if i % 10 == 0:
            print(f"  Progreso: {i}/{num_tests}")
        
        # Generar password aleatorio
        pwd = ''.join(random.choices(ALPHABET, k=PSW_LEN))
        target_hash = hash_function(pwd)
        
        # Buscar colisión
        found, elapsed = search_collision(target_hash, rainbow_table, chain_length)
        
        successes.append(found)
        times.append(elapsed)
    
    print(f"  Completado: {sum(successes)}/{num_tests} encontrados")
    return successes, times

def plot_success_rate(successes: List[bool], output_dir: str = "charts"):
    """Gráfica 1: Tasa de éxito"""
    os.makedirs(output_dir, exist_ok=True)
    
    fig, ax = plt.subplots(figsize=(10, 6))
    
    success_count = sum(successes)
    fail_count = len(successes) - success_count
    
    colors = ['#2ecc71', '#e74c3c']
    labels = [f'Éxito\n({success_count})', f'Fallo\n({fail_count})']
    sizes = [success_count, fail_count]
    
    wedges, texts, autotexts = ax.pie(sizes, labels=labels, colors=colors, 
                                        autopct='%1.1f%%', startangle=90,
                                        textprops={'fontsize': 12, 'weight': 'bold'})
    
    ax.set_title('Tasa de Éxito en Búsqueda de Colisiones', 
                 fontsize=16, weight='bold', pad=20)
    
    plt.tight_layout()
    filepath = os.path.join(output_dir, '1_tasa_exito.png')
    plt.savefig(filepath, dpi=300, bbox_inches='tight')
    print(f"[OK] Guardado: {filepath}")
    plt.close()

def plot_time_distribution(times: List[float], successes: List[bool], 
                          output_dir: str = "charts"):
    """Gráfica 2: Distribución de tiempos"""
    os.makedirs(output_dir, exist_ok=True)
    
    success_times = [t for t, s in zip(times, successes) if s]
    fail_times = [t for t, s in zip(times, successes) if not s]
    
    fig, ax = plt.subplots(figsize=(12, 6))
    
    bins = 30
    ax.hist(success_times, bins=bins, alpha=0.7, label='Éxito', color='#2ecc71', edgecolor='black')
    ax.hist(fail_times, bins=bins, alpha=0.7, label='Fallo', color='#e74c3c', edgecolor='black')
    
    ax.set_xlabel('Tiempo (segundos)', fontsize=12, weight='bold')
    ax.set_ylabel('Frecuencia', fontsize=12, weight='bold')
    ax.set_title('Distribución de Tiempos de Búsqueda', fontsize=16, weight='bold')
    ax.legend(fontsize=11)
    ax.grid(True, alpha=0.3)
    
    plt.tight_layout()
    filepath = os.path.join(output_dir, '2_distribucion_tiempos.png')
    plt.savefig(filepath, dpi=300, bbox_inches='tight')
    print(f"[OK] Guardado: {filepath}")
    plt.close()

def plot_cumulative_success(successes: List[bool], output_dir: str = "charts"):
    """Gráfica 3: Éxito acumulado"""
    os.makedirs(output_dir, exist_ok=True)
    
    cumulative = np.cumsum(successes)
    tests = np.arange(1, len(successes) + 1)
    success_rate = (cumulative / tests) * 100
    
    fig, ax = plt.subplots(figsize=(12, 6))
    
    ax.plot(tests, success_rate, linewidth=2, color='#3498db')
    ax.axhline(y=success_rate[-1], color='#e74c3c', linestyle='--', 
               linewidth=2, label=f'Tasa final: {success_rate[-1]:.1f}%')
    
    ax.set_xlabel('Número de Tests', fontsize=12, weight='bold')
    ax.set_ylabel('Tasa de Éxito (%)', fontsize=12, weight='bold')
    ax.set_title('Tasa de Éxito Acumulada', fontsize=16, weight='bold')
    ax.legend(fontsize=11)
    ax.grid(True, alpha=0.3)
    ax.set_ylim([0, 100])
    
    plt.tight_layout()
    filepath = os.path.join(output_dir, '3_exito_acumulado.png')
    plt.savefig(filepath, dpi=300, bbox_inches='tight')
    print(f"[OK] Guardado: {filepath}")
    plt.close()

def plot_time_comparison(times: List[float], successes: List[bool], 
                        output_dir: str = "charts"):
    """Gráfica 4: Comparación de tiempos éxito vs fallo"""
    os.makedirs(output_dir, exist_ok=True)
    
    success_times = [t for t, s in zip(times, successes) if s]
    fail_times = [t for t, s in zip(times, successes) if not s]
    
    fig, ax = plt.subplots(figsize=(10, 6))
    
    data = [success_times, fail_times]
    labels = ['Éxito', 'Fallo']
    colors = ['#2ecc71', '#e74c3c']
    
    bp = ax.boxplot(data, labels=labels, patch_artist=True, 
                    notch=True, showmeans=True)
    
    for patch, color in zip(bp['boxes'], colors):
        patch.set_facecolor(color)
        patch.set_alpha(0.7)
    
    ax.set_ylabel('Tiempo (segundos)', fontsize=12, weight='bold')
    ax.set_title('Comparación de Tiempos: Éxito vs Fallo', fontsize=16, weight='bold')
    ax.grid(True, alpha=0.3, axis='y')
    
    # Añadir estadísticas
    if success_times:
        avg_success = np.mean(success_times)
        ax.text(1, avg_success, f'Media: {avg_success:.4f}s', 
               ha='center', va='bottom', fontsize=10, weight='bold')
    if fail_times:
        avg_fail = np.mean(fail_times)
        ax.text(2, avg_fail, f'Media: {avg_fail:.4f}s', 
               ha='center', va='bottom', fontsize=10, weight='bold')
    
    plt.tight_layout()
    filepath = os.path.join(output_dir, '4_comparacion_tiempos.png')
    plt.savefig(filepath, dpi=300, bbox_inches='tight')
    print(f"[OK] Guardado: {filepath}")
    plt.close()

def plot_table_coverage(rainbow_table: Dict[bytes, str], chain_length: int,
                       output_dir: str = "charts"):
    """Gráfica 5: Cobertura de la tabla"""
    os.makedirs(output_dir, exist_ok=True)
    
    n = len(rainbow_table)
    t = chain_length
    
    theoretical_coverage = (n * t / SPACE_SIZE) * 100
    
    fig, ax = plt.subplots(figsize=(10, 6))
    
    categories = ['Espacio Total', 'Cobertura Teórica']
    values = [SPACE_SIZE, n * t]
    colors = ['#95a5a6', '#3498db']
    
    bars = ax.bar(categories, values, color=colors, edgecolor='black', linewidth=2)
    
    # Añadir valores encima de las barras
    for bar, value in zip(bars, values):
        height = bar.get_height()
        ax.text(bar.get_x() + bar.get_width()/2., height,
                f'{value:,}\n({value/SPACE_SIZE*100:.1f}%)',
                ha='center', va='bottom', fontsize=11, weight='bold')
    
    ax.set_ylabel('Número de Passwords', fontsize=12, weight='bold')
    ax.set_title(f'Cobertura de la Tabla Arcoíris\n(n={n:,} cadenas × t={t} pasos)', 
                 fontsize=16, weight='bold')
    ax.grid(True, alpha=0.3, axis='y')
    
    # Formato del eje Y
    ax.yaxis.set_major_formatter(plt.FuncFormatter(lambda x, p: f'{int(x):,}'))
    
    plt.tight_layout()
    filepath = os.path.join(output_dir, '5_cobertura_tabla.png')
    plt.savefig(filepath, dpi=300, bbox_inches='tight')
    print(f"[OK] Guardado: {filepath}")
    plt.close()

def generate_summary_report(rainbow_table: Dict[bytes, str], chain_length: int,
                           successes: List[bool], times: List[float],
                           output_dir: str = "charts"):
    """Genera un informe resumen en texto"""
    os.makedirs(output_dir, exist_ok=True)
    
    success_count = sum(successes)
    success_rate = (success_count / len(successes)) * 100
    
    success_times = [t for t, s in zip(times, successes) if s]
    fail_times = [t for t, s in zip(times, successes) if not s]
    
    report = f"""
{'='*70}
INFORME DE RESULTADOS - TABLA ARCOÍRIS
{'='*70}

CONFIGURACIÓN:
  - Alfabeto: {ALPHABET}
  - Tamaño alfabeto: {ALPHABET_SIZE} caracteres
  - Longitud password: {PSW_LEN} caracteres
  - Espacio total: {SPACE_SIZE:,} passwords posibles

TABLA ARCOÍRIS:
  - Número de cadenas (n): {len(rainbow_table):,}
  - Longitud de cadena (t): {chain_length}
  - Passwords cubiertos (teórico): {len(rainbow_table) * chain_length:,}
  - Cobertura teórica: {(len(rainbow_table) * chain_length / SPACE_SIZE * 100):.2f}%

RESULTADOS DE PRUEBAS ({len(successes)} tests):
  - Colisiones encontradas: {success_count}/{len(successes)}
  - Tasa de éxito: {success_rate:.2f}%
  - Fallos: {len(successes) - success_count}

TIEMPOS DE BÚSQUEDA:
  General:
    - Tiempo promedio: {np.mean(times):.4f} segundos
    - Tiempo mínimo: {np.min(times):.4f} segundos
    - Tiempo máximo: {np.max(times):.4f} segundos
    - Desviación estándar: {np.std(times):.4f} segundos
"""
    
    if success_times:
        report += f"""
  Búsquedas exitosas:
    - Tiempo promedio: {np.mean(success_times):.4f} segundos
    - Tiempo mínimo: {np.min(success_times):.4f} segundos
    - Tiempo máximo: {np.max(success_times):.4f} segundos
"""
    
    if fail_times:
        report += f"""
  Búsquedas fallidas:
    - Tiempo promedio: {np.mean(fail_times):.4f} segundos
    - Tiempo mínimo: {np.min(fail_times):.4f} segundos
    - Tiempo máximo: {np.max(fail_times):.4f} segundos
"""
    
    report += f"""
ANÁLISIS:
  - Eficiencia real vs teórica: {success_rate / (len(rainbow_table) * chain_length / SPACE_SIZE * 100) * 100:.1f}%
  - Pérdida por colisiones: {100 - (success_rate / (len(rainbow_table) * chain_length / SPACE_SIZE * 100) * 100):.1f}%

{'='*70}
"""
    
    filepath = os.path.join(output_dir, 'informe_resultados.txt')
    with open(filepath, 'w', encoding='utf-8') as f:
        f.write(report)
    
    print(f"[OK] Guardado: {filepath}")
    print(report)

if __name__ == "__main__":
    # Cargar tabla
    table_folder = "tables"
    
    if not os.path.exists(table_folder):
        print(f"Error: La carpeta '{table_folder}' no existe.")
        exit(1)
    
    csv_files = [f for f in os.listdir(table_folder) if f.endswith('.csv')]
    
    if not csv_files:
        print(f"Error: No hay archivos CSV en '{table_folder}'")
        exit(1)
    
    latest_file = max([os.path.join(table_folder, f) for f in csv_files],
                     key=os.path.getmtime)
    
    print(f"Cargando tabla: {latest_file}")
    rainbow_table, chain_length = load_rainbow_table(latest_file)
    print(f"[OK] Tabla cargada: {len(rainbow_table):,} entradas, t={chain_length}")
    
    # Generar datos de prueba
    num_tests = 100  # Puedes cambiar este número
    successes, times = generate_test_data(rainbow_table, chain_length, num_tests)
    
    # Generar todas las gráficas
    print("\nGenerando gráficas...")
    plot_success_rate(successes)
    plot_time_distribution(times, successes)
    plot_cumulative_success(successes)
    plot_time_comparison(times, successes)
    plot_table_coverage(rainbow_table, chain_length)
    
    # Generar informe
    print("\nGenerando informe...")
    generate_summary_report(rainbow_table, chain_length, successes, times)
    
    print("\n[OK] ¡Proceso completado!")
    print("  Revisa la carpeta 'charts/' para ver las gráficas generadas.")