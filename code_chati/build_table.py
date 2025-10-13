#!/usr/bin/env python3
"""
build_table.py

Construcción de tabla arcoiris (rainbow table) según el pseudocódigo:
  while tabla.size < n:
      escoger Pi aleatorio
      P = Pi
      for j = 1..t-1:
          P = r(h(P))
      store (Pi, h(P)) as endpoint

Uso:
  python3 build_table.py --n 11882 --t 1000 --out rainbow.csv

Salida: CSV con columnas start_pw, endpoint_hex (endpoint = trunc40(SHA256(P_final)))
"""
import argparse
import hashlib
import secrets
import csv
import os
from typing import Dict

ALPHABET = "abcdefghijklmnopqrstuvwxyz"
PSW_LEN = 5
SPACE_SIZE = len(ALPHABET) ** PSW_LEN  # 26**5
TRUNC_BYTES = 5  # 40 bits = 5 bytes


# ---------- utilidades ----------
def index_to_pw(idx: int) -> str:
    """Convierte índice (0..26^5-1) a contraseña 5-letras en base26."""
    chars = []
    for _ in range(PSW_LEN):
        idx, r = divmod(idx, 26)
        chars.append(ALPHABET[r])
    return ''.join(reversed(chars))


def pw_to_index(pw: str) -> int:
    """Convierte contraseña a índice (por si hace falta)."""
    idx = 0
    for c in pw:
        idx = idx * 26 + ALPHABET.index(c)
    return idx


def hash_trunc40(password: str) -> bytes:
    """SHA-256 truncado a 40 bits (5 bytes)."""
    h = hashlib.sha256(password.encode('utf-8')).digest()
    return h[:TRUNC_BYTES]  # bytes


def bytes_to_hex(b: bytes) -> str:
    return b.hex()


# ---------- función de reducción recomendada ----------
def R(i: int, h_bytes: bytes) -> str:
    """Reducción R(i, h): (int(h_bytes) + i) % SPACE_SIZE -> contraseña base26 de 5 chars."""
    H = int.from_bytes(h_bytes, 'big')
    idx = (H + i) % SPACE_SIZE
    return index_to_pw(idx)


# ---------- construcción de la tabla ----------
def build_table(n: int, t: int, seed: int = None, verbose: bool = True) -> Dict[str, str]:
    """
    Construye una rainbow table con 'n' entradas y cadenas de longitud 't'.
    Devuelve dict endpoint_hex -> start_pw
    """
    if seed is not None:
        # usar seed para reproducibilidad (afecta elección aleatoria de Pi)
        secrets_generator = secrets.SystemRandom(seed)
        randbelow = lambda x: secrets_generator.randrange(x)
    else:
        randbelow = secrets.randbelow

    table: Dict[str, str] = {}  # key: endpoint_hex, value: start_pw

    attempts = 0
    while len(table) < n:
        attempts += 1
        # escoger Pi al azar (como índice dentro del espacio)
        start_idx = randbelow(SPACE_SIZE)
        start_pw = index_to_pw(start_idx)

        P = start_pw
        # iteraciones de la cadena: j = 1 .. t-1
        for j in range(1, t):
            h = hash_trunc40(P)
            P = R(j, h)

        # calcular endpoint hash final
        endpoint_hash = hash_trunc40(P)
        endpoint_hex = bytes_to_hex(endpoint_hash)

        # almacenar si endpoint no estaba ya en la tabla
        if endpoint_hex not in table:
            table[endpoint_hex] = start_pw
            if verbose and (len(table) % max(1, n // 20) == 0):
                print(f"[+] Entradas: {len(table)}/{n} (intentos: {attempts})")
        else:
            # si endpoint repetido lo ignoramos (seguir hasta tener n entradas únicas)
            if verbose and attempts % 10000 == 0:
                print(f"[~] {attempts} intentos, {len(table)} entradas (colisiones de endpoint)")

    if verbose:
        print(f"[done] Tabla construida: {len(table)} entradas (attempts: {attempts})")
    return table


def save_table_csv(table: Dict[str, str], path: str):
    """Guarda la tabla en CSV: start_pw, endpoint_hex"""
    os.makedirs(os.path.dirname(path) or ".", exist_ok=True)
    with open(path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["start_pw", "endpoint_hex"])
        for endpoint_hex, start_pw in table.items():
            writer.writerow([start_pw, endpoint_hex])
    print(f"[save] Guardada tabla CSV en: {path}")


# ---------- CLI ----------
def main():
    p = argparse.ArgumentParser(description="Construir tabla arcoiris (rainbow table)")
    p.add_argument("--n", type=int, required=True, help="Número de entradas de la tabla (n)")
    p.add_argument("--t", type=int, required=True, help="Longitud de cada cadena (t)")
    p.add_argument("--out", type=str, default="rainbow.csv", help="Fichero CSV de salida")
    p.add_argument("--seed", type=int, default=None, help="Seed para reproducibilidad (opcional)")
    p.add_argument("--no-verbose", dest="verbose", action="store_false", help="Silenciar prints")
    args = p.parse_args()

    table = build_table(n=args.n, t=args.t, seed=args.seed, verbose=args.verbose)
    save_table_csv(table, args.out)


if __name__ == "__main__":
    main()
