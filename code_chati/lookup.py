#!/usr/bin/env python3
"""
lookup.py

Búsqueda en tabla rainbow construida con build_table.py

Uso:
  # buscar por hash truncado (hex 10 caracteres para 5 bytes)
  python3 lookup.py --table ../tables/rainbow_26_5_t1000.csv --hash 3f4a1b2c3d

  # o generar hash desde un password (y buscar)
  python3 lookup.py --table ../tables/rainbow_26_5_t1000.csv --password secret

Salida:
  - devuelve el password encontrado o "ERROR: not found"
"""

import argparse
import csv
import hashlib
from typing import Dict

ALPHABET = "abcdefghijklmnopqrstuvwxyz"
PSW_LEN = 5
SPACE_SIZE = len(ALPHABET) ** PSW_LEN
TRUNC_BYTES = 5  # 40 bits

# ---------- utilidades (compatibles con build_table.py) ----------
def index_to_pw(idx: int) -> str:
    chars = []
    for _ in range(PSW_LEN):
        idx, r = divmod(idx, 26)
        chars.append(ALPHABET[r])
    return ''.join(reversed(chars))

def hash_trunc40_from_pw(password: str) -> bytes:
    return hashlib.sha256(password.encode('utf-8')).digest()[:TRUNC_BYTES]

def bytes_to_hex(b: bytes) -> str:
    return b.hex()

def hex_to_bytes(hx: str) -> bytes:
    # acepta ambos formatos: con/ sin '0x', case-insensitive
    hx = hx.lower().strip()
    if hx.startswith("0x"):
        hx = hx[2:]
    return bytes.fromhex(hx)

def R(i: int, h_bytes: bytes) -> str:
    """R(i, h) = (int(h) + i) % SPACE_SIZE -> base26 password"""
    H = int.from_bytes(h_bytes, 'big')
    idx = (H + i) % SPACE_SIZE
    return index_to_pw(idx)

# ---------- cargar tabla CSV endpoint_hex -> start_pw ----------
def load_table_csv(path: str) -> Dict[str, str]:
    table = {}
    with open(path, newline='', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        for row in reader:
            start = row.get("start_pw") or row.get("start") or row.get("pw")  # tolerancia
            endpoint = row.get("endpoint_hex") or row.get("endpoint") or row.get("end")
            if start is None or endpoint is None:
                continue
            table[endpoint.lower()] = start
    return table

# ---------- lookup ----------
def lookup(H_target_bytes: bytes, table: Dict[str,str], t: int):
    # recorre i desde t-1 downto 0
    for i in range(t-1, -1, -1):
        temp = H_target_bytes
        # aplicar reducción y hash desde posición i hasta t-1
        for j in range(i, t):
            pw = R(j+1, temp)     # usar la misma convención: en build_table se usó j=1..t-1
            temp = hash_trunc40_from_pw(pw)
        endpoint_candidate = bytes_to_hex(temp)
        # buscar endpoint en tabla
        start_pw = table.get(endpoint_candidate)
        if start_pw:
            # regenerar cadena desde start_pw y buscar h(P) == H_target
            P = start_pw
            for k in range(0, t):
                if hash_trunc40_from_pw(P) == H_target_bytes:
                    return P  # encontrado
                hP = hash_trunc40_from_pw(P)
                P = R(k+1, hP)
            # si no se encontró en esta cadena, continuar búsqueda (debido a merges)
    return None

# ---------- CLI ----------
def main():
    p = argparse.ArgumentParser(description="Lookup in rainbow table")
    p.add_argument("--table", required=True, help="CSV table file (start_pw, endpoint_hex)")
    p.add_argument("--hash", help="target hash (hex) of truncated hash (5 bytes -> 10 hex chars)")
    p.add_argument("--password", help="or provide an actual password; script will hash it and search")
    p.add_argument("--t", type=int, required=True, help="chain length t used in construction")
    args = p.parse_args()

    if not args.hash and not args.password:
        p.error("Provide --hash or --password")

    table = load_table_csv(args.table)
    if args.hash:
        H_target_bytes = hex_to_bytes(args.hash)
    else:
        H_target_bytes = hash_trunc40_from_pw(args.password)

    result = lookup(H_target_bytes, table, args.t)
    if result:
        print("FOUND:", result)
    else:
        print("ERROR: not found")

if __name__ == "__main__":
    main()
