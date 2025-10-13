#!/usr/bin/env python3
"""
lookup_debug.py

Uso:
  python3 lookup_debug.py --table ../tables/rainbow_26_5_t1000.csv --password holap --t 1000

Opciones:
  --bruteforce  hace un brute-force por todo el espacio (solo si quieres comprobar integridad)
  --max-print N imprime hasta N pasos de reconstrucción por candidato (default 20)
"""
import argparse
import csv
import hashlib
import time
from typing import Dict, Optional

ALPHABET = "abcdefghijklmnopqrstuvwxyz"
PSW_LEN = 5
SPACE_SIZE = len(ALPHABET) ** PSW_LEN
TRUNC_BYTES = 5  # 40 bits

def index_to_pw(idx: int) -> str:
    chars = []
    for _ in range(PSW_LEN):
        idx, r = divmod(idx, 26)
        chars.append(ALPHABET[r])
    return ''.join(reversed(chars))

def pw_to_index(pw: str) -> int:
    idx = 0
    for c in pw:
        idx = idx * 26 + ALPHABET.index(c)
    return idx

def hash_trunc40_from_pw(password: str) -> bytes:
    return hashlib.sha256(password.encode('utf-8')).digest()[:TRUNC_BYTES]

def bytes_to_hex(b: bytes) -> str:
    return b.hex()

def hex_to_bytes(hx: str) -> bytes:
    hx = hx.lower().strip()
    if hx.startswith("0x"):
        hx = hx[2:]
    return bytes.fromhex(hx)

def load_table_csv(path: str) -> Dict[str,str]:
    table = {}
    with open(path, newline='', encoding='utf-8') as f:
        reader = csv.DictReader(f)
        # detect columns
        cols = reader.fieldnames or []
        # heurística: columnas comúnmente usadas
        start_col = None
        end_col = None
        for c in cols:
            lc = c.lower()
            if start_col is None and any(x in lc for x in ("start", "pw", "password")):
                start_col = c
            if end_col is None and any(x in lc for x in ("end", "endpoint", "hash")):
                end_col = c
        if start_col is None or end_col is None:
            # fallback: intentar pares de columnas
            print("[WARN] No se detectaron columnas start/endpoint automáticamente. Cabeceras:", cols)
            # try first two
            rows = list(reader)
            if len(cols) >= 2:
                start_col = cols[0]; end_col = cols[1]
                for row in rows:
                    if row.get(start_col) and row.get(end_col):
                        table[row.get(end_col).lower().strip()] = row.get(start_col)
                return table
            else:
                raise ValueError("CSV con cabeceras no reconocibles.")
        for row in reader:
            s = row.get(start_col)
            e = row.get(end_col)
            if s and e:
                table[e.lower().strip()] = s
    return table

# ---------------- Reduction variants ----------------
def R_recommended(i: int, h_bytes: bytes) -> str:
    H = int.from_bytes(h_bytes, 'big')
    idx = (H + i) % SPACE_SIZE
    return index_to_pw(idx)

def R_simple_bytes_mod(i: int, h_bytes: bytes) -> str:
    # incorpora i mezclándolo con H (determinista) y mapea bytes->letras por %26
    H = (int.from_bytes(h_bytes, 'big') + i) & ((1<<40)-1)
    b5 = H.to_bytes(5, 'big')
    return ''.join(ALPHABET[b % 26] for b in b5)

def R_try_both(i: int, h_bytes: bytes):
    return R_recommended(i, h_bytes), R_simple_bytes_mod(i, h_bytes)

# ---------------- Lookup procedure variants ----------------
def lookup_variant(H_target_bytes: bytes, table: Dict[str,str], t: int, Rfunc, verbose=False, max_print=20):
    # iterate i from t-1 down to 0
    for i in range(t-1, -1, -1):
        temp = H_target_bytes
        # apply reductions from position i to t-1
        for j in range(i, t):
            # NOTE: in build_table we used j in 1..t-1. try both j and j+1 conventions externally
            pw = Rfunc(j+1, temp)
            temp = hash_trunc40_from_pw(pw)
        endpoint_candidate = bytes_to_hex(temp)
        if endpoint_candidate.lower() in table:
            start_pw = table[endpoint_candidate.lower()]
            if verbose:
                print(f"[FOUND endpoint] i={i}, endpoint={endpoint_candidate}, start_pw={start_pw}")
            # regenerate chain and look for exact match
            P = start_pw
            steps = []
            for k in range(0, t):
                hP = hash_trunc40_from_pw(P)
                steps.append((k, P, bytes_to_hex(hP)))
                if hP == H_target_bytes:
                    if verbose:
                        print("[SUCCESS] password recovered:", P)
                        print("Regeneration steps (upto match):")
                        for s in steps[:max_print]:
                            print(s)
                    return P, {"i": i, "endpoint": endpoint_candidate, "start_pw": start_pw, "steps": steps}
                P = Rfunc(k+1, hP)
            # no match in this chain
            if verbose:
                print(f"[NO MATCH IN CHAIN] endpoint {endpoint_candidate} matched but chain didn't contain H_target (merging).")
            # continue searching other i
    return None, None

# ---------------- Brute-force utility (opcional) ----------------
def brute_force_find(H_target_bytes: bytes, stop_on_first=True):
    cnt = 0
    start = time.time()
    for idx in range(SPACE_SIZE):
        pw = index_to_pw(idx)
        cnt += 1
        if hash_trunc40_from_pw(pw) == H_target_bytes:
            elapsed = time.time() - start
            return pw, cnt, elapsed
    elapsed = time.time() - start
    return None, cnt, elapsed

# ---------------- CLI ----------------
def main():
    p = argparse.ArgumentParser()
    p.add_argument("--table", required=True)
    p.add_argument("--password", required=True)
    p.add_argument("--t", type=int, required=True)
    p.add_argument("--bruteforce", action="store_true")
    p.add_argument("--max-print", type=int, default=20)
    args = p.parse_args()

    print("Loading table:", args.table)
    table = load_table_csv(args.table)
    print("Entries in table:", len(table))

    # compute target hash
    H_target_bytes = hash_trunc40_from_pw(args.password)
    print("Password target:", args.password)
    print("Truncated hash (hex):", bytes_to_hex(H_target_bytes))

    # quick check: is the target hash present as an endpoint in the table?
    if bytes_to_hex(H_target_bytes).lower() in table:
        print("[DIRECT HIT] H_target appears as endpoint in table! start_pw =", table[bytes_to_hex(H_target_bytes).lower()])
    else:
        print("[NO DIRECT HIT] H_target not present directly as endpoint.")

    # Try recommended R first
    print("\n--- Trying recommended R (int->base26) ---")
    res, info = lookup_variant(H_target_bytes, table, args.t, R_recommended, verbose=True, max_print=args.max_print)
    if res:
        print("\n*** RECOVERED password (recommended R):", res)
        return

    # Try simple bytes%26 R variant
    print("\n--- Trying simple bytes%26 R (byte%26) ---")
    res2, info2 = lookup_variant(H_target_bytes, table, args.t, R_simple_bytes_mod, verbose=True, max_print=args.max_print)
    if res2:
        print("\n*** RECOVERED password (bytes%26 R):", res2)
        return

    print("\nNo password recovered with the two R variants tried.")

    if args.bruteforce:
        print("\n--- Running brute-force search over entire space (this may take a few seconds) ---")
        found_pw, count, elapsed = brute_force_find(H_target_bytes)
        print("Brute-force checked", count, "passwords in {:.3f}s".format(elapsed))
        if found_pw:
            print("Brute-force found password:", found_pw)
        else:
            print("Brute-force DID NOT find a password (unexpected).")

if __name__ == "__main__":
    main()
