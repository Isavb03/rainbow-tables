#!/usr/bin/env python3
"""
benchmark_hash.py

Mide el rendimiento de SHA-256 truncado (por defecto a 40 bits = 5 bytes).
Genera mensajes aleatorios y calcula hashlib.sha256(msg).digest()[:trunc_bytes].

Salida principal:
  - hashes/sec estimado
  - número total de hashes ejecutados
  - tiempo total medido

Uso:
  python3 benchmark_hash.py --target-secs 2.0 --trunc-bytes 5 --msg-len 32

Este script intenta ejecutar suficientes hashes para cubrir al menos --target-secs segundos,
dividiendo el trabajo en batches para medir con precisión.
"""

import argparse
import time
import hashlib
import os
import platform
import sys
import multiprocessing

def hash_and_trunc(data: bytes, trunc_bytes: int) -> bytes:
    return hashlib.sha256(data).digest()[:trunc_bytes]

def run_benchmark(target_secs: float = 2.0, trunc_bytes: int = 5, batch_size: int = 10000,
                  max_batches: int = 100000, msg_len: int = 32):
    total_hashes = 0
    start_time = time.perf_counter()

    # Warm-up (short)
    warmup = min(1000, batch_size)
    for _ in range(warmup):
        data = os.urandom(msg_len)
        _ = hash_and_trunc(data, trunc_bytes)

    # Timed batches
    for batch_idx in range(int(max_batches)):
        for _ in range(batch_size):
            data = os.urandom(msg_len)
            _ = hash_and_trunc(data, trunc_bytes)
        total_hashes += batch_size
        elapsed = time.perf_counter() - start_time
        if elapsed >= target_secs:
            break

    end_time = time.perf_counter()
    total_time = end_time - start_time
    hashes_per_sec = total_hashes / total_time if total_time > 0 else float('inf')
    return {
        "total_hashes": total_hashes,
        "total_time": total_time,
        "hashes_per_sec": hashes_per_sec,
        "trunc_bytes": trunc_bytes,
        "msg_len": msg_len,
        "batch_size": batch_size,
        "batches_done": batch_idx + 1,
    }

def main():
    parser = argparse.ArgumentParser(description="Benchmark SHA-256 + truncado (medir hashes/sec).")
    parser.add_argument("--target-secs", type=float, default=2.0,
                        help="Duración objetivo del benchmark en segundos (por defecto 2.0s).")
    parser.add_argument("--trunc-bytes", type=int, default=5,
                        help="Número de bytes de truncado del digest (por defecto 5 -> 40 bits).")
    parser.add_argument("--batch-size", type=int, default=10000,
                        help="Número de hashes por batch (por defecto 10000).")
    parser.add_argument("--max-batches", type=int, default=100000,
                        help="Número máximo de batches para evitar loops infinitos.")
    parser.add_argument("--msg-len", type=int, default=32,
                        help="Longitud en bytes de cada mensaje aleatorio (por defecto 32).")

    args = parser.parse_args()

    meta = {
        "python": sys.version.replace('\n', ' '),
        "platform": platform.platform(),
        "cpu_count": multiprocessing.cpu_count(),
    }
    print("=== benchmark_hash.py ===")
    print("Entorno:", meta)
    print("Parámetros: target_secs={target_secs}, trunc_bytes={trunc_bytes}, batch_size={batch_size}, msg_len={msg_len}".format(
        target_secs=args.target_secs, trunc_bytes=args.trunc_bytes, batch_size=args.batch_size, msg_len=args.msg_len
    ))
    print("Realizando benchmark... (esto puede tardar unos segundos)")

    results = run_benchmark(target_secs=args.target_secs, trunc_bytes=args.trunc_bytes,
                            batch_size=args.batch_size, max_batches=args.max_batches, msg_len=args.msg_len)

    print("\n=== Resultados ===")
    print("Total hashes:", results["total_hashes"])
    print("Tiempo total (s): {:.6f}".format(results["total_time"]))
    print("Hashes / s: {:.2f}".format(results["hashes_per_sec"]))
    print("Truncado (bytes):", results["trunc_bytes"])
    print("Mensaje (bytes):", results["msg_len"])
    print("Batches ejecutados:", results["batches_done"])
    print("====================")

if __name__ == '__main__':
    main()
