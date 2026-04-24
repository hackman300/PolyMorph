#!/usr/bin/env python3
"""
╔═══════════════════════════════════════════════════════════════╗
║  PolyMorph – Polymorphic Payload Transformation Engine        ║
║  Red Team Research Tool  ·  python + C hybrid                 ║
╚═══════════════════════════════════════════════════════════════╝

Usage:
    python3 polymorph.py [options]

    --payload <hex|file>   Input payload as hex string or path to binary
    --chain   <spec>       Comma-separated transforms, e.g.:
                             xor:0x41,rot_left:3,reverse,hex_encode
    --bad-chars <hex>      Bad bytes to avoid, e.g. 00,0a,0d
    --export  <fmt>        Output format: hex | c_array | base64 | raw
    --out     <file>       Write output to file (default: stdout)
    --analyze              Print entropy/evasion analysis only
    --fuzz    <n>          Auto-generate n random chains, rank by evasion score
    --lib     <path>       Path to polymorph_engine.so (default: ./polymorph_engine.so)

Available transforms:
    xor:<key_hex>          XOR with fixed key (e.g. xor:deadbeef)
    xor_roll:<seed>:<delta> Rolling XOR  (e.g. xor_roll:0x41:0x07)
    rot_left:<n>           Rotate bits left by n
    rot_right:<n>          Rotate bits right by n
    bit_not                Bitwise NOT of every byte
    byte_add:<n>           Add n to every byte (mod 256)
    byte_sub:<n>           Subtract n from every byte (mod 256)
    swap_pairs             Swap adjacent byte pairs
    reverse                Reverse all bytes
    nop_insert:<freq>:<byte> Insert NOP byte every freq bytes
    hex_encode             Encode as ASCII hex string
    base64:<alphabet>      Base64 with optional custom alphabet

Example chains:
    # Classic XOR stub prep
    --chain "xor:0xdeadbeef,base64"

    # Null-byte elimination + bit rotation
    --chain "byte_add:0x05,rot_left:2,hex_encode"

    # Multi-layer obfuscation
    --chain "reverse,xor_roll:0x41:0x13,bit_not,base64"
"""

import argparse
import ctypes
import json
import os
import random
import sys
from pathlib import Path
from typing import Optional

# ─── ANSI colours ─────────────────────────────────────────────────────────────
R  = "\033[91m"
G  = "\033[92m"
Y  = "\033[93m"
B  = "\033[94m"
M  = "\033[95m"
C  = "\033[96m"
W  = "\033[97m"
DIM= "\033[2m"
BLD= "\033[1m"
RST= "\033[0m"

BANNER = f"""
{M}╔══════════════════════════════════════════════════════════╗
║  {W}{BLD}PolyMorph{RST}{M}  ·  Polymorphic Payload Transformation Engine  ║
║  {DIM}Python + C hybrid  ·  Red Team Research Tool{RST}{M}            ║
╚══════════════════════════════════════════════════════════╝{RST}
"""


# ─── C Engine Binding ─────────────────────────────────────────────────────────

class PolymorphEngine:
    """ctypes wrapper around polymorph_engine.so"""

    def __init__(self, lib_path: str = "./polymorph_engine.so"):
        try:
            self._lib = ctypes.CDLL(lib_path)
        except OSError as e:
            sys.exit(f"{R}[!] Cannot load engine: {e}{RST}\n"
                     f"    Compile with: gcc -shared -fPIC -O2 -o polymorph_engine.so "
                     f"polymorph_engine.c -lm")
        self._setup_signatures()

    def _setup_signatures(self):
        L = self._lib

        L.calc_entropy.restype  = ctypes.c_double
        L.calc_entropy.argtypes = [ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t]

        L.evasion_score.restype  = ctypes.c_int
        L.evasion_score.argtypes = [ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t]

        L.byte_diversity.restype  = ctypes.c_double
        L.byte_diversity.argtypes = [ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t]

        L.count_nulls.restype  = ctypes.c_size_t
        L.count_nulls.argtypes = [ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t]

        L.most_frequent_byte.restype  = ctypes.c_uint8
        L.most_frequent_byte.argtypes = [ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t]

        L.xor_encode.restype  = None
        L.xor_encode.argtypes = [ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t,
                                  ctypes.POINTER(ctypes.c_uint8),
                                  ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t]

        L.xor_rolling_encode.restype  = None
        L.xor_rolling_encode.argtypes = [ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t,
                                          ctypes.POINTER(ctypes.c_uint8),
                                          ctypes.c_uint8, ctypes.c_uint8]

        L.bit_not.restype  = None
        L.bit_not.argtypes = [ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t,
                               ctypes.POINTER(ctypes.c_uint8)]

        L.bit_rotate_left.restype  = None
        L.bit_rotate_left.argtypes = [ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t,
                                       ctypes.POINTER(ctypes.c_uint8), ctypes.c_int]

        L.bit_rotate_right.restype  = None
        L.bit_rotate_right.argtypes = [ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t,
                                        ctypes.POINTER(ctypes.c_uint8), ctypes.c_int]

        L.byte_swap_pairs.restype  = None
        L.byte_swap_pairs.argtypes = [ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t,
                                       ctypes.POINTER(ctypes.c_uint8)]

        L.byte_add.restype  = None
        L.byte_add.argtypes = [ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t,
                                ctypes.POINTER(ctypes.c_uint8), ctypes.c_uint8]

        L.byte_sub.restype  = None
        L.byte_sub.argtypes = [ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t,
                                ctypes.POINTER(ctypes.c_uint8), ctypes.c_uint8]

        L.reverse_bytes.restype  = None
        L.reverse_bytes.argtypes = [ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t,
                                     ctypes.POINTER(ctypes.c_uint8)]

        L.insert_nops.restype  = ctypes.c_size_t
        L.insert_nops.argtypes = [ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t,
                                   ctypes.POINTER(ctypes.c_uint8),
                                   ctypes.c_size_t, ctypes.c_uint8]

        L.hex_encode.restype  = ctypes.c_size_t
        L.hex_encode.argtypes = [ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t,
                                  ctypes.c_char_p]

        L.custom_base64_encode.restype  = ctypes.c_size_t
        L.custom_base64_encode.argtypes = [ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t,
                                            ctypes.c_char_p, ctypes.c_char_p]

        L.to_c_array.restype  = ctypes.c_size_t
        L.to_c_array.argtypes = [ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t,
                                  ctypes.c_char_p, ctypes.c_size_t, ctypes.c_char_p]

        L.find_bad_chars.restype  = ctypes.c_int
        L.find_bad_chars.argtypes = [ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t,
                                      ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t,
                                      ctypes.POINTER(ctypes.c_uint8), ctypes.c_size_t]

    # ── helpers ──

    @staticmethod
    def _to_cbuf(data: bytes):
        arr = (ctypes.c_uint8 * len(data))(*data)
        return arr, len(data)

    # ── analysis ──

    def entropy(self, data: bytes) -> float:
        arr, n = self._to_cbuf(data)
        return self._lib.calc_entropy(arr, n)

    def evasion_score(self, data: bytes) -> int:
        arr, n = self._to_cbuf(data)
        return self._lib.evasion_score(arr, n)

    def diversity(self, data: bytes) -> float:
        arr, n = self._to_cbuf(data)
        return self._lib.byte_diversity(arr, n)

    def null_count(self, data: bytes) -> int:
        arr, n = self._to_cbuf(data)
        return self._lib.count_nulls(arr, n)

    def most_freq(self, data: bytes) -> int:
        arr, n = self._to_cbuf(data)
        return self._lib.most_frequent_byte(arr, n)

    def bad_char_hits(self, data: bytes, bad: bytes) -> list[int]:
        arr, n = self._to_cbuf(data)
        barr, bn = self._to_cbuf(bad)
        out = (ctypes.c_uint8 * min(len(data), 256))()
        count = self._lib.find_bad_chars(arr, n, barr, bn, out, min(len(data), 256))
        return list(out[:count])

    # ── transforms (all return bytes) ──

    def xor(self, data: bytes, key: bytes) -> bytes:
        arr, n = self._to_cbuf(data)
        karr, kn = self._to_cbuf(key)
        out = (ctypes.c_uint8 * n)()
        self._lib.xor_encode(arr, n, out, karr, kn)
        return bytes(out)

    def xor_roll(self, data: bytes, seed: int, delta: int) -> bytes:
        arr, n = self._to_cbuf(data)
        out = (ctypes.c_uint8 * n)()
        self._lib.xor_rolling_encode(arr, n, out, ctypes.c_uint8(seed), ctypes.c_uint8(delta))
        return bytes(out)

    def bit_not(self, data: bytes) -> bytes:
        arr, n = self._to_cbuf(data)
        out = (ctypes.c_uint8 * n)()
        self._lib.bit_not(arr, n, out)
        return bytes(out)

    def rot_left(self, data: bytes, n: int) -> bytes:
        arr, ln = self._to_cbuf(data)
        out = (ctypes.c_uint8 * ln)()
        self._lib.bit_rotate_left(arr, ln, out, ctypes.c_int(n))
        return bytes(out)

    def rot_right(self, data: bytes, n: int) -> bytes:
        arr, ln = self._to_cbuf(data)
        out = (ctypes.c_uint8 * ln)()
        self._lib.bit_rotate_right(arr, ln, out, ctypes.c_int(n))
        return bytes(out)

    def swap_pairs(self, data: bytes) -> bytes:
        arr, n = self._to_cbuf(data)
        out = (ctypes.c_uint8 * n)()
        self._lib.byte_swap_pairs(arr, n, out)
        return bytes(out)

    def byte_add(self, data: bytes, delta: int) -> bytes:
        arr, n = self._to_cbuf(data)
        out = (ctypes.c_uint8 * n)()
        self._lib.byte_add(arr, n, out, ctypes.c_uint8(delta))
        return bytes(out)

    def byte_sub(self, data: bytes, delta: int) -> bytes:
        arr, n = self._to_cbuf(data)
        out = (ctypes.c_uint8 * n)()
        self._lib.byte_sub(arr, n, out, ctypes.c_uint8(delta))
        return bytes(out)

    def reverse(self, data: bytes) -> bytes:
        arr, n = self._to_cbuf(data)
        out = (ctypes.c_uint8 * n)()
        self._lib.reverse_bytes(arr, n, out)
        return bytes(out)

    def nop_insert(self, data: bytes, freq: int, nop_byte: int = 0x90) -> bytes:
        arr, n = self._to_cbuf(data)
        max_out = n + (n // max(freq, 1)) + 2
        out = (ctypes.c_uint8 * max_out)()
        new_len = self._lib.insert_nops(arr, n, out, ctypes.c_size_t(freq),
                                         ctypes.c_uint8(nop_byte))
        return bytes(out[:new_len])

    def hex_encode(self, data: bytes) -> bytes:
        arr, n = self._to_cbuf(data)
        out = ctypes.create_string_buffer(n * 2 + 1)
        self._lib.hex_encode(arr, n, out)
        return out.value

    def base64(self, data: bytes, alphabet: Optional[str] = None) -> bytes:
        arr, n = self._to_cbuf(data)
        out = ctypes.create_string_buffer(((n + 2) // 3) * 4 + 1)
        ab = alphabet.encode() if alphabet else None
        self._lib.custom_base64_encode(arr, n, out, ab)
        return out.value

    def to_c_array(self, data: bytes, var_name: str = "payload") -> str:
        arr, n = self._to_cbuf(data)
        max_size = n * 6 + 512
        out = ctypes.create_string_buffer(max_size)
        self._lib.to_c_array(arr, n, out, max_size, var_name.encode())
        return out.value.decode()


# ─── Transform Pipeline ────────────────────────────────────────────────────────

class TransformPipeline:

    def __init__(self, engine: PolymorphEngine):
        self.engine = engine
        self.steps: list[tuple[str, dict]] = []

    def _parse_hex(self, s: str) -> int:
        return int(s, 16) if s.startswith("0x") else int(s, 16)

    def add(self, spec: str) -> "TransformPipeline":
        parts = spec.strip().split(":")
        name = parts[0].lower()
        args = parts[1:] if len(parts) > 1 else []
        self.steps.append((name, args))
        return self

    def parse_chain(self, chain_str: str) -> "TransformPipeline":
        for s in chain_str.split(","):
            self.add(s)
        return self

    def run(self, data: bytes) -> tuple[bytes, list[dict]]:
        """Apply all transforms and return (result, per-step stats)."""
        E   = self.engine
        cur = data
        log = []

        for name, args in self.steps:
            prev = cur
            match name:
                case "xor":
                    key = bytes.fromhex(args[0].replace("0x", ""))
                    cur = E.xor(cur, key)
                case "xor_roll":
                    seed  = self._parse_hex(args[0]) if args else 0x41
                    delta = self._parse_hex(args[1]) if len(args) > 1 else 0x07
                    cur = E.xor_roll(cur, seed, delta)
                case "bit_not":
                    cur = E.bit_not(cur)
                case "rot_left":
                    cur = E.rot_left(cur, int(args[0]) if args else 1)
                case "rot_right":
                    cur = E.rot_right(cur, int(args[0]) if args else 1)
                case "swap_pairs":
                    cur = E.swap_pairs(cur)
                case "byte_add":
                    cur = E.byte_add(cur, self._parse_hex(args[0]) if args else 5)
                case "byte_sub":
                    cur = E.byte_sub(cur, self._parse_hex(args[0]) if args else 5)
                case "reverse":
                    cur = E.reverse(cur)
                case "nop_insert":
                    freq     = int(args[0]) if args else 4
                    nop_byte = self._parse_hex(args[1]) if len(args) > 1 else 0x90
                    cur = E.nop_insert(cur, freq, nop_byte)
                case "hex_encode":
                    cur = E.hex_encode(cur)
                case "base64":
                    alpha = args[0] if args else None
                    cur = E.base64(cur, alpha)
                case _:
                    print(f"{Y}[?] Unknown transform '{name}' – skipped{RST}")
                    continue

            log.append({
                "transform" : name,
                "in_len"    : len(prev),
                "out_len"   : len(cur),
                "entropy"   : E.entropy(cur),
                "evasion"   : E.evasion_score(cur),
            })

        return cur, log


# ─── Reporting ─────────────────────────────────────────────────────────────────

def bar(val: float, width: int = 30, max_val: float = 100.0,
        fill: str = "█", empty: str = "░") -> str:
    filled = int(round(val / max_val * width))
    return fill * filled + empty * (width - filled)

def score_color(s: int) -> str:
    if s >= 75: return G
    if s >= 50: return Y
    return R

def print_analysis(engine: PolymorphEngine, data: bytes, label: str = "Payload"):
    ent  = engine.entropy(data)
    evs  = engine.evasion_score(data)
    div  = engine.diversity(data)
    nuls = engine.null_count(data)
    mfb  = engine.most_freq(data)

    sc = score_color(evs)
    print(f"\n{BLD}{C}── {label} Analysis {'─'*(46-len(label))}{RST}")
    print(f"  Size          : {len(data)} bytes")
    print(f"  Entropy       : {ent:.4f} / 8.0  {DIM}{bar(ent,30,8.0)}{RST}")
    print(f"  Byte Diversity: {div*100:.1f}%  {DIM}{bar(div*100,30)}{RST}")
    print(f"  Null bytes    : {nuls} ({nuls/max(len(data),1)*100:.1f}%)")
    print(f"  Most freq byte: 0x{mfb:02x}")
    print(f"  Evasion Score : {sc}{BLD}{evs:3d}/100{RST}  {sc}{bar(evs,30)}{RST}")

def print_step_log(log: list[dict]):
    print(f"\n{BLD}{C}── Transform Pipeline Log {'─'*37}{RST}")
    print(f"  {'Step':<16} {'In':>6} {'Out':>6}  {'Entropy':>8}  Evasion")
    print(f"  {'─'*16} {'─'*6} {'─'*6}  {'─'*8}  {'─'*27}")
    for i, step in enumerate(log, 1):
        sc = score_color(step['evasion'])
        print(f"  {i}. {step['transform']:<14} {step['in_len']:>6} {step['out_len']:>6}"
              f"  {step['entropy']:>8.4f}  "
              f"{sc}{bar(step['evasion'],20)}{RST} {sc}{step['evasion']:3d}{RST}")


# ─── Fuzzer (auto-generate ranked chains) ──────────────────────────────────────

FUZZ_POOL = [
    "xor:41", "xor:deadbeef", "xor:cafebabe",
    "xor_roll:0x41:0x07", "xor_roll:0x13:0x17",
    "bit_not", "rot_left:1", "rot_left:3", "rot_right:2", "rot_right:5",
    "byte_add:0x05", "byte_add:0x13", "byte_sub:0x07",
    "reverse", "swap_pairs",
]

def fuzz_chains(engine: PolymorphEngine, data: bytes, n: int) -> list[dict]:
    results = []
    for _ in range(n):
        depth  = random.randint(2, 5)
        chain  = random.sample(FUZZ_POOL, depth)
        chain_str = ",".join(chain)
        pipe   = TransformPipeline(engine)
        pipe.parse_chain(chain_str)
        try:
            out, _ = pipe.run(data)
            score  = engine.evasion_score(out)
            ent    = engine.entropy(out)
            results.append({"chain": chain_str, "score": score, "entropy": ent,
                             "out_len": len(out)})
        except Exception:
            pass
    results.sort(key=lambda x: x["score"], reverse=True)
    return results


# ─── Export ────────────────────────────────────────────────────────────────────

def export(engine: PolymorphEngine, data: bytes, fmt: str) -> bytes:
    match fmt:
        case "hex":
            return engine.hex_encode(data)
        case "base64":
            return engine.base64(data)
        case "c_array":
            return engine.to_c_array(data).encode()
        case "raw" | _:
            return data


# ─── CLI ───────────────────────────────────────────────────────────────────────

def parse_payload(s: str) -> bytes:
    p = Path(s)
    if p.exists():
        return p.read_bytes()
    return bytes.fromhex(s.replace(" ", "").replace("\\x", ""))

def main():
    print(BANNER)

    parser = argparse.ArgumentParser(
        description="PolyMorph – Polymorphic Payload Transformation Engine",
        add_help=True)
    parser.add_argument("--payload",   default=None,
        help="Hex string or path to binary (default: sample NOP sled)")
    parser.add_argument("--chain",     default=None,
        help="Comma-separated transform chain spec")
    parser.add_argument("--bad-chars", default=None,
        help="Bad bytes as comma-separated hex values, e.g. 00,0a,0d")
    parser.add_argument("--export",    default="hex",
        choices=["hex","c_array","base64","raw"],
        help="Output format (default: hex)")
    parser.add_argument("--out",       default=None,
        help="Write output to file (default: stdout)")
    parser.add_argument("--analyze",   action="store_true",
        help="Analyze input only, no transform")
    parser.add_argument("--fuzz",      type=int, default=0,
        help="Auto-generate N random chains and rank by evasion score")
    parser.add_argument("--lib",       default="./polymorph_engine.so",
        help="Path to polymorph_engine.so")
    args = parser.parse_args()

    # Load engine
    engine = PolymorphEngine(args.lib)
    print(f"  {G}[+] Engine loaded: {args.lib}{RST}")

    # Load payload
    if args.payload:
        payload = parse_payload(args.payload)
    else:
        # Default: textbook x86 NOP sled + INT3 for demo purposes
        payload = bytes([0x90] * 16 + [0xcc] * 4 + [0x41, 0x42, 0x43, 0x44])
        print(f"  {Y}[~] No payload specified; using demo NOP sled ({len(payload)} bytes){RST}")

    # Bad-char check on original
    if args.bad_chars:
        bad = bytes(int(x, 16) for x in args.bad_chars.split(","))
        hits = engine.bad_char_hits(payload, bad)
        if hits:
            print(f"\n  {R}[!] Bad chars found at offsets: "
                  f"{', '.join(f'0x{h:02x}' for h in hits)}{RST}")
        else:
            print(f"\n  {G}[✓] No bad characters found in input{RST}")

    # Original analysis
    print_analysis(engine, payload, "Original Payload")

    if args.analyze:
        return

    # Fuzzer mode
    if args.fuzz:
        print(f"\n{BLD}{C}── Fuzzing {args.fuzz} random chains {'─'*35}{RST}")
        results = fuzz_chains(engine, payload, args.fuzz)
        print(f"\n  {'Rank':<5} {'Score':>5} {'Entropy':>8} {'OutLen':>7}  Chain")
        print(f"  {'─'*5} {'─'*5} {'─'*8} {'─'*7}  {'─'*40}")
        for i, r in enumerate(results[:10], 1):
            sc = score_color(r["score"])
            print(f"  {i:<5} {sc}{r['score']:>5}{RST} {r['entropy']:>8.4f} "
                  f"{r['out_len']:>7}  {DIM}{r['chain']}{RST}")
        print(f"\n  {DIM}Top chain: --chain \"{results[0]['chain']}\"{RST}" if results else "")
        return

    # Transform chain
    if not args.chain:
        print(f"\n  {Y}[~] No --chain specified. Try: --chain \"xor:41,reverse\"{RST}")
        print(f"       or use --fuzz 50 to auto-discover good chains.")
        return

    pipe = TransformPipeline(engine)
    pipe.parse_chain(args.chain)
    result, log = pipe.run(payload)

    print_step_log(log)
    print_analysis(engine, result, "Transformed Payload")

    # Bad-char recheck
    if args.bad_chars:
        bad = bytes(int(x, 16) for x in args.bad_chars.split(","))
        hits = engine.bad_char_hits(result, bad)
        if hits:
            print(f"\n  {R}[!] Bad chars STILL present after transform: "
                  f"{', '.join(f'0x{h:02x}' for h in hits)}{RST}")
        else:
            print(f"\n  {G}[✓] No bad characters in transformed output{RST}")

    # Export
    out_bytes = export(engine, result, args.export)
    print(f"\n{BLD}{C}── Output ({args.export}) {'─'*44}{RST}")

    if args.out:
        mode = "wb" if args.export == "raw" else "w"
        with open(args.out, mode) as f:
            if isinstance(out_bytes, bytes):
                f.write(out_bytes if mode == "wb" else out_bytes.decode(errors="replace"))
            else:
                f.write(out_bytes)
        print(f"  {G}[+] Written to: {args.out}{RST}")
    else:
        output = out_bytes.decode(errors="replace") if isinstance(out_bytes, bytes) else out_bytes
        # Print in rows of 80
        for i in range(0, len(output), 80):
            print(f"  {output[i:i+80]}")

    print()

if __name__ == "__main__":
    main()
