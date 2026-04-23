#!/usr/bin/env python3
"""cryptosetup.py <challenge-dir> [--json]

Detect crypto artefacts and emit a SageMath/Python stub pre-wired for the detected shape.
Shapes: RSA (n,e,c), ECDSA (r,s pairs), lattice (matrix / vector), post-quantum (Kyber/Dilithium/Falcon),
Circom/Halo2 ZK artefacts. Missing dependencies -> print exact install cmd, never crash.
"""
import json, re, sys, os, pathlib, argparse, shutil

RSA_KEYS = re.compile(rb"(?P<name>\b(?:n|modulus|pubkey|N|e|d|p|q|phi|c|ct|ciphertext)\b)\s*[:=]\s*(?P<v>0x[0-9a-fA-F]+|\d{8,})", re.I)
ECDSA_SIG = re.compile(rb"\b(r|s)\s*[:=]\s*(0x[0-9a-fA-F]+|\d{20,})", re.I)
LATTICE_KEYS = re.compile(rb"\b(A|B|basis|lattice|HNP|nonces|signatures|LWE|CVP)\b", re.I)
PQ_HINTS = re.compile(rb"\b(Kyber|Dilithium|Falcon|ML-KEM|ML-DSA|FrodoKEM|SPHINCS|CRYSTALS)\b", re.I)
CIRCOM_EXT = {".circom", ".r1cs", ".zkey", ".vkey", ".ptau", ".sym"}
HALO2_HINTS = re.compile(rb"\b(halo2|plonk|PlonK|Groth16|bellman|arkworks|noir)\b", re.I)

def have(mod):
    try:
        __import__(mod); return True
    except ImportError:
        return False

def scan(root: pathlib.Path):
    out = {"rsa": [], "ecdsa": [], "lattice": [], "pq": [], "circom": [], "halo2": [], "pem": []}
    for p in root.rglob("*"):
        if not p.is_file() or p.stat().st_size > 5_000_000:
            continue
        if p.suffix.lower() in CIRCOM_EXT:
            out["circom"].append(str(p)); continue
        if p.suffix.lower() in {".pem", ".key", ".crt", ".pub"}:
            out["pem"].append(str(p)); continue
        try:
            data = p.read_bytes()
        except Exception:
            continue
        if RSA_KEYS.search(data):
            hits = {m.group("name").decode().lower(): m.group("v").decode()[:64]
                    for m in RSA_KEYS.finditer(data)}
            if {"n", "e"} & set(hits) or "modulus" in hits:
                out["rsa"].append({"file": str(p), "sample": hits})
        r_count = len(list(ECDSA_SIG.finditer(data)))
        if r_count >= 4 and (b"ecdsa" in data.lower() or b"secp" in data.lower()):
            out["ecdsa"].append({"file": str(p), "pairs_approx": r_count // 2})
        if LATTICE_KEYS.search(data) and p.suffix in {".py", ".sage", ".txt", ".json"}:
            out["lattice"].append(str(p))
        if PQ_HINTS.search(data):
            out["pq"].append({"file": str(p), "hint": PQ_HINTS.search(data).group(0).decode()})
        if HALO2_HINTS.search(data):
            out["halo2"].append({"file": str(p), "hint": HALO2_HINTS.search(data).group(0).decode()})
    return out

def emit_stub(shape: str, target_dir: pathlib.Path, findings: dict) -> str:
    stub = target_dir / f"solve_{shape}.py"
    if stub.exists():
        return str(stub)
    sage_available = shutil.which("sage") is not None
    if shape == "rsa":
        body = f"""#!/usr/bin/env python3
# {'Sage' if sage_available else 'Python'} RSA solver stub
from Crypto.Util.number import long_to_bytes, inverse, isPrime, GCD  # pip install pycryptodome
# from sage.all import *   # uncomment if sage
# Paste n, e, c from findings:
n = 0
e = 0x10001
c = 0
# Quick tries: fermat (p~q), smallE (cube root), wiener (small d), common-modulus (gcd), fixed-point (pow(m,e,n)==m)
# Factor via factordb: curl https://factordb.com/api?query=$n
print("[*] n bits:", n.bit_length())
print("[*] gcd(n,c):", GCD(n, c))
"""
    elif shape == "ecdsa":
        body = """#!/usr/bin/env python3
# Biased/short-nonce ECDSA — HNP via CVP (lattice)
# Uses rkm0959/Inequality_Solving_with_CVP template. Expects list of (h, r, s) tuples.
from fpylll import IntegerMatrix, LLL, BKZ, CVP  # pip install fpylll
signatures = []   # fill: [(h, r, s), ...]
n = 0             # curve order
# Typical: biased low-bits nonces -> recover d via HNP.
# See advanced-math.md#cvp-template-for-biased-nonce-ecdsa
"""
    elif shape == "lattice":
        body = """#!/usr/bin/env sage
# LLL/BKZ/CVP template. Use sage for ring arithmetic.
from sage.all import Matrix, ZZ, vector
B = Matrix(ZZ, [[1, 0], [0, 1]])  # replace
print(B.LLL())
"""
    elif shape == "pq":
        body = """#!/usr/bin/env python3
# Post-quantum KEM/sig sanity. Try known-answer test vectors + invalid-ciphertext oracle.
# Kyber/ML-KEM: pip install pycryptodome-pq / liboqs-python
# Check: (a) decapsulation-failure leak, (b) implicit rejection bypass, (c) small-secret LWE with biased noise.
"""
    elif shape == "circom":
        body = """#!/bin/bash
# Circom/ZK artefact workflow
# Decompile r1cs: snarkjs r1cs export json circuit.r1cs circuit.r1cs.json
# Extract verifier params: snarkjs zkey export verificationkey build/circuit.zkey vk.json
# Common bugs: missing <== constraint (use == instead), under-constrained signals, field-overflow.
"""
    else:
        body = "# no stub for shape=%s\n" % shape
    stub.write_text(body); stub.chmod(0o755)
    return str(stub)

def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("dir")
    ap.add_argument("--json", action="store_true")
    a = ap.parse_args()
    root = pathlib.Path(a.dir)
    if not root.is_dir():
        print(f"not a dir: {a.dir}", file=sys.stderr); sys.exit(2)

    missing = []
    for pymod, pipname in [("Crypto", "pycryptodome"), ("fpylll", "fpylll"),
                           ("sage", "apt install sagemath")]:
        if not have(pymod):
            missing.append((pymod, pipname))
    for m, cmd in missing:
        print(f"[miss] {m} — install: {cmd}", file=sys.stderr)

    f = scan(root)
    stubs = []
    if f["rsa"]:      stubs.append(emit_stub("rsa", root, f))
    if f["ecdsa"]:    stubs.append(emit_stub("ecdsa", root, f))
    if f["lattice"]:  stubs.append(emit_stub("lattice", root, f))
    if f["pq"]:       stubs.append(emit_stub("pq", root, f))
    if f["circom"] or f["halo2"]: stubs.append(emit_stub("circom", root, f))

    report = {
        "dir": str(root),
        "findings": f,
        "stubs": stubs,
        "pointer": {
            "rsa":      "ctf-crypto/rsa-attacks.md",
            "ecdsa":    "ctf-crypto/ecc-attacks.md + advanced-math.md#cvp-template",
            "lattice":  "ctf-crypto/advanced-math.md",
            "pq":       "ctf-crypto/exotic-crypto.md",
            "circom":   "ctf-crypto/zkp-and-advanced.md",
            "halo2":    "ctf-crypto/zkp-and-advanced.md",
        },
    }
    if a.json:
        print(json.dumps(report, indent=2))
    else:
        print(json.dumps(report, indent=2))
        for s in stubs:
            print(f"[*] stub -> {s}")

if __name__ == "__main__":
    main()
