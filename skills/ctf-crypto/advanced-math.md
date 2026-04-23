# CTF Crypto - Advanced Mathematical Attacks

## Table of Contents
- [Elliptic Curve Isogenies](#elliptic-curve-isogenies)
- [Pohlig-Hellman Attack (Weak ECC)](#pohlig-hellman-attack-weak-ecc)
- [LLL Algorithm for Approximate GCD](#lll-algorithm-for-approximate-gcd)
- [Coppersmith's Method (Close Private Keys)](#coppersmiths-method-close-private-keys)
- [Quaternion RSA](#quaternion-rsa)
- [Polynomial Arithmetic in GF(2)[x]](#polynomial-arithmetic-in-gf2x)
- [RSA Signing Bug](#rsa-signing-bug)
- [CVP for Biased-Nonce ECDSA / Truncated LCG / HNP](#cvp-for-biased-nonce-ecdsa--truncated-lcg--hnp)

For 2024-2026 era techniques (LACTF / Nullcon / EHAX / 404CTF / FCSC / SekaiCTF / Midnightflag), see [advanced-math-2.md](advanced-math-2.md).

---

## Elliptic Curve Isogenies

Isogeny-based crypto challenges are often **graph traversal problems in disguise**:

**Key concepts:**
- j-invariant uniquely identifies curve isomorphism class
- Curves connected by isogenies form a graph (often tree-like)
- Degree-2 isogenies: each node has ~3 neighbors (2 children + 1 parent)

**Modular polynomial approach:**
- Connected j-invariants j₁, j₂ satisfy Φ₂(j₁, j₂) = 0
- Find neighbors by computing roots of Φ₂(j, Y) in the finite field
- Much faster than computing actual isogenies

**Pathfinding in isogeny graphs:**
```python
# Height estimation via random walks to leaves
def estimate_height(j, neighbors_func, trials=100):
    min_depth = float('inf')
    for _ in range(trials):
        depth, curr = 0, j
        while True:
            nbrs = neighbors_func(curr)
            if len(nbrs) <= 1:  # leaf node
                break
            curr = random.choice(nbrs)
            depth += 1
        min_depth = min(min_depth, depth)
    return min_depth

# Find path between two nodes via LCA
def find_path(start, end):
    # Ascend from both nodes tracking heights
    # Find least common ancestor
    # Concatenate: path_up(start) + reversed(path_up(end))
```

**Complex multiplication (CM) curves:**
- Discriminant D = f² · D_K where D_K is fundamental discriminant
- Conductor f determines tree depth
- Look for special discriminants: -163, -67, -43, etc. (class number 1)

## Pohlig-Hellman Attack (Weak ECC)

For elliptic curves with smooth order (many small prime factors):

```python
from sage.all import *

# Factor curve order
E = EllipticCurve(GF(p), [a, b])
n = E.order()
factors = factor(n)

# Solve DLP in each small subgroup
partial_logs = []
for (prime, exp) in factors:
    # Compute subgroup generator
    cofactor = n // (prime ** exp)
    G_sub = cofactor * G
    P_sub = cofactor * P  # Target point

    # Solve small DLP
    d_sub = discrete_log(P_sub, G_sub, ord=prime**exp)
    partial_logs.append((d_sub, prime**exp))

# Combine with CRT
from sympy.ntheory.modular import crt
moduli = [m for (_, m) in partial_logs]
residues = [r for (r, _) in partial_logs]
private_key, _ = crt(moduli, residues)
```

## LLL Algorithm for Approximate GCD

**Pattern (Grinch's Cryptological Defense):** Server gives hints `h_i = f * p_i + n_i` where f is the flag, p_i are small primes, n_i is small noise.

**Lattice construction:**
```python
from sage.all import *

# Collect 3 hints from server
# h_i = f * p_i + n_i (noise is small)
# Construct lattice where short vector reveals primes

M = matrix(ZZ, [
    [1, 0, 0, h1],
    [0, 1, 0, h2],
    [0, 0, 1, h3],
    [0, 0, 0, -1]  # Scaling factor
])

reduced = M.LLL()
# Short vector contains p1, p2, p3
# Recover f = (h1 - n1) / p1
```

## Coppersmith's Method (Close Private Keys)

**Pattern (Duality of Key):** Two RSA key pairs with d1 ≈ d2 (small difference).

**Attack:**
```python
# From e1*d1 ≡ 1 mod φ and e2*d2 ≡ 1 mod φ:
# d2 - d1 ≡ (e1*e2)^(-1) * (e1 - e2) mod p

# Construct polynomial f(x) = (r - x) mod p where x = d2-d1
# Use Coppersmith small_roots() to find x

R.<x> = PolynomialRing(Zmod(N))
r = inverse_mod(e1*e2, N) * (e1 - e2) % N
f = r - x
roots = f.small_roots(X=2^128, beta=0.5)  # Adjust bounds
# x = d2 - d1, recover p from gcd(f(x), N)
```

## Quaternion RSA

**Pattern:** RSA encryption using Hamilton quaternion algebra over Z/nZ. The plaintext is embedded into quaternion components that are linear combinations of m, p, q, then the quaternion matrix is raised to power e mod n.

**Key structure:**
```python
# Quaternion q = a0 + a1*i + a2*j + a3*k
# Components are linear in m, p, q:
a0 = m
a1 = m + α1*p + β1*q  # e.g., m + 3p + 7q
a2 = m + α2*p + β2*q  # e.g., m + 11p + 13q
a3 = m + α3*p + β3*q  # e.g., m + 17p + 19q

# 4x4 matrix representation:
# Row 0: [a0, -a1, -a2, -a3]
# Row 1: [a1,  a0, -a3,  a2]
# Row 2: [a2,  a3,  a0, -a1]
# Row 3: [a3, -a2,  a1,  a0]

# Ciphertext = first row of matrix^e mod n
```

**Critical property:** For quaternion `q = s + v` (scalar + vector), `q^k = s_k + t_k*v` — the vector part stays **proportional** under exponentiation. This means the ratios of imaginary components are preserved:

`c1 : c2 : c3 = a1 : a2 : a3 (mod n)`

**Factoring n (the attack):**

```python
import math

# Extract quaternion components from ciphertext row [ct0, ct1, ct2, ct3]
# Row 0 = [c0, -c1, -c2, -c3], so negate last 3:
c0, c1, c2, c3 = ct[0], (-ct[1]) % n, (-ct[2]) % n, (-ct[3]) % n

# From ratio preservation: c1*a2 = c2*a1 (mod n), c1*a3 = c3*a1 (mod n)
# Substituting a_i = m + αi*p + βi*q and eliminating m between two equations:
# Result: A*p + B*q ≡ 0 (mod n=pq) => q|A, p|B

# For components a1=m+α1p+β1q, a2=m+α2p+β2q, a3=m+α3p+β3q:
# Eliminate m from (c1*a2=c2*a1) and (c1*a3=c3*a1):
A = (-(α1*c1 - α2*c2)*(c1-c3) + (α1*c1 - α3*c3)*(c1-c2)) % n
B = (-(β1*c1 - β2*c2)*(c1-c3) + (β1*c1 - β3*c3)*(c1-c2)) % n

# More concretely for coefficients [3,7], [11,13], [17,19]:
A = (-(11*c1-3*c2)*(c1-c3) + (17*c1-3*c3)*(c1-c2)) % n
B = (-(13*c1-7*c2)*(c1-c3) + (19*c1-7*c3)*(c1-c2)) % n

q_factor = math.gcd(A, n)  # gives q
p_factor = math.gcd(B, n)  # gives p
```

**Decryption after factoring:**

Over F_p, the quaternion algebra H_p ≅ M_2(F_p) (Wedderburn theorem), so the quaternion's multiplicative order divides p²-1. Decrypt using:

```python
# Group order for quaternions over F_p divides p²-1
d_p = pow(e, -1, p**2 - 1)
d_q = pow(e, -1, q**2 - 1)

# Decrypt mod p and mod q separately, then CRT
enc_mod_p = [[x % p for x in row] for row in enc_matrix]
enc_mod_q = [[x % q for x in row] for row in enc_matrix]
dec_p = matrix_pow(enc_mod_p, d_p, p)
dec_q = matrix_pow(enc_mod_q, d_q, q)

# CRT combine: dec_matrix[0][0] = m (the flag)
m = CRT(dec_p[0][0], dec_q[0][0], p, q)
flag = long_to_bytes(m)
```

**Why it works:** The "reduced dimension" is that 4D quaternion exponentiation reduces to a 2D recurrence (scalar + magnitude of vector), and the direction of the vector part is invariant. This leaks the ratio a1:a2:a3 directly from the ciphertext, enabling factorization.

**References:** SECCON CTF 2023 "RSA 4.0", 0xL4ugh CTF "Reduced Dimension"

---

## Polynomial Arithmetic in GF(2)[x]

**Key operations for CTF crypto:**
```python
def poly_add(a, b):
    """Addition in GF(2)[x] = XOR of coefficient integers."""
    return a ^ b

def poly_mul(a, b):
    """Carry-less multiplication in GF(2)[x]."""
    result = 0
    while b:
        if b & 1:
            result ^= a
        a <<= 1
        b >>= 1
    return result

def poly_divmod(a, b):
    """Division with remainder in GF(2)[x]."""
    if b == 0:
        raise ZeroDivisionError
    deg_a, deg_b = a.bit_length() - 1, b.bit_length() - 1
    q = 0
    while deg_a >= deg_b and a:
        shift = deg_a - deg_b
        q ^= (1 << shift)
        a ^= (b << shift)
        deg_a = a.bit_length() - 1
    return q, a  # quotient, remainder
```

**Applications:** CRT in GF(2)[x] for recovering secrets from polynomial remainders, Reed-Solomon-like error correction.

---

## RSA Signing Bug

**Vulnerability:** Using wrong exponent for signing
- Correct: `sign = m^d mod n` (private exponent)
- Bug: `sign = m^e mod n` (public exponent)

**Exploitation:**
```python
# If signature is m^e mod n, we can "encrypt" to verify
# and compute e-th root to forge signatures
from sympy import integer_nthroot

# For small e (e.g., 3), take e-th root if m^e < n
forged_sig, exact = integer_nthroot(message, e)
if exact:
    print(f"Forged signature: {forged_sig}")
```

---

## CVP for Biased-Nonce ECDSA / Truncated LCG / HNP

**Pattern (Hidden Number Problem):** You have many equations of the form `k_i ≡ a_i * x + b_i (mod q)` where `k_i` is an unknown nonce **with some high or low bits known or biased**. Goal: recover the secret `x`.

Applies to:
- ECDSA with partial-nonce leak (top/bottom bits known from side-channel)
- Truncated LCG (seen low/mid bits of state, each state relates linearly to seed)
- DSA with constant nonce prefix

**Lattice construction (Babai's nearest plane via fpylll):**
```python
from fpylll import IntegerMatrix, CVP, LLL

# N equations: k_i = a_i * x + b_i (mod q), where |k_i| <= K (bias bound)
# Build basis B and target t so that CVP(B, t) recovers x

n = len(a_list)
B = IntegerMatrix(n + 2, n + 2)
for i in range(n):
    B[i, i] = q
B[n, n] = 1
B[n + 1, n + 1] = K                 # bound term (so short vector reveals x)
for i in range(n):
    B[n, i] = a_list[i]
    B[n + 1, i] = b_list[i]

B = LLL.reduction(B)
target = tuple([0] * n + [0, K])    # we want the "centered" combination
closest = CVP.babai(B, target)
# Read x from the reduced basis — typically closest[-2] or a small post-processing step
```

**Canonical reference:** [rkm0959/Inequality_Solving_with_CVP](https://github.com/rkm0959/Inequality_Solving_with_CVP) — this repo is the go-to template; it reframes biased-nonce ECDSA, truncated LCG, and bounded HNP into a single inequality-solving CVP problem.

**Spot the pattern:** any challenge with many linear equations mod q + bounded error → CVP via lattice. Don't try to Gaussian-eliminate; the "error" is what makes LLL/Babai necessary.

---

