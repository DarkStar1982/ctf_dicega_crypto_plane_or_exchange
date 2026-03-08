# CTF Solutions

---

## DiceCTF — protocol.py (2026-03-07)

**Flag**: `dice{plane_or_planar_my_w0rds_4r3_411_knotted_up}`

**Category**: Cryptography

**Files**: `cybersecurity/dice_ctf/protocol.py`, `public.txt`, `challenge.txt`

### Protocol summary

Diffie-Hellman analogue over permutation pairs representing braids:
- Public info: permutation pair size 12
- Alice private: size 15 → Alice pubkey: size 27
- Bob private: size 18 → Bob pubkey: size 30
- Public key = `scramble(connect(pub_info, priv), 1000)`
- Shared secret = `sha256(str(normalize(calculate(connect(my_priv, their_pub)))))`
- `calculate(point)`: builds matrix `M[i][j] = t^{-winding[i][j]}`, returns `det(M) × (1-t)^{1-n}` — an Alexander polynomial variant
- `scramble` implements Reidemeister-like moves that preserve `calculate` (intended security property)

### Vulnerability

`calculate` is **multiplicative under `connect`**:

```
calculate(connect(a, b)) = calculate(a) × calculate(b)
```

Verified: `calc(connect(pub_info, pub_info)) = calc(pub_info)²`

This makes the scheme abelian. Polynomial multiplication commutes, so Eve computes:

```
shared_secret_poly = calc(alice_pub) × calc(bob_pub) / calc(pub_info)
                   = calc(alice_priv) × calc(bob_pub)
```

Root cause: the Alexander polynomial is designed to be multiplicative under braid concatenation (a feature in knot theory, fatal in cryptography).

### Solution steps

1. **Compute `calc(pub_info)`** via sympy bareiss on 12×12 matrix (fast).
   Result: `t^6 - 5t^5 + 13t^4 - 17t^3 + 13t^2 - 5t + 1`

2. **Compute `calc(alice_pub)`** via sympy bareiss on 27×27 matrix (slow but tractable).
   Result: palindromic degree-14 polynomial.

3. **Recover `calc(alice_priv)`** by exact polynomial division:
   `calc(alice_priv) = calc(alice_pub) / calc(pub_info)`
   (Remainder = 0 confirms multiplicativity.)

4. **Compute `calc(bob_pub)`** (30×30 — sympy bareiss too slow). Trick:
   - Winding numbers range [-1, 5]. Multiply all entries by `t^5` → integer polynomial matrix
   - `det(M') = det(M) × t^{5×30}`, all entries `t^{5-winding} ∈ {t^0 … t^6}`
   - Run Bareiss on polynomial matrix (fast): `det(M')` = degree-138 polynomial
   - Verify `(1-t)^{29}` divides `det(M')` exactly
   - `calc_raw = det(M') / ((1-t)^{29} × t^{150})`
   - `normalize`: shift minimum power of t to 0 → degree-14 palindromic polynomial
   - Result: `2t^14 - 19t^13 + 84t^12 - 226t^11 + 405t^10 - 523t^9 + 540t^8 - 527t^7 + 540t^6 - 523t^5 + 405t^4 - 226t^3 + 84t^2 - 19t + 2`

5. **Compute shared secret**:
   ```python
   shared_poly = calc_alice_priv * calc_bob_pub
   shared_hex  = sha256(str(shared_poly).encode()).hexdigest()
   plaintext   = XOR(ciphertext, keystream(shared_hex))
   ```

### Key technical notes

- `normalize()` in the protocol: finds minimum power of t, multiplies by t^{-min_exp}, flips sign if constant term negative. The raw `calculate` output is a Laurent polynomial; normalize makes it a proper polynomial.
- All `calculate` outputs for valid points are palindromic polynomials (Alexander polynomial property).
- For the sympy symbolic det on large matrices, the denominator-clearing trick (multiply by t^k) converts a rational-function matrix into a polynomial matrix, making Bareiss tractable.
- `(1-t)^{n-1}` always divides `det(M')` for valid braid-like points. This is the topological content.

### Lessons

| Lesson | Detail |
|--------|--------|
| DH requires non-abelian hardness | Any invariant that is multiplicative under the group operation is immediately broken by Eve |
| Alexander polynomial is wrong for crypto | It satisfies `Δ(β₁β₂) = Δ(β₁)·Δ(β₂)` — well-known, fatal here |
| Large polynomial det trick | Clear denominators by multiplying entries by t^k → integer polynomial matrix → fast Bareiss |
| Palindromic polynomial = sanity check | All valid `calculate()` outputs are palindromic. Useful for verifying intermediate results |
