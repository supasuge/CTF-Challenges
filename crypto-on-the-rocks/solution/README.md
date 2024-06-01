# Crypto on the Rocks Solution

This challenge was inspired by [CVE-2024-31497](https://www.cert.europa.eu/publications/security-advisories/2024-039/pdf).

Within PuTTY, when utilizing the NIST P-521 elliptic curve, the implementation generates nonces with the first 9 bits set to zero. PuTTY's technique worked by making a SHA-512 hash and then reducing it mod $q$, where $q$ is the order of the group used in the ECDSA system.

## Challenge Writeup

### Introduction

This challenge involves breaking the ECDSA (Elliptic Curve Digital Signature Algorithm) using a lattice-based attack. The vulnerability arises from the biased $k$ values used during the signing process. By exploiting these biases, we can recover the private key and decrypt the encrypted flag. This writeup will provide a detailed explanation of the steps involved in solving the challenge.

### Challenge Overview

1. **Public Key Retrieval**: The challenge provides an option to retrieve the public key.
2. **Signature Generation**: The user can generate multiple ECDSA signatures.
3. **Signature Verification**: The user can verify the validity of given signatures.
4. **Encrypted Flag Retrieval**: The challenge provides an option to retrieve an encrypted flag.

The goal is to recover the private key used for signing messages by leveraging biased nonces in the ECDSA signature process. Once the private key is obtained, it can be used to derive the AES key, which is then used to decrypt the flag.

### Technical Details

#### ECDSA Signature Scheme

In ECDSA, a signature for a message $m$ is generated as follows:

1. Compute the hash of the message, $e = \text{HASH}(m)$.
2. Generate a random nonce $k$.
3. Compute the elliptic curve point $P = kG$, where $G$ is the base point of the curve.
4. The signature components are:
   - $r = x_P \mod n$, where $x_P$ is the x-coordinate of $P$
   - $s = k^{-1}(e + rd) \mod n$, where $d$ is the private key.
5. The signature is $(r, s)$.

The public key $Q$ is computed as $Q = dG$.

#### Challenge Implementation

The provided `challenge.py` script performs the ECDSA signing and encryption of the flag. The `ecdsa_sign` function generates signatures using a biased nonce $k$ where the $9$ most significant bits (MSBs) are zero. This is a common mistake with the NIST P-521 Curve as it can be easily mistaken for $512$ instead of $521$.

**Vulnerability**
```python
def get_k() -> int:
    return int.from_bytes(hashlib.sha512(os.urandom(512//8)).digest(), byteorder='big') % n

def ecdsa_sign(d: int, m: str) -> Tuple[int, int]:
    e = digest(m)
    k = get_k()
    P = k * G
    r_i = int(P.xy()[0])
    s_i = (pow(k, -1, n) * (e + r_i * d)) % n
    return (r_i, s_i)
```

### Lattice Attack

The lattice attack leverages the structure of the signature equations to recover the private key. Given several signatures $(r_i, s_i)$ for messages $m_i$:

1. Compute the hash of each message $e_i = \text{HASH}(m_i)$.
2. For each signature, express $s_i$ as:
   $$s_i = k_i^{-1}(e_i + r_i d) \mod n$$
   Rearrange to get:
   $$k_i = s_i^{-1}(e_i + r_i d) \mod n$$
3. Using the biased $k$ values, we know the MSBs are zero. This can be modeled as a hidden number problem (HNP).
4. Construct a lattice basis to solve for the private key $d$ using the Lenstra–Lenstra–Lovász (LLL) algorithm.

#### Solution Script

The `exploit.py` script performs the following steps to recover the private key and decrypt the flag:

1. **Retrieve Public Key**:
   ```python
   pub, _ = get_pub(r)
   ```

2. **Retrieve Signatures**:
   ```python
   sigs = get_sigs(n_sigs, r)
   ```

3. **Retrieve Encrypted Flag**:
   ```python
   flag = get_flag(r)
   ```

4. **Construct Partial Integers for Biased k Values**:
   ```python
   ks = PartialInteger.from_bits_be("000000000" + ("?" * 512))
   ```

5. **Set Up Arrays for Lattice Attack**:
   ```python
   for r_s, s in sigs:
       r_s_i = str(r_s).replace(",", "")
       s_i.append(int(s))
       r_i.append(int(r_s_i))
       k_i.append(ks)
       h_i.append(hashed)
   ```

6. **Perform Lattice Attack**:
   ```python
   for d_, _ in dsa_known_msb(n, h_i, r_i, s_i, k_i):
       if check_public_key(int(d_), curve, pub[0], pub[1]):
           # Private key found
           break
   ```

7. **Decrypt Flag**:
   ```python
   dec_flag = decrypt_flag(flag, hashlib.sha256(long_to_bytes(int(d_))).digest())
   ```

### Detailed Explanation of Lattice Construction

The lattice attack constructs a basis matrix $B$ such that the shortest vector corresponds to the correct solution of the HNP:

1. Construct a matrix $B$ of dimension $n1 + n2 + 1 \times n1 + n2 + 1$.
2. Populate the matrix with known values from the signature equations.
3. Apply the LLL algorithm to find the shortest vector.
4. Extract potential solutions for the private key and verify.

### Conclusion

This challenge demonstrates the practical application of lattice-based cryptanalysis to break ECDSA when nonces are biased. By carefully analyzing the signatures and constructing a suitable lattice, the private key can be recovered, allowing for the decryption of the flag. This attack underscores the importance of using strong, unbiased random values in cryptographic protocols.


### Script in use
[exploit.py](https://github.com/supaaasuge/CTF-Challenges/blob/main/crypto-on-the-rocks/solution/exploit.py)
```bash
python exploit.py 
[+] Opening connection to 172.17.0.2 on port 1337: Done
[+] Connection established with the server. [+]
[+] Public Key Received: (3109980590986919311287046533887492002477811552891909791863089310727982955200855447689228284912554348477907370491007162534350370090834859510917441206285191833, 1849341532655318689606938160662082719013085154529414983552465624971698466645605396348569232219887646346509053390109036465552085426099099404907799665353982020) [+]
[+] Total Parsed Signatures: 100 [+]
██████████╗░░█████╗░░█████╗░███████╗█
[=] ------------ Menu------------ [=]
[+] !1: Get Public Key            [+]
[+] !2: Sign a message            [+]
[+] !3: Verify a signature        [+]
[+] !4: Get the encrypted flag    [+]
[+] !5: Exit                      [+]
[=] ------------------------------[=]
██████████╗░░█████╗░░█████╗░███████╗█


>>
[+] Received Encrypted Flag: [] [+]
Encrypted Flag: 4bce8bc72f8ed73016a7fa8b3c0543e863dbb4ac382707d3f916b49450faa64c3324aed5f5052917901c35ba1b1a03f01b60a098b8965511be9b461d2d447fc3
[+] Received Encrypted Flag: 4bce8bc72f8ed73016a7fa8b3c0543e863dbb4ac382707d3f916b49450faa64c3324aed5f5052917901c35ba1b1a03f01b60a098b8965511be9b461d2d447fc3 [+]
[+] Arrays lengths
-> h_i: 100
-> r_i: 100
-> s_i: 100
-> k_i: 100
[+]
[+] Success: Correct private key found. [+]
[+] Private Key: 4382437925999591767510550313910999914971677081144417715676670125599319162854128772342173165773504391470287477162386441738612489510063693972385644281868216440 [+]
[+] AES_KEY: c10216d682898955ef6fbb64afeca03c9bb5a68b4bcaaa9ca792991371b2214c [+]
[+] Decrypted Flag: L3AK{9_b1ts_12_m0r3_th4n_3n0ugh} [+]
```

###### Sources
- https://www.chiark.greenend.org.uk/~sgtatham/putty/wishlist/vuln-p521-bias.html
- https://www.cert.europa.eu/publications/security-advisories/2024-039/pdf
- https://www.openwall.com/lists/oss-security/2024/04/15/6
- https://github.com/jvdsn/crypto-attacks
- https://github.com/advisories/GHSA-6p4c-r453-8743
