from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.backends import default_backend

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import dsa , ec, rsa, padding
import time
import os
import builtins

## write results to results.txt
# Simple logger: append each printed line to results.txt while still printing to console
_builtin_print = builtins.print
RESULTS_PATH = 'results.txt'
# truncate previous results so file is empty at program start
try:
    with open(RESULTS_PATH, 'w', encoding='utf-8'):
        pass
except Exception:
    pass
#

def print(*args, sep=' ', end='\n', file=None, flush=False):
    s = sep.join(str(a) for a in args) + end
    try:
        with open(RESULTS_PATH, 'a', encoding='utf-8') as f:
            f.write(s)
    except Exception:
        pass
    _builtin_print(*args, sep=sep, end=end, file=file, flush=flush)

## code for benchmarking

# AES (multiple key sizes)
for key_bits in (128, 192, 256):
    print(f"AES with {key_bits}-bit key")
    print()
    average = 0
    average2 = 0
    run = 0
    # generate random key
    key_bytes = os.urandom(key_bits // 8)

    # AES key sizes:
    # - 128 bits (16 bytes)
    # - 192 bits (24 bytes)
    # - 256 bits (32 bytes)

    while run < 11:
        aes_cipher = Cipher(algorithms.AES(key_bytes),
                            modes.CBC(bytearray(16)),
                            backend=default_backend())
        aes_encryptor = aes_cipher.encryptor()
        aes_decryptor = aes_cipher.decryptor()

        start = time.perf_counter_ns()
        # use a 10 KiB random plaintext
        plaintext_bytes = os.urandom(10 * 1024)

        ciphertext_bytes = aes_encryptor.update(plaintext_bytes) + aes_encryptor.finalize()
        ciphertext = ciphertext_bytes.hex()
        end = time.perf_counter_ns()

        start2 = time.perf_counter_ns()
        ciphertext_hex = ciphertext
        ciphertext_bytes = bytes.fromhex(ciphertext_hex)

        plaintext_bytes_2 = aes_decryptor.update(ciphertext_bytes) + aes_decryptor.finalize()
        # verify if it matches
        decrypt_match = (plaintext_bytes_2 == plaintext_bytes)
        end2 = time.perf_counter_ns()
        if run == 0:
            run += 1
            continue

        print("time taken (encrypt):" , (end-start)/1e6 , "ms")
        print("time taken (decrypt):" , (end2-start2)/1e6 , "ms")
        print(" decrypt matches original:", decrypt_match)
        average += (end-start)/1e6
        average2 += (end2-start2)/1e6
        run += 1
    print("Average (encrypt):" , (average/10) , "ms")
    print("Average (decrypt):" , (average2/10) , "ms")
    print()
print()


# ChaCha20
print("ChaCha20")
print()
average = 0
average2 = 0
run = 0
# ChaCha20 key/nonce sizes:
# - key: 256 bits (32 bytes)
# - nonce: 128 bits (16 bytes)

key_bytes = os.urandom(32)
nonce_bytes = os.urandom(16)

while run < 11:
    chacha_cipher = Cipher(algorithms.ChaCha20(key_bytes, nonce_bytes),
                           mode=None,
                           backend=default_backend())
    chacha_encryptor = chacha_cipher.encryptor()
    chacha_decryptor = chacha_cipher.decryptor()

    start = time.perf_counter_ns()
    # use 10 KiB random plaintext
    plaintext_bytes = os.urandom(10 * 1024)

    ciphertext_bytes = chacha_encryptor.update(plaintext_bytes)
    ciphertext = ciphertext_bytes.hex()
    end = time.perf_counter_ns()

    start2 = time.perf_counter_ns()
    ciphertext_bytes = bytes.fromhex(ciphertext)
    plaintext_bytes_2 = chacha_decryptor.update(ciphertext_bytes)
    decrypt_match = (plaintext_bytes_2 == plaintext_bytes)
    end2 = time.perf_counter_ns()
    if run == 0:
        run += 1
        continue

    print("time taken (encrypt): " , (end-start)/1e6 , "ms")
    print("time taken (decrypt): " , (end2-start2)/1e6 , "ms")
    print(" decrypt matches original:", decrypt_match)
    average += (end-start)/1e6
    average2 += (end2-start2)/1e6
    run += 1
print("Average (encrypt): " , (average/10) , "ms")
print("Average (decrypt): " , (average2/10) , "ms")
print()


# RSA (encrypting/decrypting) - multiple key sizes
for rsa_size in (1024, 2048, 3072, 4096):
    print(f"RSA encrypt/decrypt with {rsa_size}-bit key")
    print()
    average = 0
    average2 = 0
    run = 0
    private_key_rsa = rsa.generate_private_key(
        public_exponent=65537,
        key_size=rsa_size
    )
    public_key_rsa = private_key_rsa.public_key()

    short_plaintext = os.urandom(50)  # small plaintext suitable for RSA-OAEP

    while run < 11:
        start = time.perf_counter_ns()
        short_ciphertext = public_key_rsa.encrypt(
            short_plaintext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        end = time.perf_counter_ns()

        start2 = time.perf_counter_ns()
        short_plaintext_2 = private_key_rsa.decrypt(
            short_ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )
        end2 = time.perf_counter_ns()
        if run == 0:
            run += 1
            continue

        print("time taken (encrypt):" , (end-start)/1e6 , "ms")
        print("time taken (decrypt):" , (end2-start2)/1e6 , "ms")
        average += (end-start)/1e6
        average2 += (end2-start2)/1e6
        run += 1
    print("Average (encrypt):" , (average/10) , "ms")
    print("Average (decrypt):" , (average2/10) , "ms")
    print()
print()

# RSA (signing/verifying) - multiple key sizes
for rsa_size in (1024, 2048, 3072, 4096):
    print(f"RSA sign/verify with {rsa_size}-bit key")
    print()
    average = 0
    average2 = 0
    run = 0
    private_key_rsa_sign = rsa.generate_private_key(
        public_exponent=65537,
        key_size=rsa_size
    )
    public_key_rsa_sign = private_key_rsa_sign.public_key()

    message = os.urandom(10240)

    while run < 11:
        start = time.perf_counter_ns()
        signature = private_key_rsa_sign.sign(
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        end = time.perf_counter_ns()

        start2 = time.perf_counter_ns()
        # will raise if verification fails
        public_key_rsa_sign.verify(
            signature,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        end2 = time.perf_counter_ns()
        if run == 0:
            run += 1
            continue

        print("time taken (sign):" , (end-start)/1e6 , "ms")
        print("time taken (verify):" , (end2-start2)/1e6 , "ms")
        average += (end-start)/1e6
        average2 += (end2-start2)/1e6
        run += 1
    print("Average (sign):" , (average/10) , "ms")
    print("Average (verify):" , (average2/10) , "ms")
    print()
print()

# DSA (signing/verifying) - multiple key sizes
for dsa_size in (1024, 2048, 3072, 4096):
    print(f"DSA sign/verify with {dsa_size}-bit key")
    print()
    average = 0
    average2 = 0
    run = 0
    private_key = dsa.generate_private_key(
        key_size=dsa_size
    )
    public_key = private_key.public_key()

    message = os.urandom(10240)

    while run < 11:
        start = time.perf_counter_ns()
        signature = private_key.sign(
            message,
            hashes.SHA256()
        )
        end = time.perf_counter_ns()

        start2 = time.perf_counter_ns()
        public_key.verify(
            signature,
            message,
            hashes.SHA256()
        )
        end2 = time.perf_counter_ns()
        if run == 0:
            run += 1
            continue

        print("time taken (sign):" , (end-start)/1e6 , "ms")
        print("time taken (verify):" , (end2-start2)/1e6 , "ms")
        average += (end-start)/1e6
        average2 += (end2-start2)/1e6
        run += 1
    print("Average (sign):" , (average/10) , "ms")
    print("Average (verify):" , (average2/10) , "ms")
    print()
print()

# ECC (signing/verifying) - multiple curves / key sizes
for curve in (ec.SECP192R1(), ec.SECP224R1(), ec.SECP256R1(), ec.SECP384R1(), ec.SECP521R1()):
    print(f"ECC sign/verify with curve {curve.name}")
    print()
    average = 0
    average2 = 0
    run = 0
    private_key = ec.generate_private_key(
        curve
    )
    public_key = private_key.public_key()

    message = os.urandom(10240)

    while run < 11:
        start = time.perf_counter_ns()
        signature = private_key.sign(
            message,
            ec.ECDSA(hashes.SHA256())
        )
        end = time.perf_counter_ns()

        start2 = time.perf_counter_ns()
        public_key.verify(
            signature,
            message,
            ec.ECDSA(hashes.SHA256())
        )
        end2 = time.perf_counter_ns()
        if run == 0:
            run += 1
            continue

        print("time taken (sign):" , (end-start)/1e6 , "ms")
        print("time taken (verify):" , (end2-start2)/1e6 , "ms")
        average += (end-start)/1e6
        average2 += (end2-start2)/1e6
        run += 1
    print("Average (sign):" , (average/10) , "ms")
    print("Average (verify):" , (average2/10) , "ms")   
    print()

# ---------------- Key pair generation timings ----------------
print()
print("Key pair generation timings")
print()

# RSA key generation timings
for rsa_size in (1024, 2048, 3072, 4096):
    print(f"RSA key generation for {rsa_size}-bit key")
    average = 0
    run = 0
    while run < 11:
        start = time.perf_counter_ns()
        _ = rsa.generate_private_key(public_exponent=65537, key_size=rsa_size)
        end = time.perf_counter_ns()
        elapsed_ms = (end - start) / 1e6
        if run == 0:
            run += 1
            continue
        print(" time taken (gen):", elapsed_ms, "ms")
        average += elapsed_ms
        run += 1
    print("Average (gen):", (average/10), "ms")
    print()

# DSA key generation timings
for dsa_size in (1024, 2048, 3072, 4096):
    print(f"DSA key generation for {dsa_size}-bit key")
    average = 0
    run = 0
    while run < 11:
        start = time.perf_counter_ns()
        _ = dsa.generate_private_key(key_size=dsa_size)
        end = time.perf_counter_ns()
        elapsed_ms = (end - start) / 1e6
        if run == 0:
            run += 1
            continue
        print(" time taken (gen):", elapsed_ms, "ms")
        average += elapsed_ms
        run += 1
    print("Average (gen):", (average/10), "ms")
    print()

# ECC key generation timings
for curve in (ec.SECP192R1(), ec.SECP224R1(), ec.SECP256R1(), ec.SECP384R1(), ec.SECP521R1()):
    print(f"ECC key generation for curve {curve.name}")
    average = 0
    run = 0
    while run < 11:
        start = time.perf_counter_ns()
        _ = ec.generate_private_key(curve)
        end = time.perf_counter_ns()
        elapsed_ms = (end - start) / 1e6
        if run == 0:
            run += 1
            continue
        print(" time taken (gen):", elapsed_ms, "ms")
        average += elapsed_ms
        run += 1
    print("Average (gen):", (average/10), "ms")
    print()
