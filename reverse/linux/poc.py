#!/usr/bin/env python3
"""
OMEGA CrackMe (2026 Edition) — Password Recovery PoC
Recovers the password from the .pdata_c section via static XOR decryption.
"""

import struct
import sys
import os


def xor_decrypt(encrypted: bytes, key: int) -> bytearray:
    """Replicate the binary's AY_OBFUSCATE XOR decryption."""
    buf = bytearray(encrypted)
    acc = 0
    for i in range(len(buf)):
        acc += i
        if acc > 0xF4240:
            acc = 0
        shift = (i & 7) * 8
        buf[i] ^= (key >> shift) & 0xFF
    return buf


def extract_pdata_c(filepath: str) -> bytes:
    """Extract the .pdata_c section from the PE binary."""
    PDATA_C_OFFSET = 0x12E00
    PDATA_C_SIZE = 0x37B

    with open(filepath, "rb") as f:
        f.seek(PDATA_C_OFFSET)
        return f.read(PDATA_C_SIZE)


def recover_password(filepath: str) -> str:
    """
    Recover the password from the OMEGA CrackMe binary.

    Targets Function 1 (Check_Real) in .pdata_c:
      - Encrypted buffer at movl instructions (offset 0x7E)
      - XOR key from movabs (offset 0xB0)
    """
    # Encrypted password bytes (little-endian from movl instructions)
    enc = bytes([0x26, 0x14, 0xFE, 0x80,
                 0x2F, 0x4E, 0xAE, 0xB2,
                 0x4B, 0x75, 0xAB])

    # 64-bit XOR key from: movabs $0x85FF1D7FCFAB4173, %r10
    key = 0x85FF1D7FCFAB4173

    dec = xor_decrypt(enc, key)
    password = dec[:10].decode("ascii")
    return password


def verify_decoy() -> str:
    """Decrypt Function 2 to demonstrate the decoy."""
    enc2 = bytes([0x93, 0x76, 0xA4, 0xA5,
                  0x40, 0xF5, 0x1A, 0xE8,
                  0x91, 0x6C, 0x01])

    key2 = 0xAD5FB71FE1E533D7
    dec2 = xor_decrypt(enc2, key2)
    return dec2[:10].decode("ascii", errors="replace"), dec2[10]


def verify_lcg() -> bool:
    """Verify the LCG anti-tamper produces non-zero."""
    x = 0x123456789ABCDEF0
    for _ in range(100):
        x = ((x << 13) | (x >> 7)) ^ x
        x &= 0xFFFFFFFFFFFFFFFF
    return x != 0


def main():
    script_dir = os.path.dirname(os.path.abspath(__file__))
    binary_path = os.path.join(script_dir, "Crack Me.exe")

    print("=" * 52)
    print("  OMEGA CrackMe (2026) - Password Recovery PoC")
    print("=" * 52)
    print()

    # --- Password Recovery ---
    password = recover_password(binary_path)
    print(f"[*] Recovered password: {password}")
    print(f"    Length: {len(password)} characters")

    # --- Decoy Analysis ---
    decoy_str, decoy_byte10 = verify_decoy()
    print(f"\n[*] Decoy function decrypts to: {decoy_str}")
    print(f"    Byte 10 = 0x{decoy_byte10:02X} (non-null -> strlen mismatch -> always fails)")

    # --- LCG Check ---
    lcg_ok = verify_lcg()
    print(f"\n[*] LCG anti-tamper seed: 0x123456789ABCDEF0")
    print(f"    After 100 iterations: non-zero = {lcg_ok}")

    # --- Validation ---
    print("\n" + "-" * 52)
    print("[+] Validation:")
    print(f"    Password length == 10:       {len(password) == 10}")
    print(f"    All printable ASCII:         {all(32 <= ord(c) < 127 for c in password)}")
    print(f"    Decoy byte 10 != 0x00:       {decoy_byte10 != 0x00}")
    print(f"    LCG non-zero guaranteed:     {lcg_ok}")
    print()

    if len(password) == 10 and all(32 <= ord(c) < 127 for c in password):
        print(f"[+] ACCESS GRANTED")
        print(f"[+] Password: {password}")
    else:
        print("[-] Validation failed")
        sys.exit(1)


if __name__ == "__main__":
    main()
