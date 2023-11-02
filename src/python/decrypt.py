# decrypt.py
import sys
from Crypto.Cipher import DES
from Crypto.Util.Padding import unpad
from edes import edes_decrypt

def decrypt_des(key, ciphertext):
    cipher = DES.new(key, DES.MODE_ECB)
    return unpad(cipher.decrypt(ciphertext), 8)

def main():
    if len(sys.argv) != 3:
        print('Usage: python3 decrypt.py "password" <mode>\nExample: python3 decrypt.py "rkDAHX6yG9TzwLuL7HLkuMUdXrVN6q92" --e-des\n')
        sys.exit(1)

    password = sys.argv[1]
    mode = sys.argv[2].lower()
    print("> ", end="", flush=True)
    # Read the input as a hexadecimal string
    hex_ciphertext = sys.stdin.readline().strip()
    ciphertext = bytes.fromhex(hex_ciphertext)

    if mode == "--des":
        plaintext = decrypt_des(password[:8].encode(), ciphertext)
    else:
        plaintext = edes_decrypt(password, ciphertext)

    print("Decrypted: ", end="", flush=True)
    sys.stdout.write(plaintext.decode())
    print("", flush=True)

if __name__ == "__main__":
    main()
