# encrypt_application.py
import sys
import base64
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad
from enhanced_des import edes_encrypt

def encrypt_des(key, plaintext):
    cipher = DES.new(key, DES.MODE_ECB)
    return cipher.encrypt(pad(plaintext, 8))

def main():
    if len(sys.argv) != 3:
        print('Usage: python3 encrypt.py "password" <mode>\nExample: python3 encrypt.py "rkDAHX6yG9TzwLuL7HLkuMUdXrVN6q92" --e-des\n')
        sys.exit(1)

    password = sys.argv[1]
    mode = sys.argv[2].lower()
    print("> ", end="", flush=True)
    plaintext = sys.stdin.readline().strip().encode()

    if mode == "--des":
        ciphertext = encrypt_des(password[:8].encode(), plaintext)
    else:
        ciphertext = edes_encrypt(password, plaintext)

    sys.stdout.write(base64.b64encode(ciphertext).decode())

if __name__ == "__main__":
    main()