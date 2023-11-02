# encrypt.py
import sys
from Crypto.Cipher import DES
from Crypto.Util.Padding import pad
from edes import edes_encrypt, generate_sboxes

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
        sboxes = generate_sboxes(password)
        ciphertext = edes_encrypt(password, plaintext, sboxes)

    sys.stdout.write(ciphertext.hex() + "\n")

if __name__ == "__main__":
    main()