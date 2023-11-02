# decrypt_application.py
import sys
import base64
from Crypto.Cipher import DES
from Crypto.Util.Padding import unpad
from enhanced_des import edes_decrypt

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
    b64_ciphertext = sys.stdin.readline().strip()
    ciphertext = base64.b64decode(b64_ciphertext)

    if mode == "--des":
        plaintext = decrypt_des(password[:8].encode(), ciphertext)
    else:
        plaintext = edes_decrypt(password, ciphertext)

    print("Decrypted: ", end="", flush=True)
    sys.stdout.write(plaintext.decode())
    print("", flush=True)

if __name__ == "__main__":
    main()
