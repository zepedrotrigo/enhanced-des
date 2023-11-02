import numpy as np

class LCG:
    def __init__(self, seed):
        self.state = seed

    def next(self):
        self.state = (self.state * 1103515245 + 12345) & 0x7FFFFFFF
        return self.state


def pkcs7_pad(data, block_size):
    padding_length = block_size - (len(data) % block_size)
    return data + bytes([padding_length] * padding_length)


def pkcs7_unpad(data):
    padding_length = data[-1]
    return data[:-padding_length]


def generate_sboxes(key):
    # Ensure key is 256-bit
    assert len(key) == 32
    
    seed = 0
    for ch in key:
        seed = ((seed << 5) | (seed >> (64-5))) ^ ord(ch)
        seed &= 0xFFFFFFFFFFFFFFFF  # Ensure 64-bit size
    
    prng = LCG(seed)
    
    # Generate 16 S-Boxes
    sboxes = []
    for i in range(16):
        sbox = [prng.next() % 256 for _ in range(256)]
        
        # Ensure 16 zeros across all S-Boxes
        zero_indices = [idx for idx, val in enumerate(sbox) if val == 0]
        for zidx in zero_indices[1:]:
            missing_values = set(range(1, 256)) - set(sbox)
            sbox[zidx] = missing_values.pop()
        
        sboxes.append(sbox)
        
    return sboxes


def feistel_function(sbox, input_block):
    assert len(input_block) == 4
    
    out = [0] * 4
    index = input_block[3]
    out[0] = sbox[index]
    index = (index + input_block[2]) % 256
    out[1] = sbox[index]
    index = (index + input_block[1]) % 256
    out[2] = sbox[index]
    index = (index + input_block[0]) % 256
    out[3] = sbox[index]
    
    return bytes(out)


def edes_encrypt_block(key, plaintext_block, sboxes):
    # Ensure block is 64 bits
    assert len(plaintext_block) == 8
    
    L, R = plaintext_block[:4], plaintext_block[4:]
    
    # 16 rounds of Feistel Network
    for i in range(16):
        L, R = R, bytes(a ^ b for a, b in zip(L, feistel_function(sboxes[i], R)))
    
    return R + L


def edes_decrypt_block(key, ciphertext_block, sboxes):
    # Ensure block is 64 bits
    assert len(ciphertext_block) == 8
    
    L, R = ciphertext_block[:4], ciphertext_block[4:]
    
    # 16 rounds of Feistel Network in reverse
    for i in range(15, -1, -1):
        L, R = R, bytes(a ^ b for a, b in zip(L, feistel_function(sboxes[i], R)))
    
    return R + L


def edes_encrypt(key, plaintext):
    padded_data = pkcs7_pad(plaintext, 8)
    ciphertext = b''
    sboxes = generate_sboxes(key)

    # Encrypt each block using ECB mode
    for i in range(0, len(padded_data), 8):
        block = padded_data[i:i+8]
        ciphertext += edes_encrypt_block(key, block, sboxes)
    
    return ciphertext


def edes_decrypt(key, ciphertext):
    plaintext = b''
    sboxes = generate_sboxes(key)
    
    # Decrypt each block using ECB mode
    for i in range(0, len(ciphertext), 8):
        block = ciphertext[i:i+8]
        plaintext += edes_decrypt_block(key, block, sboxes)
    
    return pkcs7_unpad(plaintext)


''' TESTS ###
#password = "rkDAHX6yG9TzwLuL7HLkuMUdXrVN6q92"
#plaintext = "My name is Alice and this is my very secret message."
#ciphertext = edes_encrypt(password, plaintext.encode())
#decrypted = edes_decrypt(password, ciphertext)
#print(decrypted)
'''