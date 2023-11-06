# Enhanced DES (E-DES)

This repository contains the implementation of Enhanced DES (E-DES), a symmetric key block cipher that extends the traditional Data Encryption Standard (DES) by using a 256-bit key and optimizing operations within the Feistel Networks. E-DES is designed to improve upon DES's security measures while maintaining cross-language compatibility between C and Python implementations.

## Features

- 256-bit key for enhanced security.
- Consistent S-Box generation across C and Python using a custom Linear Congruential Generator (LCG).
- Cross-language encryption and decryption compatibility.
- PKCS7 padding for block size alignment.