# Advanced-ECC-Cpp

An advanced C++ implementation of Elliptic Curve Cryptography (ECC) featuring:

- **Finite Field Operations**: Efficient arithmetic in GF(p).
- **Elliptic Curve Operations**: Point addition, doubling, and scalar multiplication.
- **Elliptic Curve Diffie-Hellman (ECDH)**: Secure key exchange mechanism.
- **Elliptic Curve Digital Signature Algorithm (ECDSA)**: Secure signing and verification.
- **Point Compression and Decompression**: Optimized public key representation.
- **Secure Random Number Generation**: Cryptographically secure randomness using C++11 `<random>`.
- **Comprehensive Demonstrations**: Examples showcasing key generation, encryption/decryption, signing/verification.

> **Disclaimer:** This implementation is intended for educational purposes only and should not be used in production environments. For secure applications, consider using well-established cryptographic libraries like [OpenSSL](https://www.openssl.org/), [libsodium](https://libsodium.org/), or [Crypto++](https://www.cryptopp.com/).

## Features

- **Finite Field Arithmetic**: Implements addition, subtraction, multiplication, division, and inversion in a prime field GF(p).
- **Elliptic Curve Operations**: Supports point addition, doubling, and scalar multiplication using the double-and-add algorithm.
- **Key Generation**: Generates secure private-public key pairs.
- **ECDH Key Exchange**: Facilitates secure shared secret generation between parties.
- **ECDSA Signing and Verification**: Enables signing messages and verifying signatures using the Elliptic Curve Digital Signature Algorithm.
- **Point Compression**: Reduces public key size by storing only the x-coordinate and a parity bit for the y-coordinate.
- **Message Hashing**: Integrates SHA-256 hashing for secure message signing.
- **Secure Randomness**: Utilizes C++11’s `<random>` library for cryptographically secure random number generation.

## Prerequisites

- **C++17 Compiler**: Ensure you have a modern C++ compiler that supports C++17 standards (e.g., `g++`, `clang++`).
- **OpenSSL Library**: Required for SHA-256 hashing.
  
  ### **Installation on Ubuntu/Debian:**

  ```bash
  sudo apt update
  sudo apt install build-essential libssl-dev
