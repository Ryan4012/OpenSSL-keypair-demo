# OpenSSL-keypair-demo

## Images
<p align="center">
  Commands to run the keypair demo <br>
  <img src="./images/OpenSSL Keypair Demo.png" alt="" width="500" />
</p>

## Overview
This project demonstrates RSA 2048-bit keypair cryptography in C++ using OpenSSL. It includes utilities to load PEM-encoded public and private keys, sign messages with the private key, and verify signatures with the public key. The demo is designed to show practical use of OpenSSL EVP APIs for secure digital signatures.

## Motivation & Goals
- Understand how RSA digital signatures work at a code level
- Gain hands-on experience using OpenSSL C APIs for cryptographic operations
- Build reusable C++ utilities for loading keys and signing/verifying messages
- Explore secure message authentication and integrity verification techniques

## Technology Stack
- C++ (C++11+)
- OpenSSL (EVP API)
- CMake build system

## Architecture Overview
- main.cpp demonstrates loading keys, signing a string message, and verifying the signature
- crypto_utils.cpp/.hpp provide functions for key loading and signing/verifying
- Keys are PEM-encoded and stored outside the source tree (e.g., in a /keys folder)
- Program outputs whether signature verification was successful

## Services & Functionality
| Component       | Purpose                          | Deployment    |
|-----------------|----------------------------------|---------------|
| Key Loader      | Loads PEM private/public keys    | C++ utility   |
| Sign Function   | Signs a message with private key | Demo executable |
| Verify Function | Verifies signature with public key | Demo executable |

## Security Considerations
- Private keys are loaded securely from files with error handling
- Signature generation uses SHA-256 for message digest
- Proper error checking on all OpenSSL API calls
- Keys and sensitive data not embedded in source code

## Setup & Deployment
- Build using CMake (cmake .. && make)
- Place PEM keys in the /keys directory as specified in code
- Run executable to see signing and verification outputs

## What I Learned
- Practical use of OpenSSL EVP interfaces
- How RSA digital signatures work in C++
- Key management and error handling in cryptography
- Using CMake to manage cryptographic projects

## Future Improvements & Roadmap
- Support other key sizes and algorithms (e.g., ECC)
- Add encryption/decryption demos
- Wrap utilities in a reusable library
- Add command-line interface for signing files/messages

