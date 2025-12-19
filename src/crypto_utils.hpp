#ifndef CRYPTO_UTILS_HPP
#define CRYPTO_UTILS_HPP

#include <openssl/evp.h>
#include <string>
#include <vector>

// Loads a PEM-encoded private key from disk
EVP_PKEY* loadPrivateKey(const std::string& path);

// Loads a PEM-encoded public key from disk
EVP_PKEY* loadPublicKey(const std::string& path);

// Signs a message using RSA + SHA-256
std::vector<unsigned char> signMessage(
    EVP_PKEY* privateKey,
    const std::string& message
);

// Verifies a signature using RSA + SHA-256
bool verifySignature(
    EVP_PKEY* publicKey,
    const std::string& message,
    const std::vector<unsigned char>& signature
);


#endif