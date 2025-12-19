#include "crypto_utils.hpp"
#include <openssl/pem.h>
#include <stdexcept>
#include <cstdio>

EVP_PKEY* loadPrivateKey(const std::string& path) {
    FILE* file = fopen(path.c_str(), "r");
    if (!file) {
        throw std::runtime_error("Unable to open private key file");
    }

    EVP_PKEY* key = PEM_read_PrivateKey(
        file,
        nullptr,
        nullptr,
        nullptr
    );

    fclose(file);

    if (!key) {
        throw std::runtime_error("Failed to parse private key");
    }

    return key;
}


EVP_PKEY* loadPublicKey(const std::string& path) {
    FILE* file = fopen(path.c_str(), "r");
    if (!file) {
        throw std::runtime_error("Unable to open public key file");
    }

    EVP_PKEY* key = PEM_read_PUBKEY(file, nullptr, nullptr, nullptr);
    fclose(file);

    if (!key) {
        throw std::runtime_error("Failed to parse public key");
    }

    return key;
}


std::vector<unsigned char> signMessage(
    EVP_PKEY* privateKey,
    const std::string& message
) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) throw std::runtime_error("Failed to create MD_CTX");

    if (EVP_DigestSignInit(ctx, nullptr, EVP_sha256(), nullptr, privateKey) <= 0)
        throw std::runtime_error("DigestSignInit failed");

    EVP_DigestSignUpdate(ctx, message.data(), message.size());

    size_t sigLen = 0;
    EVP_DigestSignFinal(ctx, nullptr, &sigLen);

    std::vector<unsigned char> signature(sigLen);
    EVP_DigestSignFinal(ctx, signature.data(), &sigLen);

    EVP_MD_CTX_free(ctx);
    return signature;
}


bool verifySignature(
    EVP_PKEY* publicKey,
    const std::string& message,
    const std::vector<unsigned char>& signature
) {
    EVP_MD_CTX* ctx = EVP_MD_CTX_new();
    if (!ctx) throw std::runtime_error("Failed to create MD_CTX");

    if (EVP_DigestVerifyInit(ctx, nullptr, EVP_sha256(), nullptr, publicKey) <= 0)
        throw std::runtime_error("DigestVerifyInit failed");

    EVP_DigestVerifyUpdate(ctx, message.data(), message.size());

    int result = EVP_DigestVerifyFinal(
        ctx,
        signature.data(),
        signature.size()
    );

    EVP_MD_CTX_free(ctx);

    return result == 1;
}
