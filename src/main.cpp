#include "crypto_utils.hpp"
#include <iostream>

int main() {
    try {
        EVP_PKEY* privateKey = loadPrivateKey("../keys/private_key.pem");
        EVP_PKEY* publicKey  = loadPublicKey("../keys/public_key.pem");

        std::string message = "RSA 2048 signing demo in C++!";

        auto signature = signMessage(privateKey, message);
        bool valid = verifySignature(publicKey, message, signature);

        std::cout << "Signature valid? "
                  << (valid ? "YES" : "NO") << "\n";

        EVP_PKEY_free(privateKey);
        EVP_PKEY_free(publicKey);

    } catch (const std::exception& ex) {
        std::cerr << "Error: " << ex.what() << "\n";
    }
}
