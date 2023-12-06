#include <cstdio>

#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>

#include <string>
#include <vector>

std::vector<unsigned char> base64_decode(const std::string &base64_encoded) {
    BIO *bio, *b64;
    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new_mem_buf(base64_encoded.c_str(), base64_encoded.size());
    bio = BIO_push(b64, bio);

    std::vector<unsigned char> result(base64_encoded.size());
    int length = BIO_read(bio, result.data(), result.size());
    BIO_free_all(bio);

    result.resize(length);
    return result;
}

std::vector<unsigned char> hex_decode(const std::string &hex_encoded) {
    std::vector<unsigned char> result(hex_encoded.size() / 2);
    for (size_t i = 0; i < result.size(); i++) {
        sscanf(hex_encoded.c_str() + 2 * i, "%2hhx", result.data() + i);
    }
    return result;
}

bool decrypt_with_private_key(EVP_PKEY *privateKey, const std::string &encrypted_message, std::string &message) {
    EVP_PKEY_CTX *ctx;
    size_t outlen;
    unsigned char *outbuf;

    ctx = EVP_PKEY_CTX_new(privateKey, NULL);
    if (!ctx)
        return false;

    if (EVP_PKEY_decrypt_init(ctx) <= 0)
        return false;

    if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0)
        return false;

    // std::vector<unsigned char> encrypted_message_bytes = base64_decode(encrypted_message);
    std::vector<unsigned char> encrypted_message_bytes = hex_decode(encrypted_message);

    if (EVP_PKEY_decrypt(ctx, NULL, &outlen, encrypted_message_bytes.data(), encrypted_message_bytes.size()) <= 0)
        return false;

    outbuf = (unsigned char *)malloc(outlen);
    if (!outbuf)
        return false;

    if (EVP_PKEY_decrypt(ctx, outbuf, &outlen, encrypted_message_bytes.data(), encrypted_message_bytes.size()) <= 0)
        return false;

    message = std::string(outbuf, outbuf + outlen);

    free(outbuf);
    EVP_PKEY_CTX_free(ctx);

    return true;
}

int main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <private key path> <encrypted message>\n", argv[0]);
        return EXIT_FAILURE;
    }
    const char *private_key_path = argv[1];
    const char *encrypted_message = argv[2];

    FILE *private_key_file = fopen(private_key_path, "r");
    if (!private_key_file) {
        perror("Failed to open private key file");
        return EXIT_FAILURE;
    }

    EVP_PKEY *private_key = PEM_read_PrivateKey(private_key_file, NULL, NULL, NULL);
    if (!private_key) {
        fprintf(stderr, "Error reading private key\n");
        return EXIT_FAILURE;
    }

    std::string message;
    if (!decrypt_with_private_key(private_key, encrypted_message, message)) {
        fprintf(stderr, "Error decrypting message\n");
        return EXIT_FAILURE;
    }

    printf("Decrypted message: %s\n", message.c_str());
    return 0;
}
