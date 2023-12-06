#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rand.h>

#include <string>

void handleErrors() {
    fprintf(stderr, "Error occurred.\n");
    exit(EXIT_FAILURE);
}
std::string base64_encode(unsigned char* bytes, size_t length);

int signMessage(const char *message, const char *privateKeyPath) {
    FILE *privateKeyFile = fopen(privateKeyPath, "r");
    if (!privateKeyFile) {
        perror("Error opening private key file");
        return 1;
    }

    // The key must be in PEM format. Notice that OpenSSH uses a different pem format.
    // You can convert an OpenSSH key to PEM with the following command:
    // ssh-keygen -p -m PEM -f ~/.ssh/id_rsa
    // The same goes for public keys.
    EVP_PKEY *privateKey = PEM_read_PrivateKey(privateKeyFile, NULL, NULL, NULL);
    fclose(privateKeyFile);

    if (!privateKey) {
        fprintf(stderr, "Error reading private key\n");
        return 1;
    }

    // Create a signature context
    EVP_MD_CTX *ctx = EVP_MD_CTX_create();
    if (!ctx) {
        handleErrors();
    }

    // Initialize the signing operation
    if (EVP_DigestSignInit(ctx, NULL, EVP_sha256(), NULL, privateKey) != 1) {
        handleErrors();
    }

    // Update the message to be signed
    if (EVP_DigestSignUpdate(ctx, message, strlen(message)) != 1) {
        handleErrors();
    }

    // Finalize the signature
    size_t signatureLen;
    if (EVP_DigestSignFinal(ctx, NULL, &signatureLen) != 1) {
        handleErrors();
    }

    unsigned char *signature = (unsigned char*)malloc(signatureLen);
    if (!signature) {
        perror("Memory allocation failed");
        return 1;
    }

    if (EVP_DigestSignFinal(ctx, signature, &signatureLen) != 1) {
        handleErrors();
    }

    // Print the signature in hexadecimal format
    printf("Signature: \n");
    std::string signature_base64 = base64_encode(signature, signatureLen);
    printf("%s\n", signature_base64.c_str());

    // Clean up
    free(signature);
    EVP_MD_CTX_destroy(ctx);
    EVP_PKEY_free(privateKey);

    return 0;
}

int main(int argc, char **argv) {
    if (argc != 3) {
        fprintf(stderr, "Usage: %s <private key path> <message>\n", argv[0]);
        return EXIT_FAILURE;
    }
    const char *message = argv[2];
    const char *privateKeyPath = argv[1];

    if (signMessage(message, privateKeyPath) != 0) {
        fprintf(stderr, "Signing failed\n");
        return EXIT_FAILURE;
    }

    return 0;
}

std::string base64_encode(unsigned char* bytes, size_t length)
{
    BIO *bio, *b64;
    BUF_MEM *bufferPtr;

    b64 = BIO_new(BIO_f_base64());
    bio = BIO_new(BIO_s_mem());
    bio = BIO_push(b64, bio);

    BIO_write(bio, bytes, length);
    BIO_flush(bio);
    BIO_get_mem_ptr(bio, &bufferPtr);

    std::string result(bufferPtr->data, bufferPtr->length);

    BIO_free_all(bio);

    return result;
}
