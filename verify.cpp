#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/bio.h>
#include <openssl/evp.h>
#include <openssl/pem.h>

void handleErrors() {
    fprintf(stderr, "Error occurred.\n");
    exit(EXIT_FAILURE);
}

int verifySignature(const char *message, const char *signatureHex, const char *publicKeyPath) {
    FILE *publicKeyFile = fopen(publicKeyPath, "r");
    if (!publicKeyFile) {
        perror("Error opening public key file");
        return 1;
    }

    EVP_PKEY *publicKey = PEM_read_PUBKEY(publicKeyFile, NULL, NULL, NULL);
    fclose(publicKeyFile);

    if (!publicKey) {
        fprintf(stderr, "Error reading public key\n");
        return 1;
    }

    // Create a verification context
    EVP_MD_CTX *ctx = EVP_MD_CTX_create();
    if (!ctx) {
        handleErrors();
    }

    // Initialize the verification operation
    if (EVP_DigestVerifyInit(ctx, NULL, EVP_sha256(), NULL, publicKey) != 1) {
        handleErrors();
    }

    // Update the message to be verified
    if (EVP_DigestVerifyUpdate(ctx, message, strlen(message)) != 1) {
        handleErrors();
    }

    // Convert the hexadecimal signature to binary
    size_t signatureLen = strlen(signatureHex) / 2;
    printf("Signature length: %zu\n", signatureLen);
    unsigned char *signature = (unsigned char*)malloc(signatureLen);
    if (!signature) {
        perror("Memory allocation failed");
        return 1;
    }

    // Convert the hexadecimal signature to binary
    for (size_t i = 0; i < signatureLen; i++) {
        sscanf(signatureHex + 2 * i, "%2hhx", signature + i);
    }

    // Perform the verification
    int verificationResult = EVP_DigestVerifyFinal(ctx, signature, signatureLen);

    // Print the result
    if (verificationResult == 1) {
        printf("Signature verification successful\n");
    } else if (verificationResult == 0) {
        printf("Signature verification failed\n");
    } else {
        handleErrors();
    }

    // Clean up
    free(signature);
    EVP_MD_CTX_destroy(ctx);
    EVP_PKEY_free(publicKey);

    return 0;
}

int main(int argc, char **argv) {
    if (argc != 4) {
        fprintf(stderr, "Usage: %s <public key path> <message> <signature>\n", argv[0]);
        return EXIT_FAILURE;
    }
    const char *publicKeyPath = argv[1];
    const char *message = argv[2];
    const char *signatureHex = argv[3];

    if (verifySignature(message, signatureHex, publicKeyPath) != 0) {
        fprintf(stderr, "Signature verification failed\n");
        return EXIT_FAILURE;
    }

    return 0;
}

