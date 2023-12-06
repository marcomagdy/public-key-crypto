
#include <_stdio.h>
#include <cmath>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>

#include <string>

std::string base64_encode(unsigned char *bytes, size_t length) {
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

std::string hex_encode(unsigned char *bytes, size_t length) {
  std::string result;
  const auto hex_digits = "0123456789ABCDEF";
  result.resize(length * 2);
  for (size_t i = 0; i < length; i++) {
    result[2 * i] = hex_digits[(bytes[i] & 0xF0) >> 4];
    result[2 * i + 1] = hex_digits[bytes[i] & 0x0F];
  }
  return result;
}

bool encrypt_with_public_key(EVP_PKEY *publicKey, const std::string &message,
                             std::string &encrypted_message) {
  EVP_PKEY_CTX *ctx;
  size_t outlen;
  unsigned char *outbuf;

  ctx = EVP_PKEY_CTX_new(publicKey, NULL);
  if (!ctx)
    return false;

  if (EVP_PKEY_encrypt_init(ctx) <= 0)
    return false;

  if (EVP_PKEY_CTX_set_rsa_padding(ctx, RSA_PKCS1_PADDING) <= 0)
    return false;

  if (EVP_PKEY_encrypt(ctx, NULL, &outlen, (unsigned char *)message.c_str(),
                       message.size()) <= 0)
    return false;

  outbuf = (unsigned char *)malloc(outlen);
  if (!outbuf)
    return false;

  if (EVP_PKEY_encrypt(ctx, outbuf, &outlen, (unsigned char *)message.c_str(),
                       message.length()) <= 0)
    return false;

  // encrypted_message = base64_encode(outbuf, outlen);
  encrypted_message = hex_encode(outbuf, outlen);

  free(outbuf);
  EVP_PKEY_CTX_free(ctx);

  return true;
}

int main(int argc, char **argv) {
  if (argc != 3) {
    fprintf(stderr, "Usage: %s <public key path> <message>\n", argv[0]);
    return EXIT_FAILURE;
  }

  const char *public_key_path = argv[1];
  const char *message = argv[2];

  FILE *public_key_file = fopen(public_key_path, "r");
  if (!public_key_file) {
    perror("Error opening private key file");
    return 1;
  }

  EVP_PKEY *public_key = PEM_read_PUBKEY(public_key_file, NULL, NULL, NULL);
  if (!public_key) {
    fprintf(stderr, "Error reading public key\n");
    return 1;
  }

  std::string encrypted_message;
  if (!encrypt_with_public_key(public_key, message, encrypted_message)) {
    fprintf(stderr, "Error encrypting message\n");
    return 1;
  }

  printf("Encrypted message: %s\n", encrypted_message.c_str());
  return 0;
}
