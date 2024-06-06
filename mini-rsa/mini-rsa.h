#include <stdint.h>

typedef struct{
    uint64_t n;
    uint32_t e;
} RSAPublicKey;

typedef struct{
    RSAPublicKey public_key;
    uint32_t p;
    uint32_t q;
    uint64_t d;
} RSAPrivateKey;

void rsa_generate_private_key(RSAPrivateKey* priv, uint32_t p, uint32_t q);
uint64_t rsa_sign(RSAPrivateKey* priv, uint64_t data);
int rsa_validate(RSAPublicKey* pub, uint64_t signature, uint64_t data);