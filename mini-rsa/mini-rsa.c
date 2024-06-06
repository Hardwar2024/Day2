#include "mini-rsa.h"

#define DEFAULT_E 65537

uint64_t modadd(uint64_t a, uint64_t b, uint64_t mod)
{
    if (a >= mod)
        a %= mod;
    if (b >= mod)
        b %= mod;

    a += b;
    if (a >= mod || a < b)
        a -= mod;
    return a;
}

uint64_t modmult(uint64_t a, uint64_t b, uint64_t mod)
{

    if (a == 0 || b < mod / a)
        return ((uint64_t)a * b) % mod;
    uint64_t sum;
    sum = 0;
    while (b > 0)
    {
        if (b & 1)
            sum = modadd(sum, a, mod);
        a = modadd(a, a, mod);
        b >>= 1;
    }
    return sum;
}

uint64_t modpow(uint64_t a, uint64_t b, uint64_t mod)
{
    uint64_t product, pseq;
    product = 1;
    pseq = a % mod;
    while (b > 0)
    {
        if (b & 1)
            product = modmult(product, pseq, mod);
        pseq = modmult(pseq, pseq, mod);
        b >>= 1;
    }
    return product;
}

uint64_t gcd(uint64_t a, uint64_t b)
{
    if (a == 0)
        return b;
    return gcd(b % a, a);
}

uint64_t find_d(uint64_t e, uint64_t phi)
{
    uint64_t eprev, dprev, d = 1, etemp, dtemp;

    eprev = phi, dprev = phi;
    while (e != 1)
    {
        etemp = e;
        dtemp = d;
        e = eprev - eprev / etemp * e;
        d = dprev - eprev / etemp * d;
        eprev = etemp;
        dprev = dtemp;
        while (d < 0)
            d += phi;
    }

    return d;
}

/**
 * Generate a private key based on two given values of p and q.
 * Both of these values must be prime values.
 * 
 * There is a small chance that the selected p and q values do not work well with
 * the hardcoded "e" value. In this case, e is set to 0xFFFFFFFF to indicate an error.
 * In this case, choose another pair of p and q.
*/
void rsa_generate_private_key(RSAPrivateKey *priv, uint32_t p, uint32_t q)
{
    uint64_t lambda = (uint64_t)(p - 1) * (uint64_t)(q - 1);
    priv->p = p;
    priv->q = q;
    priv->public_key.n = (uint64_t)p * (uint64_t)q;
    if (gcd(DEFAULT_E, lambda) != 1)
    {
        priv->public_key.e = -1; // indicates an error
        return;                  // They should be co-prime. Try another values
    }
    priv->public_key.e = DEFAULT_E;
    priv->d = find_d(priv->public_key.e, lambda);
}

/**
 * Sign a message (data) with a private key.
*/
uint64_t rsa_sign(RSAPrivateKey *priv, uint64_t data)
{
    return modpow(data, priv->d, priv->public_key.n);
}

/**
 * Check if a signature is valid.
*/
int rsa_validate(RSAPublicKey* pub, uint64_t signature, uint64_t data)
{
    return modpow(signature, pub->e, pub->n) == (data % pub->n);
}