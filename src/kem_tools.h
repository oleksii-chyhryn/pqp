#include <oqs/oqs.h>
#ifndef _KYBER
#define _KYBER

typedef struct Kyber_kp {
    OQS_KEM *kem;
    uint8_t* pkey;
    uint8_t* skey;
    size_t pkey_len;
    size_t skey_len;
} Kyber_kp;

typedef struct Kyber {
    OQS_KEM *kem;
    Kyber_kp *kp;
    uint8_t *shared_secret;
    uint8_t *ctext;
} Kyber;

typedef Kyber_kp KKP;

void cleanup_k(Kyber* k);

KKP* gen_keypair_k();

Kyber* KEM_new_k(Kyber_kp* kp);

int encaps_k(Kyber *k);

int decaps_k(Kyber *k);

#endif