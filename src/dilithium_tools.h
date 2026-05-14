#include <oqs/oqs.h>
#ifndef _DILITHIUM
#define _DILITHIUM

typedef struct Dilithium_kp {
    OQS_SIG *sig;
    uint8_t* pkey;
    uint8_t* skey;
    size_t pkey_len;
    size_t skey_len;
} Dilithium_kp;

typedef struct Dilithium {
    OQS_SIG *sig;
    Dilithium_kp *kp;
    uint8_t* signature;
    uint8_t* msg;
    size_t msg_len;
    size_t signature_len;
} Dilithium;

typedef Dilithium_kp DKP;

void cleanup_d(Dilithium *d);

DKP* gen_keypair_d();

Dilithium* SIG_new_d(Dilithium_kp* kp);

int sign_d(Dilithium *d, char *msg, size_t msg_len);

int verify_D(Dilithium *d, char *msg, size_t msg_len);

#endif