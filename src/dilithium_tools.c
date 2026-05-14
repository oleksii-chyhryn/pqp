#include "dilithium_tools.h"
#include <oqs/oqs.h>
#include <stdlib.h>
#include <stdio.h>
#include <stddef.h>

void cleanup_d(Dilithium* d) {
    OQS_MEM_secure_free(d->kp->skey, d->kp->skey_len);
    OQS_MEM_insecure_free(d->kp->pkey);
    OQS_MEM_insecure_free(d->msg);
    OQS_MEM_insecure_free(d->signature);
    OQS_SIG_free(d->sig);
    return;
}

DKP* gen_keypair_d() {
    DKP* d;
    d->sig = OQS_SIG_new(OQS_SIG_alg_ml_dsa_87);
    if (!d->sig) {
        fprintf(stderr, "Error generating keypair, shutdown imminent");
        cleanup(d);
        return 0;
    }
    d->pkey_len = d->sig->length_public_key;
    d->skey_len = d->sig->length_secret_key;
    d->pkey = malloc(d->pkey_len);
    d->skey = malloc(d->skey_len);

    if (OQS_SIG_keypair(d->sig, d->pkey, d->skey) != OQS_SUCCESS) {
        fprintf(stderr, "Error generating keypair, shutdown imminent");
        cleanup(SIG_new(d));
        return 0;
    }
    return d;
}

Dilithium* SIG_new_d(Dilithium_kp *kp) {
    Dilithium* d;
    d->sig = kp->sig;
    d->signature = NULL;
    d->signature_len = 0;
    d->kp = kp;
    d->msg = NULL;
    d->msg_len = 0;
    return d;
}

int sign_d(Dilithium* d, char* msg, size_t msg_len){
    uint8_t* signature = malloc(d->sig->length_signature);
    if (OQS_SIG_sign(d->sig, d->signature, &(d->signature_len), msg, msg_len, d->kp->skey)!=OQS_SUCCESS) {cleanup(d); return OQS_ERROR;}
}

int verify_d(Dilithium* d, char* msg, size_t msg_len) {
    if (OQS_SIG_verify(d->sig, msg, msg_len, d->signature, d->signature_len, d->kp->pkey) != OQS_SUCCESS) {
        fprintf(stderr, "Verification error!\n");
        return -1;
    }
    return OQS_SUCCESS;
}
