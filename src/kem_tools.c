#include "kem_tools.h"
#include <oqs/oqs.h>
#include <stdlib.h>
#include <stdio.h>
#include <stddef.h>

void cleanup_k(Kyber* k) {
    if (k->kem != NULL) {
        OQS_MEM_secure_free(k->kp->skey, k->kp->skey_len);
        OQS_MEM_secure_free(k->shared_secret, k->kem->length_shared_secret);
    }
    OQS_MEM_insecure_free(k->ctext);
    OQS_MEM_insecure_free(k->kp->pkey);
    OQS_KEM_free(k->kem);
}

KKP* gen_keypair_k() {
    KKP* kkp;
    kkp->kem = OQS_KEM_new(OQS_KEM_alg_ml_kem_1024);
    kkp->pkey = malloc(kkp->kem->length_public_key);
    kkp->skey = malloc(kkp->kem->length_secret_key);
    kkp->pkey_len = kkp->kem->length_public_key;
    kkp->skey_len = kkp->kem->length_secret_key;

    if (OQS_KEM_keypair(kkp->kem, kkp->pkey, kkp->skey) != OQS_SUCCESS) {
        fprintf(stderr, "Error generating kem keypair!\n");
        cleanup(KEM_new(kkp));
        return 0;
    }
    return kkp;
}

Kyber* KEM_new_k(Kyber_kp* kp) {
    Kyber* k;
    k->kp = kp;
    k->kem = k->kp->kem;
    k->shared_secret = malloc(k->kem->length_shared_secret);
    k->ctext = malloc(k->kem->length_ciphertext);
    return k;
}

int encaps_k(Kyber *k){
    KKP* kp = k->kp;
    if (OQS_KEM_encaps(k->kem, k->ctext, k->shared_secret, kp->pkey) != OQS_SUCCESS) {
        fprintf(stderr, "Error during kem encaps!\n");
        cleanup(k);
        return OQS_ERROR;
    }
}

int decaps_k(Kyber *k) {
    KKP* kp = k->kp;
    if (OQS_KEM_decaps(k->kem, k->shared_secret, k->ctext, kp->skey) != OQS_SUCCESS) {
        fprintf(stderr, "Error during kem decaps!\n");
        cleanup(k);
        return OQS_ERROR;
    }
}