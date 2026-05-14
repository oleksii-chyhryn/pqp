#include "dilithium_tools.h"
#include "kem_tools.h"
#include <oqs/oqs.h>
#include <microtar.h>
#include <string.h>
#include <stdio.h>



char* add_ext(char* src, char* ext){
    size_t src_len = strlen(src);
    char* ret = malloc(src_len+5);
    strcpy(ret, src);
    strcpy(ret+src_len, ext);
    return ret;
}

int main(int argc, char** argv) {
    if (argc != 5) {
        printf("Usage: %s <option> <input> <output> <keyfile>", argv[0]);
        return 1;
    }

    if (strcmp(argv[1], "encrypt") == 0 || strcmp(argv[1], "encrypt-only") == 0) {
        
    }
}