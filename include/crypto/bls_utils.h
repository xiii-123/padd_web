#pragma once

#include <openssl/sha.h>
#include <pbc/pbc.h>
#include <string>
#include <memory>
#include <vector>

extern pairing_t PAIRING;

#define PKC_SIZE 424

// BLS key structures
typedef struct {
    element_t v;
    element_t spk;
} bls_pk;

typedef struct {
    element_t alpha;
    element_t ssk;
} bls_sk;

/**
 * @brief Represents a BLS (Boneh-Lynn-Shacham) key pair container structure
 * 
 * This structure contains both public and private BLS keys along with the generator element.
 * It's used for operations requiring access to complete BLS cryptographic key materials.
 * 
 * @struct bls_pkc
 * @var bls_pkc::pk Pointer to the BLS public key
 * @var bls_pkc::sk Pointer to the BLS secret key
 * @var bls_pkc::g Generator element for the BLS cryptographic operations
 */
typedef struct {
    bls_pk *pk;
    bls_sk *sk;
    element_t g;
} bls_pkc;

// Function declarations
element_t* sig_init();

void sign_message(element_t sk, std::string message, element_t sig);

int verify_signature(element_t sig, element_t g, element_t public_key, std::string message);

void compress_element(unsigned char **data, int *n, element_t sig, pairing_t PAIRING);

void decompress_element(element_t sig, unsigned char *data, int n);
