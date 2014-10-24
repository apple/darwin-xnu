/*
 *  ccdrbg_nisthmac.c
 *  corecrypto
 *
 *  Created by John Hurley on 04/30/14.
 *  Copyright 2014 Apple, Inc. All rights reserved.
 *
 */

#include <corecrypto/ccdrbg.h>
#include <corecrypto/cchmac.h>
#include <corecrypto/ccsha2.h>
#if !CC_KERNEL
#include <corecrypto/cc_debug.h>
#endif


#if CC_KERNEL
#include <pexpert/pexpert.h>
static int hmac_dbrg_error(int val, __unused const char *msg) {
	return val;
}
#else
static int hmac_dbrg_error(int val, const char *msg) {
    if (msg) {
        char buffer[1024];
        snprintf(buffer, sizeof(buffer)-1, "Error: %s", msg);
        cc_print(buffer, 0, NULL);
    }
    return val;
}
#endif

// Test vectors at:
//      http://csrc.nist.gov/groups/STM/cavp/#05
//      http://csrc.nist.gov/groups/STM/cavp/documents/drbg/drbgtestvectors.zip
//

/*
    This HMAC DBRG is described in:

    SP 800-90 A Rev. 1 (2nd Draft)
    DRAFT Recommendation for Random Number Generation Using Deterministic Random Bit Generators
    April 2014

    SP 800-90A (revision 1), Recommendation for Random Number Generation Using Deterministic Random Bit Generators
    http://csrc.nist.gov/publications/drafts/800-90/sp800_90a_r1_draft.pdf

    See in particular
    - 10.1.2 HMAC_DRBG (p 45)
    - B.2 HMAC_DRBGExample (p 83)

    We only support one security strength, 256 bits
    In addition, we limit the personalization string to 20 bytes
    Note that the example in B.2 is very limited, refer to §10.1.2 for more
*/



/*
 The Get_entropy_input function is specified in pseudocode in [SP 800-90C] for various RBG constructions; 
 however, in general, the function has the following meaning:
 Get_entropy_input: A function that is used to obtain entropy input. The function call is:
 (status, entropy_input) = Get_entropy_input (min_entropy, min_ length, max_ length, prediction_resistance_request),
 which requests a string of bits (entropy_input) with at least min_entropy bits of entropy. The length for the string
 shall be equal to or greater than min_length bits, and less than or equal to max_length bits. The 
 prediction_resistance_request parameter indicates whether or not prediction resistance is to be provided during the request 
 (i.e., whether fresh entropy is required). A status code is also returned from the function.
 */

/*
 Check the validity of the input parameters.
 1. If (requested_instantiation_security_strength > 256), then Return (“Invalid
 requested_instantiation_security_strength”, −1).
 2. If (len (personalization_string) > 160), then Return (“Personalization_string
 too long”, −1)
 Comment: Set the security_strength to one of the valid security strengths.
 3. If (requested_security_strength ≤ 112), then security_strength = 112 Else (requested_ security_strength ≤ 128), then security_strength = 128 Else (requested_ security_strength ≤ 192), then security_strength = 192 Else security_strength = 256.
 Comment: Get the entropy_input and the nonce.
 4. min_entropy = 1.5 × security_strength.
 5. (status, entropy_input) = Get_entropy_input (min_entropy, 1000).
 6. If (status ≠ “Success”), then Return (status, −1).
 */

/*
 1. highest_supported_security_strength = 256.
 2. Output block (outlen) = 256 bits.
 3. Required minimum entropy for the entropy input at instantiation = 3/2 security_strength (this includes the entropy required for the nonce).
 4. Seed length (seedlen) = 440 bits.
 5. Maximum number of bits per request (max_number_of_bits_per_request) = 7500
 bits.
 6. Reseed_interval (reseed_ interval) = 10,000 requests.
 7. Maximum length of the personalization string (max_personalization_string_length) = 160 bits.
 8. Maximum length of the entropy input (max _length) = 1000 bits.
 */

//
// Defines below based on 10.1, Table 2: Definitions for Hash-Based DRBG Mechanisms (p 39)
//

#define NH_MAX_SECURITY_STRENGTH    256                             // in bits
#define NH_MAX_OUTPUT_BLOCK_SIZE    (CCSHA512_OUTPUT_SIZE)          // 512 bits, i.e. 64 bytes (CCSHA512_OUTPUT_SIZE)
#define NH_MAX_KEY_SIZE             (CCSHA512_OUTPUT_SIZE)          // 512 bits, i.e. 64 bytes (CCSHA512_OUTPUT_SIZE)
#define NH_REQUIRED_MIN_ENTROPY(s)  (3*(s)/2)
#define NH_MAX_BYTES_PER_REQUEST    (0xffff)                        // in bytes, 2^^16
#define NH_RESEED_INTERVAL          ((unsigned long)0xffffffffffff) // 2^^48 requests between reseeds
#define NH_MAX_PERSONALIZE_LEN      (1024)                          // 1024 bytes
#define NH_MIN_ENTROPY_LEN          (NH_MAX_SECURITY_STRENGTH/8)
#define NH_MAX_ENTROPY_LEN          (0xffffffff)                    // in bytes, 2^^32

struct ccdrbg_nisthmac_state {
    const struct ccdrbg_info *info;
	size_t bytesLeft;
    size_t reseed_counter;
    size_t vsize;
    size_t keysize;
    uint8_t v[NH_MAX_OUTPUT_BLOCK_SIZE];
    uint8_t key[NH_MAX_KEY_SIZE];
};

#ifdef DEBUGFOO
static void dumpState(const char *label, struct ccdrbg_nisthmac_state *state) {
    cc_print(label, state->vsize, state->v);
    cc_print(label, state->keysize, state->key);
}
#endif

/*
 NIST SP 800-90A, Rev. 1 HMAC_DRBG April 2014, p 46

 HMAC_DRBG_Update (provided_data, K, V):
 1. provided_data: The data to be used.
 2. K: The current value of Key.
 3. V: The current value of V.
 Output:
 1. K: The new value for Key.
 2. V: The new value for V.

 HMAC_DRBG Update Process:

 1. K = HMAC (K, V || 0x00 || provided_data).
 2. V=HMAC(K,V).
 3. If (provided_data = Null), then return K and V.
 4. K = HMAC (K, V || 0x01 || provided_data).
 5. V=HMAC(K,V).
 6. Return K and V.
 */

// was: unsigned long providedDataLength, const void *providedData

/*
 To handle the case where we have three strings that are concatenated,
 we pass in three (ptr, len) pairs
 */

static int hmac_dbrg_update(struct ccdrbg_state *drbg,
                            unsigned long daLen, const void *da,
                            unsigned long dbLen, const void *db,
                            unsigned long dcLen, const void *dc
                            )
{
    struct ccdrbg_nisthmac_state *state = (struct ccdrbg_nisthmac_state *)drbg;
    const struct ccdrbg_nisthmac_custom *custom = state->info->custom;
    const struct ccdigest_info *di = custom->di;

    const unsigned char cZero = 0x00;
    const unsigned char cOne  = 0x01;
    cchmac_ctx_decl(di->state_size, di->block_size, ctx);

    cchmac_init(di, ctx, state->keysize, state->key);
    // 1. K = HMAC (K, V || 0x00 || provided_data).
    cchmac_update(di, ctx, state->vsize, state->v);
    cchmac_update(di, ctx, 1, &cZero);
    if (da && daLen) cchmac_update(di, ctx, daLen, da);
    if (db && dbLen) cchmac_update(di, ctx, dbLen, db);
    if (dc && dcLen) cchmac_update(di, ctx, dcLen, dc);
    cchmac_final(di, ctx, state->key);

    //  2. V=HMAC(K,V).
    cchmac(di, state->keysize, state->key, state->vsize, state->v, state->v);

    // 3. If (provided_data = Null), then return K and V.
    // One parameter must be non-empty, or return
    if (!((da && daLen) || (db && dbLen) || (dc && dcLen)))
        return 0;

    // 4. K = HMAC (K, V || 0x01 || provided_data).
    cchmac_init(di, ctx, state->keysize, state->key);
    cchmac_update(di, ctx, state->vsize, state->v);
    cchmac_update(di, ctx, 1, &cOne);
    if (da && daLen) cchmac_update(di, ctx, daLen, da);
    if (db && dbLen) cchmac_update(di, ctx, dbLen, db);
    if (dc && dcLen) cchmac_update(di, ctx, dcLen, dc);
    cchmac_final(di, ctx, state->key);

    //  5. V=HMAC(K,V).
    cchmac(di, state->keysize, state->key, state->vsize, state->v, state->v);

    return 0;
}

/*
    NIST SP 800-90A, Rev. 1 April 2014 B.2.2, p 84

    HMAC_DRBG_Instantiate_algorithm (...):
    Input: bitstring (entropy_input, personalization_string). 
    Output: bitstring (V, Key), integer reseed_counter.

    Process:
    1. seed_material = entropy_input || personalization_string.
    2. Set Key to outlen bits of zeros.
    3. Set V to outlen/8 bytes of 0x01.
    4. (Key, V) = HMAC_DRBG_Update (seed_material, Key, V).
    5. reseed_counter = 1.
    6. Return (V, Key, reseed_counter).
*/

// This version does not do memory allocation

static int hmac_dbrg_instantiate_algorithm(struct ccdrbg_state *drbg,
                                           unsigned long entropyLength, const void *entropy,
                                           unsigned long nonceLength, const void *nonce,
                                           unsigned long psLength, const void *ps)
{
    // TODO: The NIST code passes nonce (i.e. HMAC key) to generate, but cc interface isn't set up that way

    struct ccdrbg_nisthmac_state *state=(struct ccdrbg_nisthmac_state *)drbg;

    // 1. seed_material = entropy_input || nonce || personalization_string.

    // 2. Set Key to outlen bits of zeros.
    cc_zero(state->keysize, state->key);

    // 3. Set V to outlen/8 bytes of 0x01.
    CC_MEMSET(state->v, 0x01, state->vsize);

    // 4. (Key, V) = HMAC_DRBG_Update (seed_material, Key, V).
    hmac_dbrg_update(drbg, entropyLength, entropy, nonceLength, nonce, psLength, ps);

    // 5. reseed_counter = 1.
    state->reseed_counter = 1;
    
    return 0;
}

//  In NIST terminology, the nonce is the HMAC key and ps is the personalization string

static int init(const struct ccdrbg_info *info, struct ccdrbg_state *drbg,
                unsigned long entropyLength, const void* entropy,
                unsigned long nonceLength, const void* nonce,
                unsigned long psLength, const void* ps)
{
    struct ccdrbg_nisthmac_state *state=(struct ccdrbg_nisthmac_state *)drbg;
    const struct ccdrbg_nisthmac_custom *custom = NULL;
    const struct ccdigest_info *di = NULL;
    size_t security_strength;
    size_t min_entropy;

    state->bytesLeft = 0;
    state->info = info;
    custom = state->info->custom;
    di = custom->di;
    state->vsize = di->output_size;    // TODO: state_size? or output_size
    state->keysize = di->output_size; // TODO: state size?

    security_strength = NH_MAX_SECURITY_STRENGTH;

    if (psLength > NH_MAX_PERSONALIZE_LEN)  // "Personalization_string too long"
        return hmac_dbrg_error(-1, "Personalization_string too long");

    if (entropyLength > NH_MAX_ENTROPY_LEN) // Supplied too much entropy
        return hmac_dbrg_error(-1, "Supplied too much entropy");

    // 4. min_entropy = 1.5 × security_strength.
    min_entropy = NH_REQUIRED_MIN_ENTROPY(security_strength);

    // 7. (V, Key, reseed_counter) = HMAC_DRBG_Instantiate_algorithm (entropy_input, personalization_string).

    hmac_dbrg_instantiate_algorithm(drbg, entropyLength, entropy, nonceLength, nonce, psLength, ps);
    
#ifdef DEBUGFOO
    dumpState("Init: ", state);
#endif
	return 0;
}

/*
    10.1.2.4 Reseeding an HMAC_DRBG Instantiation
    Notes for the reseed function specified in Section 9.2:
    The reseeding of an HMAC_DRBG instantiation requires a call to the Reseed_function specified in Section 9.2. 
    Process step 6 of that function calls the reseed algorithm specified in this section. The values for min_length 
    are provided in Table 2 of Section 10.1.

    The reseed algorithm:
    Let HMAC_DRBG_Update be the function specified in Section 10.1.2.2. The following process or its equivalent 
    shall be used as the reseed algorithm for this DRBG mechanism (see step 6 of the reseed process in Section 9.2):

    HMAC_DRBG_Reseed_algorithm (working_state, entropy_input, additional_input):
    1.  working_state: The current values for V, Key and reseed_counter (see Section 10.1.2.1).
    2.  entropy_input: The string of bits obtained from the source of entropy input.
    3.  additional_input: The additional input string received from the consuming application. 
        Note that the length of the additional_input string may be zero.

    Output:
    1.  new_working_state: The new values for V, Key and reseed_counter. HMAC_DRBG Reseed Process:
    1.  seed_material = entropy_input || additional_input.
    2.  (Key, V) = HMAC_DRBG_Update (seed_material, Key, V). 3. reseed_counter = 1.
    4.  Return V, Key and reseed_counter as the new_working_state.
*/

static int reseed(struct ccdrbg_state *drbg,
                  unsigned long entropyLength, const void *entropy,
                  unsigned long inputlen, const void *input)
{
    struct ccdrbg_nisthmac_state *state=(struct ccdrbg_nisthmac_state *)drbg;

    int rx = hmac_dbrg_update(drbg, entropyLength, entropy, inputlen, input, 0, NULL);
    state->reseed_counter = 1;

#ifdef DEBUGFOO
    dumpState("Reseed: ", state);
#endif
    return rx;
}

/*
    HMAC_DRBG_Generate_algorithm:
    Input: bitstring (V, Key), integer (reseed_counter, requested_number_of_bits). 
    Output: string status, bitstring (pseudorandom_bits, V, Key), integer reseed_counter.

    Process:
    1.      If (reseed_counter ≥ 10,000), then Return (“Reseed required”, Null, V, Key, reseed_counter).
    2.      temp = Null.
    3.      While (len (temp) < requested_no_of_bits) do:
    3.1         V = HMAC (Key, V).
    3.2         temp = temp || V.
    4.      pseudorandom_bits = Leftmost (requested_no_of_bits) of temp.
    5.      (Key, V) = HMAC_DRBG_Update (Null, Key, V).
    6.      reseed_counter = reseed_counter + 1.
    7.      Return (“Success”, pseudorandom_bits, V, Key, reseed_counter).
*/

static int generate(struct ccdrbg_state *drbg, unsigned long numBytes, void *outBytes,
                    unsigned long inputLen, const void *input)
{
    struct ccdrbg_nisthmac_state *state = (struct ccdrbg_nisthmac_state *)drbg;
    const struct ccdrbg_nisthmac_custom *custom = state->info->custom;
    const struct ccdigest_info *di = custom->di;

    if (numBytes > NH_MAX_BYTES_PER_REQUEST)
        return hmac_dbrg_error(CCDRBG_STATUS_PARAM_ERROR,
			       "Requested too many bytes in one request");

    // 1. If (reseed_counter > 2^^48), then Return (“Reseed required”, Null, V, Key, reseed_counter).
    if (state->reseed_counter > NH_RESEED_INTERVAL)
        return hmac_dbrg_error(CCDRBG_STATUS_NEED_RESEED, "Reseed required");

    // 2. If additional_input ≠ Null, then (Key, V) = HMAC_DRBG_Update (additional_input, Key, V).
    if (input && inputLen)
        hmac_dbrg_update(drbg, inputLen, input, 0, NULL, 0, NULL);

    // hmac_dbrg_generate_algorithm
    char *outPtr = (char *) outBytes;
    while (numBytes > 0) {
        if (!state->bytesLeft) {
            //  5. V=HMAC(K,V).
            cchmac(di, state->keysize, state->key, state->vsize, state->v, state->v);
            state->bytesLeft = di->output_size;//di->output_size;  state->vsize
        }
        size_t outLength = numBytes > state->bytesLeft ? state->bytesLeft : numBytes;
        memcpy(outPtr, state->v, outLength);
        state->bytesLeft -= outLength;
        outPtr += outLength;
        numBytes -= outLength;
    }

    // 6. (Key, V) = HMAC_DRBG_Update (additional_input, Key, V).
    hmac_dbrg_update(drbg, inputLen, input, 0, NULL, 0, NULL);

    // 7. reseed_counter = reseed_counter + 1.
    state->reseed_counter++;

#ifdef DEBUGFOO
    dumpState("generate: ", state);
#endif
    
    return 0;
}

static void done(struct ccdrbg_state *drbg)
{
    struct ccdrbg_nisthmac_state *state=(struct ccdrbg_nisthmac_state *)drbg;
    cc_zero(sizeof(state->v), state->v);
    cc_zero(sizeof(state->key), state->key);
}

struct ccdrbg_info ccdrbg_nisthmac_info = {
    .size = sizeof(struct ccdrbg_nisthmac_state) + sizeof(struct ccdrbg_nisthmac_custom),
    .init = init,
    .reseed = reseed,
    .generate = generate,
    .done = done,
    .custom = NULL
};

/* This initializes an info object with the right options */
void ccdrbg_factory_nisthmac(struct ccdrbg_info *info, const struct ccdrbg_nisthmac_custom *custom)
{
    info->size = sizeof(struct ccdrbg_nisthmac_state) + sizeof(struct ccdrbg_nisthmac_custom);
    info->init = init;
    info->generate = generate;
    info->reseed = reseed;
    info->done = done;
    info->custom = custom;
};

