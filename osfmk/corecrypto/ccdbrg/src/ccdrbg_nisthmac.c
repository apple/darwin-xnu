/*
 *  ccdrbg_nisthmac.c
 *  corecrypto
 *
 *  Created on 05/09/2014
 *
 *  Copyright (c) 2014,2015 Apple Inc. All rights reserved.
 *
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_START@
 *
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. The rights granted to you under the License
 * may not be used to create, or enable the creation or redistribution of,
 * unlawful or unlicensed copies of an Apple operating system, or to
 * circumvent, violate, or enable the circumvention or violation of, any
 * terms of an Apple operating system software license agreement.
 *
 * Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this file.
 *
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_END@
 */

#include <corecrypto/ccdrbg.h>
#include <corecrypto/cchmac.h>
#include <corecrypto/ccsha2.h>
#include <corecrypto/cc_priv.h>
#include <corecrypto/cc_macros.h>

// Test vectors at:
//      http://csrc.nist.gov/groups/STM/cavp/#05
//      http://csrc.nist.gov/groups/STM/cavp/documents/drbg/drbgtestvectors.zip
//

/*
 This HMAC DBRG is described in:

 SP 800-90 A Rev. 1 (2nd Draft)
 DRAFT Recommendation for Random Number Generation Using Deterministic Random Bit Generators
 April 2014


 See in particular
 - 10.1.2 HMAC_DRBG (p 45)
 - B.2 HMAC_DRBGExample (p 83)

 We support maximum security strength of 256 bits
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

#define NH_MAX_OUTPUT_BLOCK_SIZE    (CCSHA512_OUTPUT_SIZE)          // 512 bits, i.e. 64 bytes (CCSHA512_OUTPUT_SIZE)
#define NH_MAX_KEY_SIZE             (CCSHA512_OUTPUT_SIZE)          // 512 bits, i.e. 64 bytes (CCSHA512_OUTPUT_SIZE)

#define MIN_REQ_ENTROPY(di)            ((di)->output_size/2)

struct ccdrbg_nisthmac_state {
    const struct ccdrbg_nisthmac_custom *custom; //ccdrbg_nisthmac_state does not need to store ccdrbg_info. ccdrbg_nisthmac_custom is sufficient
    size_t bytesLeft;
    uint64_t reseed_counter; // the reseed counter should be able to hole 2^^48. size_t might be smaller than 48 bits
    size_t  vsize;
    size_t  keysize;
    uint8_t v[2*NH_MAX_OUTPUT_BLOCK_SIZE];
    uint8_t *vptr;
    uint8_t *nextvptr;
    uint8_t key[NH_MAX_KEY_SIZE];
};

#define DRBG_NISTHMAC_DEBUG 0


#if DRBG_NISTHMAC_DEBUG
#include "cc_debug.h"

static void dumpState(const char *label, struct ccdrbg_nisthmac_state *state) {
    //cc_print(label, state->vsize, state->nextvptr);
    cc_print(label, state->vsize, state->vptr);
    cc_print(label, state->keysize, state->key);
}
#endif


static void done(struct ccdrbg_state *drbg);

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

// was: size_t providedDataLength, const void *providedData

/*
 To handle the case where we have three strings that are concatenated,
 we pass in three (ptr, len) pairs
 */

static int hmac_dbrg_update(struct ccdrbg_state *drbg,
                            size_t daLen, const void *da,
                            size_t dbLen, const void *db,
                            size_t dcLen, const void *dc
                            )
{
    int rc=CCDRBG_STATUS_ERROR;
    struct ccdrbg_nisthmac_state *state = (struct ccdrbg_nisthmac_state *)drbg;
    const struct ccdigest_info *di = state->custom->di;

    const unsigned char cZero = 0x00;
    const unsigned char cOne  = 0x01;

    cchmac_ctx_decl(di->state_size, di->block_size, ctx);
    cchmac_init(di, ctx, state->keysize, state->key);

    // 1. K = HMAC (K, V || 0x00 || provided_data).
    cchmac_update(di, ctx, state->vsize, state->vptr);
    cchmac_update(di, ctx, 1, &cZero);
    if (da && daLen) cchmac_update(di, ctx, daLen, da);
    if (db && dbLen) cchmac_update(di, ctx, dbLen, db);
    if (dc && dcLen) cchmac_update(di, ctx, dcLen, dc);
    cchmac_final(di, ctx, state->key);

    // One parameter must be non-empty, or return
    if (((da && daLen) || (db && dbLen) || (dc && dcLen))) {
        //  2. V=HMAC(K,V).
        cchmac(di, state->keysize, state->key, state->vsize, state->vptr, state->vptr);
        //  4. K = HMAC (K, V || 0x01 || provided_data).
        cchmac_init(di, ctx, state->keysize, state->key);
        cchmac_update(di, ctx, state->vsize, state->vptr);
        cchmac_update(di, ctx, 1, &cOne);
        if (da && daLen) cchmac_update(di, ctx, daLen, da);
        if (db && dbLen) cchmac_update(di, ctx, dbLen, db);
        if (dc && dcLen) cchmac_update(di, ctx, dcLen, dc);
        cchmac_final(di, ctx, state->key);
    }
    //  If additional data 5. V=HMAC(K,V)
    //  If no addtional data, this is step 2. V=HMAC(K,V).
    state->bytesLeft = 0;

    // FIPS 140-2 4.9.2 Conditional Tests
    // "the first n-bit block generated after power-up, initialization, or reset shall not be used, but shall be saved for comparison with the next n-bit block to be generated"
    // Generate the first block and the second block. Compare for FIPS and discard the first block
    // We keep the second block as the first set of data to be returned
    cchmac(di, state->keysize, state->key, state->vsize, state->vptr, state->vptr);     // First block
    cchmac(di, state->keysize, state->key, state->vsize, state->vptr, state->nextvptr); // First to be returned
    if (0==cc_cmp_safe(state->vsize, state->vptr, state->nextvptr)) {
        //The world as we know it has come to an end
        //the DRBG data structure is zeroized. subsequent calls to
        //DRBG ends up in NULL dereferencing and/or unpredictable state.
        //catastrophic error in SP 800-90A
        done(drbg);
        rc=CCDRBG_STATUS_ABORT;
        cc_try_abort(NULL);
        goto errOut;
    }
    rc=CCDRBG_STATUS_OK;
errOut:
    return rc;
}

//make sure state is initialized, before calling this function
static int validate_inputs(struct ccdrbg_nisthmac_state *state,
                           size_t entropyLength,
                           size_t additionalInputLength,
                           size_t psLength)
{
    int rc;
    const struct ccdrbg_nisthmac_custom *custom=state->custom;
    const struct ccdigest_info *di  = custom->di;

    rc =CCDRBG_STATUS_ERROR;
    //buffer size checks
    cc_require (di->output_size<=sizeof(state->v)/2, end); //digest size too long
    cc_require (di->output_size<=sizeof(state->key), end); //digest size too long

    //NIST SP800 compliance checks
    //the following maximum checks are redundant if long is 32 bits.

    rc=CCDRBG_STATUS_PARAM_ERROR;
    cc_require (psLength <= CCDRBG_MAX_PSINPUT_SIZE, end); //personalization string too long
    cc_require (entropyLength <= CCDRBG_MAX_ENTROPY_SIZE, end); //supplied too much entropy
    cc_require (additionalInputLength <= CCDRBG_MAX_ADDITIONALINPUT_SIZE, end); //additional input too long
    cc_require (entropyLength >=  MIN_REQ_ENTROPY(di), end); //supplied too litle entropy

    cc_require(di->output_size<=NH_MAX_OUTPUT_BLOCK_SIZE, end); //the requested security strength is not supported

    rc=CCDRBG_STATUS_OK;
end:
    return rc;
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
//SP800-90 A: Required minimum entropy for instantiate and reseed=security_strength

static int hmac_dbrg_instantiate_algorithm(struct ccdrbg_state *drbg,
                                           size_t entropyLength, const void *entropy,
                                           size_t nonceLength, const void *nonce,
                                           size_t psLength, const void *ps)
{
    // TODO: The NIST code passes nonce (i.e. HMAC key) to generate, but cc interface isn't set up that way
    struct ccdrbg_nisthmac_state *state = (struct ccdrbg_nisthmac_state *)drbg;

    // 1. seed_material = entropy_input || nonce || personalization_string.

    // 2. Set Key to outlen bits of zeros.
    cc_zero(state->keysize, state->key);

    // 3. Set V to outlen/8 bytes of 0x01.
    CC_MEMSET(state->vptr, 0x01, state->vsize);

    // 4. (Key, V) = HMAC_DRBG_Update (seed_material, Key, V).
    hmac_dbrg_update(drbg, entropyLength, entropy, nonceLength, nonce, psLength, ps);

    // 5. reseed_counter = 1.
    state->reseed_counter = 1;

    return CCDRBG_STATUS_OK;
}

//  In NIST terminology, the nonce is the HMAC key and ps is the personalization string
//  We assume that the caller has passed in
//      min_entropy = NH_REQUIRED_MIN_ENTROPY(security_strength)
//  bytes of entropy

static int init(const struct ccdrbg_info *info, struct ccdrbg_state *drbg,
                size_t entropyLength, const void* entropy,
                size_t nonceLength, const void* nonce,
                size_t psLength, const void* ps)
{
    struct ccdrbg_nisthmac_state *state=(struct ccdrbg_nisthmac_state *)drbg;
    state->bytesLeft = 0;
    state->custom = info->custom; //we only need to get the custom parameter from the info structure.

    int rc = validate_inputs(state , entropyLength, 0, psLength);
    if(rc!=CCDRBG_STATUS_OK){
        //clear everything if cannot initialize. The idea is that if the caller doesn't check the output of init() and init() fails,
        //the system crashes by NULL dereferencing after a call to generate, rather than generating bad random numbers.
        done(drbg);
        return rc;
    }

    const struct ccdigest_info *di = state->custom->di;
    state->vsize = di->output_size;
    state->keysize = di->output_size;
    state->vptr=state->v;
    state->nextvptr=state->v+state->vsize;

    // 7. (V, Key, reseed_counter) = HMAC_DRBG_Instantiate_algorithm (entropy_input, personalization_string).
    hmac_dbrg_instantiate_algorithm(drbg, entropyLength, entropy, nonceLength, nonce, psLength, ps);

#if DRBG_NISTHMAC_DEBUG
    dumpState("Init: ", state);
#endif
    return CCDRBG_STATUS_OK;

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

static int
reseed(struct ccdrbg_state *drbg,
       size_t entropyLength, const void *entropy,
       size_t additionalLength, const void *additional)
{

    struct ccdrbg_nisthmac_state *state = (struct ccdrbg_nisthmac_state *)drbg;
    int rc = validate_inputs(state, entropyLength, additionalLength, 0);
    if(rc!=CCDRBG_STATUS_OK) return rc;

    int rx = hmac_dbrg_update(drbg, entropyLength, entropy, additionalLength, additional, 0, NULL);
    state->reseed_counter = 1;

#if DRBG_NISTHMAC_DEBUG
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

static int validate_gen_params(uint64_t reseed_counter,  size_t dataOutLength, size_t additionalLength)

{
    int rc=CCDRBG_STATUS_PARAM_ERROR;

    // Zero byte in one request is a valid use-case (21208820)
    cc_require (dataOutLength <= CCDRBG_MAX_REQUEST_SIZE, end); //Requested too many bytes in one request
    cc_require (additionalLength<=CCDRBG_MAX_ADDITIONALINPUT_SIZE, end); //Additional input too long

    // 1. If (reseed_counter > 2^^48), then Return (“Reseed required”, Null, V, Key, reseed_counter).
     rc = CCDRBG_STATUS_NEED_RESEED;
     cc_require (reseed_counter <= CCDRBG_RESEED_INTERVAL, end); //Reseed required

    rc=CCDRBG_STATUS_OK;

end:
    return rc;
}

static int generate(struct ccdrbg_state *drbg, size_t dataOutLength, void *dataOut,
                    size_t additionalLength, const void *additional)
{
    struct ccdrbg_nisthmac_state *state = (struct ccdrbg_nisthmac_state *)drbg;
    const struct ccdrbg_nisthmac_custom *custom = state->custom;
    const struct ccdigest_info *di = custom->di;

    int rc = validate_gen_params(state->reseed_counter, dataOutLength, additional==NULL?0:additionalLength);
    if(rc!=CCDRBG_STATUS_OK) return rc;

    // 2. If additional_input ≠ Null, then (Key, V) = HMAC_DRBG_Update (additional_input, Key, V).
    if (additional && additionalLength)
        hmac_dbrg_update(drbg, additionalLength, additional, 0, NULL, 0, NULL);

    // hmac_dbrg_generate_algorithm
    char *outPtr = (char *) dataOut;
    while (dataOutLength > 0) {
        if (!state->bytesLeft) {
            //  5. V=HMAC(K,V).
            cchmac(di, state->keysize, state->key, state->vsize, state->nextvptr, state->vptr);        // Won't be returned
            // FIPS 140-2 4.9.2 Conditional Tests
            // "Each subsequent generation of an n-bit block shall be compared with the previously generated block. The test shall fail if any two compared n-bit blocks are equal."
            if (0==cc_cmp_safe(state->vsize, state->vptr, state->nextvptr)) {
                //The world as we know it has come to an end
                //the DRBG data structure is zeroized. subsequent calls to
                //DRBG ends up in NULL dereferencing and/or unpredictable state.
                //catastrophic error in SP 800-90A
                done(drbg);
                rc=CCDRBG_STATUS_ABORT;
                cc_try_abort(NULL);
                goto errOut;
            }
            CC_SWAP(state->nextvptr, state->vptr);
            state->bytesLeft = state->vsize;
#if DRBG_NISTHMAC_DEBUG
            cc_print("generate blk: ", state->vsize, state->vptr);
#endif
        }
        size_t outLength = dataOutLength > state->bytesLeft ? state->bytesLeft : dataOutLength;
        CC_MEMCPY(outPtr, state->vptr, outLength);
        state->bytesLeft -= outLength;
        outPtr += outLength;
        dataOutLength -= outLength;
    }

    // 6. (Key, V) = HMAC_DRBG_Update (additional_input, Key, V).
    hmac_dbrg_update(drbg, additionalLength, additional, 0, NULL, 0, NULL);

    // 7. reseed_counter = reseed_counter + 1.
    state->reseed_counter++;

#if DRBG_NISTHMAC_DEBUG
    dumpState("generate end: ", state);
    cc_print("generate end nxt: ", state->vsize, state->nextvptr);
#endif
    rc=CCDRBG_STATUS_OK;
errOut:
    return rc;
}

static void done(struct ccdrbg_state *drbg)
{
    struct ccdrbg_nisthmac_state *state=(struct ccdrbg_nisthmac_state *)drbg;
    cc_clear(sizeof(struct ccdrbg_nisthmac_state), state); //clear v, key as well as internal variables
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
