/* Copyright (c) (2015,2016,2017,2018,2019) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to 
 * people who accept that license. IMPORTANT:  Any license rights granted to you by 
 * Apple Inc. (if any) are limited to internal use within your organization only on 
 * devices and computers you own or control, for the sole purpose of verifying the 
 * security characteristics and correct functioning of the Apple Software.  You may 
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#ifndef _CORECRYPTO_CCMODE_SIV_H_
#define _CORECRYPTO_CCMODE_SIV_H_

#include <corecrypto/cc.h>
#include <corecrypto/ccmode.h>
#include <corecrypto/ccmode_impl.h>

#include <corecrypto/cccmac.h>

/* This provide an implementation of SIV
 as specified in https://tools.ietf.org/html/rfc5297
 also in http://csrc.nist.gov/groups/ST/toolkit/BCM/documents/proposedmodes/siv/siv.pdf
 Counter Mode where IV is based on CMAC
 */

cc_aligned_struct(16) ccsiv_ctx;

struct ccmode_siv {
    size_t size;        /* first argument to ccsiv_ctx_decl(). */
    size_t block_size;
    int (*init)(const struct ccmode_siv *siv, ccsiv_ctx *ctx,
                 size_t key_len, const uint8_t *key);
    int (*set_nonce)(ccsiv_ctx *ctx,  size_t nbytes, const uint8_t *in);  // could just be ccm with NULL out
    int (*auth)(ccsiv_ctx *ctx,  size_t nbytes, const uint8_t *in);  // could just be ccm with NULL out
    int (*crypt)(ccsiv_ctx *ctx, size_t nbytes, const uint8_t *in, uint8_t *out);
    int (*reset)(ccsiv_ctx *ctx);
    const struct ccmode_cbc *cbc;
    const struct ccmode_ctr *ctr;
};

#define ccsiv_ctx_decl(_size_, _name_)  cc_ctx_decl(ccsiv_ctx, _size_, _name_)
#define ccsiv_ctx_clear(_size_, _name_) cc_clear(_size_, _name_)

// Functions

CC_INLINE size_t ccsiv_context_size(const struct ccmode_siv *mode)
{
    return mode->size;
}

/*!
@function ccsiv_block_size
@abstract Return the block_size = block_length = tag_length used in the mode.

@param      mode               ccsiv mode descriptor

@discussion     Used to return the current block size of the SIV mode. Note that the tag in this mode is an output of the underlying blockcipher and therefore the tag length corresponds to the block size.
*/
CC_INLINE size_t ccsiv_block_size(const struct ccmode_siv *mode)
{
    return mode->block_size;
}

/*!
 @function   ccsiv_ciphertext_size
 @abstract   Return size of Ciphertext (which is the ciphertext and corresponding tag) given the mode and plaintext length

 @param      mode               ccsiv mode descriptor
 @param      plaintext_size    Size of the plaintext

 @discussion returns the length of the aead ciphertext that the context will generate which includes both the encrypted plaintext and tag.
 */
CC_INLINE size_t ccsiv_ciphertext_size(const struct ccmode_siv *mode,
                                       size_t plaintext_size)
{
    return plaintext_size + mode->cbc->block_size;
}

/*!
 @function   ccsiv_plaintext_size
 @abstract   Return size of plaintext given a ciphertext length and mode.

 @param      mode                 ccsiv mode descriptor
 @param      ciphertext_size     Size of the ciphertext

 @discussion returns the length of the plaintext which results from the decryption of a ciphertext of the corresponding size (here ciphertext size includes the tag).
 */

CC_INLINE size_t ccsiv_plaintext_size(const struct ccmode_siv *mode,
                                       size_t ciphertext_size)
{
    if (ciphertext_size<mode->cbc->block_size) {
        return 0; // error
    }
    return ciphertext_size - mode->cbc->block_size;
}

/*!
 @function   ccsiv_init
 @abstract   Initialize a context for ccsiv with an associated mode, and given key.

 @param      mode               Descriptor for the mode
 @param      ctx                Alocated context to be intialized
 @param      key_byte_len       Length of the key:  Supported key sizes are 32, 48, 64 bytes.
 @param      key                key for siv. All bits of this key should be random. (See discussion)

 @discussion In order to  compute SIV_Enc_k(a1,...,am, n, x) where ai is the ith piece of associated data, n is a nonce and x  is a plaintext, we use the following sequence of calls :


 @code
 ccsiv_init(...)
 ccsiv_aad(...)       (may be called zero or more times)
 ccsiv_set_nonce(...)
 ccsiv_crypt(...)
 @endcode

 To reuse the context for additional encryptions, follow this sequence:

 @code
 ccsiv_reset(...)
 ccsiv_aad(...)       (may be called zero or more times)
 ccsiv_set_nonce(...)
 ccsiv_crypt(...)
 @endcode

Importantly, all the bits in the key need to be random. Duplicating a smaller key to achieve a longer key length will result in an insecure implementation.
 */
CC_INLINE int ccsiv_init(const struct ccmode_siv *mode, ccsiv_ctx *ctx,
                          size_t key_byte_len, const uint8_t *key)
{
    return mode->init(mode, ctx, key_byte_len, key);
}

/*!
 @function   ccsiv_set_nonce
 @abstract   Add the nonce to the siv's computation of the the tag. Changes the internal state of the context
 so that after the call only a crypt or reset call is permitted.

 @param      mode               Descriptor for the mode
 @param      ctx                Intialized ctx
 @param      nbytes             Length of the current nonce data being added
 @param      in                 Nonce data to be authenticated.

 @discussion The nonce is a special form of authenticated data. If provided (a call to ccsiv_set_nonce is optional) it allows
 randomization of the ciphertext (preventing deterministic encryption). While the length of the nonce is not limmited, the
 amount of entropy that can be provided is limited by the number of bits in the block of the associated block-cipher.
 */
CC_INLINE int ccsiv_set_nonce(const struct ccmode_siv *mode, ccsiv_ctx *ctx,
                         size_t nbytes, const uint8_t *in)
{
    return mode->set_nonce(ctx, nbytes, in);
}

/*!
 @function   ccsiv_aad
 @abstract   Add the next piece of associated data to the SIV's computation of the tag.
 @param      mode               Descriptor for the mode
 @param      ctx                Intialized ctx
 @param      nbytes             Length of the current associated data being added
 @param      in                 Associated data to be authenticated.

 @discussion Adds the associated data given by in to the computation of the tag in the associated data. Note this call is optional and no  associated data needs to be provided. Multiple pieces of associated data can be provided by multiple calls to this  function. Note the associated data in this case is simply computed as the concatenation of all of the associated data inputs.
 */
CC_INLINE int ccsiv_aad(const struct ccmode_siv *mode, ccsiv_ctx *ctx,
                            size_t nbytes, const uint8_t *in)
{
    return mode->auth(ctx, nbytes, in);
}

/*!
 @function   ccsiv_crypt
 @abstract Depdening on mode, 1) Encrypts a plaintext , or 2) Decrypts a ciphertext

 @param      mode               Descriptor for the mode
 @param      ctx                Intialized ctx
 @param      nbytes             Case 1) Length of the current plaintext
                                Case 2) Length of the current ciphertext (block length + plaintext length).
 @param      in                 Case 1) Plaintext
                                Case 2) Ciphertext
 @param     out                 Case 1) Tag+ciphertext (buffer should be already allocated and of length block_length+plaintext_length.)
                                Case 2) Plaintext (buffer should be already allocated and of length ciphertext_length - block_length length

 @discussion Depending on whether mode has been setup to encrypt or decrypt, this function
 1) Encrypts the plaintext given as input in, and provides the ciphertext (which is a concatenation of the cbc-tag
 followed by the encrypted plaintext) as output out. 2) Decrypts plaintext using the input ciphertext at in (which again is the  cbc-tag, followed by encrypted plaintext), and then verifies that the computed tag and provided tags match.

 This function is only called once. If one wishes to compute another (en)/(de)cryption, one resets the state with
 ccsiv_reset, and then begins the process again. There is no way to stream large plaintext/ciphertext inputs into the
 function.

 In the case of a decryption, if there is a failure in verifying the computed tag against the provided tag (embedded int he ciphertext), then a decryption/verification
 failure is returned, and any internally computed plaintexts and tags are zeroed out.
 Lastly the contexts internal state is reset, so that a new decryption/encryption can be commenced.

 Decryption can be done in place in memory by setting in=out. Encryption cannot be done in place. However, if one is trying to minimize memory usage one can set out = in - block_length, which results in the ciphertext being encrypted inplace, and the IV being prepended before the ciphertext.
 */
CC_INLINE int ccsiv_crypt(const struct ccmode_siv *mode, ccsiv_ctx *ctx,
                            size_t nbytes, const uint8_t *in, uint8_t *out)
{
    return mode->crypt(ctx, nbytes, in, out);
}

/*!
 @function   ccsiv_reset
 @abstract   Resets the state of the ccsiv_ctx ctx, maintaing the key, but preparing the
 ctx to preform a new Associated Data Authenticated (En)/(De)cryption.
 @param      mode               Descriptor for the mode
 @param      ctx                Intialized ctx
 */
CC_INLINE int ccsiv_reset(const struct ccmode_siv *mode, ccsiv_ctx *ctx)
{
    return mode->reset(ctx);
}

/*!
 @function   ccsiv_one_shot
 @abstract   A simplified but more constrained way of performing a AES SIV (en)/(de)cryption. It is limited because only
 one piece of associated data may be provided.

 @param      mode               Descriptor for the mode
 @param      key_len            Length of the key:  Supported key sizes are 32, 48, 64 bytes
 @param      key                key for siv
 @param      nonce_nbytes       Length of the current nonce data being added
 @param      nonce              Nonce data to be authenticated.
 @param      adata_nbytes       Length of the associated data.
 @param      adata              Associated data to be authenticated.
 @param      in_nbytes          Length of either the plaintext (for encryption) or ciphertext (for decryption), in the latter case the length includes the length of the tag.
 @param      in                 Plaintext or ciphertext. Note that the ciphertext includes a tag of length tag_length prepended to it.
 @param      out                Buffer to hold ciphertext/plaintext. (Note Ciphertext is of size plaintext_length + block_length and plaintext is of ciphertext_length - block_length, as the tag has the length of one block.
                                Must be the case that out<= in - block length || out>= in + plaintext_length

 @discussion Decryption can be done in place in memory by setting in=out. Encryption cannot be done in place. However, is one is trying to minimize memory usage
 one can set out = in - block_length, which results in the ciphertext being encrypted inplace, and the IV being prepended before the ciphertext.

 Suppose the block length is 16 bytes long (AES) and plaintext of length 20, then we could set in = 16, out = 0 let the bytes of the plaintext be denoted as P_1...P_20
 then memory is depicted as:
            | 0 = ? | 1 = ?  | ... | 15 = ? | 16 = P_1 | ... | 35 = P_20 |
                |       |             |         |                |
                V       V             V         V                V
            |IV_1  | IV_2  | ... | IV_16    |   C_1    | ... |  C_20      |

Note that the ciphrtext itself is encrypted in place, but the IV prefixes the ciphertext.


 */

CC_INLINE int ccsiv_one_shot(const struct ccmode_siv *mode,
                              size_t key_len, const uint8_t *key,
                              unsigned nonce_nbytes, const uint8_t* nonce,
                              unsigned adata_nbytes, const uint8_t* adata,
                              size_t in_nbytes, const uint8_t *in, uint8_t *out)
{
    int rc;
    ccsiv_ctx_decl(mode->size, ctx);
    rc=mode->init(mode, ctx, key_len, key);
    if (rc) {return rc;}
    rc=mode->set_nonce(ctx, nonce_nbytes, nonce);
    if (rc) {return rc;}
    rc=mode->auth(ctx, adata_nbytes, adata);
    if (rc) {return rc;}
    rc=mode->crypt(ctx, in_nbytes, in, out);
    if (rc) {return rc;}
    ccsiv_ctx_clear(mode->size, ctx);
    return rc;
}

#endif /* _CORECRYPTO_CCMODE_H_ */
