/*
 *  ccpad.h
 *  corecrypto
 *
 *  Created by Michael Brouwer on 12/6/10.
 *  Copyright 2010,2011 Apple Inc. All rights reserved.
 *
 */

#ifndef _CORECRYPTO_CCPAD_H_
#define _CORECRYPTO_CCPAD_H_

#include <corecrypto/ccmode.h>

/* Contract is nbytes is at least 1 block + 1 byte.  Also in is nbytes long out is nbytes long. */
void ccpad_cts_decrypt(const struct ccmode_cbc *cbc, cccbc_ctx *ctx,
                       unsigned long nbytes, const void *in, void *out);

/* Contract is nbytes is at least 1 block + 1 byte.  Also in is nbytes long out is nbytes long. */
void ccpad_cts_encrypt(const struct ccmode_cbc *cbc, cccbc_ctx *ctx,
                       unsigned long nbytes, const void *in, void *out);

/* Contract is nbytes is at least 1 block + 1 byte.  Also in is nbytes long out is nbytes long. */
void ccpad_cts1_decrypt(const struct ccmode_cbc *cbc, cccbc_ctx *ctx,
                       unsigned long nbytes, const void *in, void *out);

/* Contract is nbytes is at least 1 block + 1 byte.  Also in is nbytes long out is nbytes long. */
void ccpad_cts1_encrypt(const struct ccmode_cbc *cbc, cccbc_ctx *ctx,
                       unsigned long nbytes, const void *in, void *out);
/* Contract is nbytes is at least 1 block + 1 byte.  Also in is nbytes long out is nbytes long. */
void ccpad_cts2_decrypt(const struct ccmode_cbc *cbc, cccbc_ctx *ctx,
                       unsigned long nbytes, const void *in, void *out);

/* Contract is nbytes is at least 1 block + 1 byte.  Also in is nbytes long out is nbytes long. */
void ccpad_cts2_encrypt(const struct ccmode_cbc *cbc, cccbc_ctx *ctx,
                       unsigned long nbytes, const void *in, void *out);
/* Contract is nbytes is at least 1 block + 1 byte.  Also in is nbytes long out is nbytes long. */
void ccpad_cts3_decrypt(const struct ccmode_cbc *cbc, cccbc_ctx *ctx,
                       unsigned long nbytes, const void *in, void *out);

/* Contract is nbytes is at least 1 block + 1 byte.  Also in is nbytes long out is nbytes long. */
void ccpad_cts3_encrypt(const struct ccmode_cbc *cbc, cccbc_ctx *ctx,
                       unsigned long nbytes, const void *in, void *out);

/* Contract is nbytes is non zero and a multiple of block_size. Furthermore in is nbytes long and out is nbytes long.  Returns number of bytes written to out (technically we always write nbytes to out but the returned value is the number of bytes decrypted after removal of padding.

    To be safe we remove the entire offending block if the pkcs7 padding checks failed.  However we purposely don't report the failure to decode the padding since any use of this error leads to potential security exploits.  So currently there is no way to distinguish between a full block of padding and bad padding.
 */
unsigned long ccpad_pkcs7_decrypt(const struct ccmode_cbc *cbc, cccbc_ctx *ctx,
                                  unsigned long nbytes, const void *in,
                                  void *out);

/* Contract is in is nbytes long.  Writes (nbytes / block_size) + 1 times block_size to out.  In other words, out must be nbytes rounded down to the closest multiple of block_size plus block_size bytes. */
void ccpad_pkcs7_encrypt(const struct ccmode_cbc *cbc, cccbc_ctx *ctx,
                         unsigned long nbytes, const void *in, void *out);

/* Contract is nbytes is at least 1 block + 1 byte.  Also in is nbytes long out is nbytes long. */
void ccpad_xts_decrypt(const struct ccmode_xts *xts, ccxts_ctx *ctx,
                       unsigned long nbytes, const void *in, void *out);

/* Contract is nbytes is at least 1 block + 1 byte.  Also in is nbytes long out is nbytes long. */
void ccpad_xts_encrypt(const struct ccmode_xts *xts, ccxts_ctx *ctx,
                       unsigned long nbytes, const void *in, void *out);

#endif /* _CORECRYPTO_CCPAD_H_ */
