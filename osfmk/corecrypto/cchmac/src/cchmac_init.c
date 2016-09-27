/*
 *  cchmac_init.c
 *  corecrypto
 *
 *  Created on 12/07/2010
 *
 *  Copyright (c) 2010,2011,2015 Apple Inc. All rights reserved.
 *
 */

#include <corecrypto/cchmac.h>
#include <corecrypto/ccn.h>
#include <corecrypto/cc_priv.h>

/* The HMAC_<DIG> transform looks like:
   <DIG> (K XOR opad || <DIG> (K XOR ipad || text))
   Where K is a n byte key
   ipad is the byte 0x36 repeated 64 times.
   opad is the byte 0x5c repeated 64 times.
   text is the data being protected.
 */
void cchmac_init(const struct ccdigest_info *di, cchmac_ctx_t hc,
                 size_t key_len, const void *key_data) {
    const unsigned char *key = key_data;

    /* Set cchmac_data(di, hc) to key ^ opad. */
    size_t byte = 0;
	if (key_len <= di->block_size) {
        for (;byte < key_len; ++byte) {
            cchmac_data(di, hc)[byte] = key[byte] ^ 0x5c;
        }
    } else {
        /* Key is longer than di->block size, reset it to key=digest(key) */
        ccdigest_init(di, cchmac_digest_ctx(di, hc));
        ccdigest_update(di, cchmac_digest_ctx(di, hc), key_len, key);
        ccdigest_final(di, cchmac_digest_ctx(di, hc), cchmac_data(di, hc));
        key_len = di->output_size;
        for (;byte < key_len; ++byte) {
            cchmac_data(di, hc)[byte] ^= 0x5c;
        }
    }
    /* Fill remainder of cchmac_data(di, hc) with opad. */
	if (key_len < di->block_size) {
		CC_MEMSET(cchmac_data(di, hc) + key_len, 0x5c, di->block_size - key_len);
	}

    /* Set cchmac_ostate32(di, hc) to the state of the first round of the
       outer digest. */
    ccdigest_copy_state(di, cchmac_ostate32(di, hc), di->initial_state);
    di->compress(cchmac_ostate(di, hc), 1, cchmac_data(di, hc));

    /* Set cchmac_data(di, hc) to key ^ ipad. */
    for (byte = 0; byte < di->block_size; ++byte) {
        cchmac_data(di, hc)[byte] ^= (0x5c ^ 0x36);
    }
    ccdigest_copy_state(di, cchmac_istate32(di, hc), di->initial_state);
    di->compress(cchmac_istate(di, hc), 1, cchmac_data(di, hc));
    cchmac_num(di, hc) = 0;
    cchmac_nbits(di, hc) = di->block_size * 8;
}
