/*
 *  cchmac.c
 *  corecrypto
 *
 *  Created by Michael Brouwer on 12/7/10.
 *  Copyright 2010,2011 Apple Inc. All rights reserved.
 *
 */

#include <corecrypto/cchmac.h>

void cchmac(const struct ccdigest_info *di,
            unsigned long key_len, const void *key,
            unsigned long data_len, const void *data, unsigned char *mac) {
    cchmac_di_decl(di, hc);
    cchmac_init(di, hc, key_len, key);
    cchmac_update(di, hc, data_len, data);
    cchmac_final(di, hc, mac);
	cchmac_di_clear(di, hc);
}
