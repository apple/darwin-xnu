/*
 * Copyright (c) 2008 Apple Inc. All rights reserved.
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


#ifndef _NFS_NFS_GSS_CRYPTO_H_
#define _NFS_NFS_GSS_CRYPTO_H_
#include <libkern/libkern.h>
#include <libkern/crypto/sha1.h>
#include <libkern/crypto/md5.h>
#include <crypto/des/des_locl.h>

#define KG_USAGE_SEAL 22
#define KG_USAGE_SIGN 23
#define KG_USAGE_SEQ  24

#define KEY_USAGE_DES3_SEAL (const unsigned char *)"\x00\x00\x00\x16\xaa"
#define KEY_USAGE_DES3_SIGN (const unsigned char *)"\x00\x00\x00\x17\x99"
#define KEY_USAGE_DES3_SEQ  (const unsigned char *)"\x00\x00\x00\x18\x55"
#define KEY_USAGE_LEN 5

typedef struct {
	SHA1_CTX sha1_ctx;
	des_cblock dk[3];
} HMAC_SHA1_DES3KD_CTX;

typedef struct {
	MD5_CTX md5_ctx;
	des_key_schedule *sched;
} MD5_DESCBC_CTX;

#define MD5_DESCBC_DIGEST_LENGTH 8

__BEGIN_DECLS

void krb5_nfold(unsigned int, const unsigned char *, unsigned int, unsigned char *);
void des3_make_key(const unsigned char[21], des_cblock[3]);
int des3_key_sched(des_cblock[3], des_key_schedule[3]);
void des3_cbc_encrypt(des_cblock *, des_cblock *, int32_t,
			des_key_schedule[3], des_cblock *, des_cblock *, int);
int des3_derive_key(des_cblock[3], des_cblock[3], const unsigned char *, int);
void HMAC_SHA1_DES3KD_Init(HMAC_SHA1_DES3KD_CTX *, des_cblock[3], int);
void HMAC_SHA1_DES3KD_Update(HMAC_SHA1_DES3KD_CTX *, void *, size_t);
void HMAC_SHA1_DES3KD_Final(void *, HMAC_SHA1_DES3KD_CTX *);
DES_LONG des_cbc_cksum(des_cblock *, des_cblock *, int32_t, des_key_schedule, des_cblock *);
void	des_cbc_encrypt(des_cblock *, des_cblock *, int32_t, des_key_schedule,
			des_cblock *, des_cblock *, int);

void MD5_DESCBC_Init(MD5_DESCBC_CTX *, des_key_schedule *);
void MD5_DESCBC_Update(MD5_DESCBC_CTX *, void *, size_t);
void MD5_DESCBC_Final(void *, MD5_DESCBC_CTX *);

__END_DECLS

#endif /* _NFS_NFS_GSS_CRYPTO_H_ */
