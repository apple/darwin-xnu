/*
 ---------------------------------------------------------------------------
 Copyright (c) 2003, Dr Brian Gladman, Worcester, UK.   All rights reserved.

 LICENSE TERMS

 The free distribution and use of this software in both source and binary
 form is allowed (with or without changes) provided that:

   1. distributions of this source code include the above copyright
      notice, this list of conditions and the following disclaimer;

   2. distributions in binary form include the above copyright
      notice, this list of conditions and the following disclaimer
      in the documentation and/or other associated materials;

   3. the copyright holder's name is not used to endorse products
      built using this software without specific written permission.

 ALTERNATIVELY, provided that this notice is retained in full, this product
 may be distributed under the terms of the GNU General Public License (GPL),
 in which case the provisions of the GPL apply INSTEAD OF those given above.

 DISCLAIMER

 This software is provided 'as is' with no explicit or implied warranties
 in respect of its properties, including, but not limited to, correctness
 and/or fitness for purpose.
 ---------------------------------------------------------------------------
 Issue 31/01/2006

 These subroutines implement multiple block AES modes for ECB, CBC, CFB,
 OFB and CTR encryption,  The code provides support for the VIA Advanced 
 Cryptography Engine (ACE).

 NOTE: In the following subroutines, the AES contexts (ctx) must be
 16 byte aligned if VIA ACE is being used
*/

//#include <memory.h>
#include <kern/assert.h>

#include "aesopt.h"

#if defined( AES_MODES )
#if defined(__cplusplus)
extern "C"
{
#endif

#if defined( _MSC_VER ) && ( _MSC_VER > 800 )
#pragma intrinsic(memcpy)
#define in_line __inline
#else
#define in_line
#endif

#define BFR_BLOCKS      8

/* These values are used to detect long word alignment in order to */
/* speed up some buffer operations. This facility may not work on  */
/* some machines so this define can be commented out if necessary  */

#define FAST_BUFFER_OPERATIONS
#pragma warning( disable : 4311 4312 )

#define lp08(x)         ((uint_8t*)(x))
#define lp32(x)         ((uint_32t*)(x))
#define addr_mod_04(x)	((unsigned long)(x) & 3)
#define addr_mod_16(x)  ((unsigned long)(x) & 15)

#if defined( USE_VIA_ACE_IF_PRESENT )

#include "via_ace.h"

#pragma pack(16)

aligned_array(unsigned long,    enc_gen_table, 12, 16) =    NEH_ENC_GEN_DATA;
aligned_array(unsigned long,   enc_load_table, 12, 16) =   NEH_ENC_LOAD_DATA;
aligned_array(unsigned long, enc_hybrid_table, 12, 16) = NEH_ENC_HYBRID_DATA;
aligned_array(unsigned long,    dec_gen_table, 12, 16) =    NEH_DEC_GEN_DATA;
aligned_array(unsigned long,   dec_load_table, 12, 16) =   NEH_DEC_LOAD_DATA;
aligned_array(unsigned long, dec_hybrid_table, 12, 16) = NEH_DEC_HYBRID_DATA;

/* NOTE: These control word macros must only be used after  */
/* a key has been set up because they depend on key size    */

#if NEH_KEY_TYPE == NEH_LOAD
#define kd_adr(c)   ((uint_8t*)(c)->ks)
#elif NEH_KEY_TYPE == NEH_GENERATE
#define kd_adr(c)   ((uint_8t*)(c)->ks + (c)->inf.b[0])
#else
#define kd_adr(c)   ((uint_8t*)(c)->ks + ((c)->inf.b[0] == 160 ? 160 : 0))
#endif

#else

#define aligned_array(type, name, no, stride) type name[no]
#define aligned_auto(type, name, no, stride)  type name[no]

#endif

#if defined( _MSC_VER ) && _MSC_VER > 1200

#define via_cwd(cwd, ty, dir, len) unsigned long* cwd = (dir##_##ty##_table + ((len - 128) >> 4)) 

#else

#define via_cwd(cwd, ty, dir, len)				\
    aligned_auto(unsigned long, cwd, 4, 16);	\
    cwd[1] = cwd[2] = cwd[3] = 0;				\
    cwd[0] = neh_##dir##_##ty##_key(len)

#endif

/* implemented in case of wrong call for fixed tables */
void gen_tabs(void)
{
}

aes_rval aes_mode_reset(aes_encrypt_ctx ctx[1])
{
    ctx->inf.b[2] = 0; 
    return 0;
}

aes_rval aes_ecb_encrypt(const unsigned char *ibuf, unsigned char *obuf,
                    int len, const aes_encrypt_ctx ctx[1])
{   int nb = len >> 4;

    if(len & (AES_BLOCK_SIZE - 1))
        return 1;

#if defined( USE_VIA_ACE_IF_PRESENT )

    if(ctx->inf.b[1] == 0xff)
    {   uint_8t *ksp = (uint_8t*)(ctx->ks);
        via_cwd(cwd, hybrid, enc, 2* ctx->inf.b[0] - 192);	

        if(addr_mod_16(ctx))
            return 1;

        if(!addr_mod_16(ibuf) && !addr_mod_16(obuf))
        {
            via_ecb_op5(ksp,cwd,ibuf,obuf,nb);
        }
        else
        {   aligned_auto(uint_8t, buf, BFR_BLOCKS * AES_BLOCK_SIZE, 16);
            uint_8t *ip, *op;

            while(nb)
            {
                int m = (nb > BFR_BLOCKS ? BFR_BLOCKS : nb);

                ip = (addr_mod_16(ibuf) ? buf : (uint_8t*)ibuf);
                op = (addr_mod_16(obuf) ? buf : obuf);

                if(ip != ibuf)
                    memcpy(buf, ibuf, m * AES_BLOCK_SIZE);

                via_ecb_op5(ksp,cwd,ip,op,m);

                if(op != obuf)
                    memcpy(obuf, buf, m * AES_BLOCK_SIZE);

                ibuf += m * AES_BLOCK_SIZE;
                obuf += m * AES_BLOCK_SIZE;
                nb -= m;
            }
        }

        return 0;
    }

#endif

#if !defined( ASSUME_VIA_ACE_PRESENT )
    while(nb--)
    {
        aes_encrypt(ibuf, obuf, ctx);
        ibuf += AES_BLOCK_SIZE;
        obuf += AES_BLOCK_SIZE;
    }
#endif
    return 0;
}

aes_rval aes_ecb_decrypt(const unsigned char *ibuf, unsigned char *obuf,
                    int len, const aes_decrypt_ctx ctx[1])
{   int nb = len >> 4;

    if(len & (AES_BLOCK_SIZE - 1))
        return 1;

#if defined( USE_VIA_ACE_IF_PRESENT )

    if(ctx->inf.b[1] == 0xff)
    {   uint_8t *ksp = kd_adr(ctx);
        via_cwd(cwd, hybrid, dec, 2* ctx->inf.b[0] - 192);	

        if(addr_mod_16(ctx))
            return 1;

        if(!addr_mod_16(ibuf) && !addr_mod_16(obuf))
        {
            via_ecb_op5(ksp,cwd,ibuf,obuf,nb);
        }
        else
        {   aligned_auto(uint_8t, buf, BFR_BLOCKS * AES_BLOCK_SIZE, 16);
            uint_8t *ip, *op;

            while(nb)
            {
                int m = (nb > BFR_BLOCKS ? BFR_BLOCKS : nb);

                ip = (addr_mod_16(ibuf) ? buf : (uint_8t*)ibuf);
                op = (addr_mod_16(obuf) ? buf : obuf);

                if(ip != ibuf)
                    memcpy(buf, ibuf, m * AES_BLOCK_SIZE);

                via_ecb_op5(ksp,cwd,ip,op,m);

                if(op != obuf)
                    memcpy(obuf, buf, m * AES_BLOCK_SIZE);

                ibuf += m * AES_BLOCK_SIZE;
                obuf += m * AES_BLOCK_SIZE;
                nb -= m;
            }
        }

        return 0;
    }

#endif

#if !defined( ASSUME_VIA_ACE_PRESENT )
    while(nb--)
    {
        aes_decrypt(ibuf, obuf, ctx);
        ibuf += AES_BLOCK_SIZE;
        obuf += AES_BLOCK_SIZE;
    }
#endif
    return 0;
}

aes_rval aes_cbc_encrypt(const unsigned char *ibuf, unsigned char *obuf,
                    int len, unsigned char *iv, const aes_encrypt_ctx ctx[1])
{   int nb = len >> 4;

    if(len & (AES_BLOCK_SIZE - 1))
        return 1;

#if defined( USE_VIA_ACE_IF_PRESENT )

    if(ctx->inf.b[1] == 0xff)
    {   uint_8t *ksp = (uint_8t*)(ctx->ks), *ivp = iv;
        aligned_auto(uint_8t, liv, AES_BLOCK_SIZE, 16);
        via_cwd(cwd, hybrid, enc, 2* ctx->inf.b[0] - 192);	

        if(addr_mod_16(ctx))
            return 1;

        if(addr_mod_16(iv))   /* ensure an aligned iv */
        {
            ivp = liv;
            memcpy(liv, iv, AES_BLOCK_SIZE);
        }

        if(!addr_mod_16(ibuf) && !addr_mod_16(obuf) && !addr_mod_16(iv))
        {
            via_cbc_op7(ksp,cwd,ibuf,obuf,nb,ivp,ivp);
        }
        else
        {   aligned_auto(uint_8t, buf, BFR_BLOCKS * AES_BLOCK_SIZE, 16);
            uint_8t *ip, *op;

            while(nb)
            {
                int m = (nb > BFR_BLOCKS ? BFR_BLOCKS : nb);

                ip = (addr_mod_16(ibuf) ? buf : (uint_8t*)ibuf);
                op = (addr_mod_16(obuf) ? buf : obuf);

                if(ip != ibuf)
                    memcpy(buf, ibuf, m * AES_BLOCK_SIZE);

                via_cbc_op7(ksp,cwd,ip,op,m,ivp,ivp);

                if(op != obuf)
                    memcpy(obuf, buf, m * AES_BLOCK_SIZE);

                ibuf += m * AES_BLOCK_SIZE;
                obuf += m * AES_BLOCK_SIZE;
                nb -= m;
            }
        }

        if(iv != ivp)
            memcpy(iv, ivp, AES_BLOCK_SIZE);

        return 0;
    }

#endif

#if !defined( ASSUME_VIA_ACE_PRESENT )
# ifdef FAST_BUFFER_OPERATIONS
    if(!addr_mod_04(ibuf) && !addr_mod_04(iv))
        while(nb--)
        {
            lp32(iv)[0] ^= lp32(ibuf)[0];
            lp32(iv)[1] ^= lp32(ibuf)[1];
            lp32(iv)[2] ^= lp32(ibuf)[2];
            lp32(iv)[3] ^= lp32(ibuf)[3];
            aes_encrypt(iv, iv, ctx);
            memcpy(obuf, iv, AES_BLOCK_SIZE);
            ibuf += AES_BLOCK_SIZE;
            obuf += AES_BLOCK_SIZE;
        }
    else
# endif
        while(nb--)
        {
            iv[ 0] ^= ibuf[ 0]; iv[ 1] ^= ibuf[ 1];
            iv[ 2] ^= ibuf[ 2]; iv[ 3] ^= ibuf[ 3];
            iv[ 4] ^= ibuf[ 4]; iv[ 5] ^= ibuf[ 5];
            iv[ 6] ^= ibuf[ 6]; iv[ 7] ^= ibuf[ 7];
            iv[ 8] ^= ibuf[ 8]; iv[ 9] ^= ibuf[ 9];
            iv[10] ^= ibuf[10]; iv[11] ^= ibuf[11];
            iv[12] ^= ibuf[12]; iv[13] ^= ibuf[13];
            iv[14] ^= ibuf[14]; iv[15] ^= ibuf[15];
            aes_encrypt(iv, iv, ctx);
            memcpy(obuf, iv, AES_BLOCK_SIZE);
            ibuf += AES_BLOCK_SIZE;
            obuf += AES_BLOCK_SIZE;
        }
#endif
    return 0;
}

aes_rval aes_encrypt_cbc(const unsigned char *in_blk, const unsigned char *in_iv, unsigned int num_blk,
					 unsigned char *out_blk, const aes_encrypt_ctx cx[1])
{
		unsigned char tmp_iv[16];
		int i;
		
		for (i = 0; i < 16; i++)
			tmp_iv[i] = *(in_iv + i);
		
		return aes_cbc_encrypt(in_blk, out_blk, num_blk<<4, tmp_iv, cx);

}

aes_rval aes_cbc_decrypt(const unsigned char *ibuf, unsigned char *obuf,
                    int len, unsigned char *iv, const aes_decrypt_ctx ctx[1])
{   unsigned char tmp[AES_BLOCK_SIZE];
    int nb = len >> 4;

    if(len & (AES_BLOCK_SIZE - 1))
        return 1;

#if defined( USE_VIA_ACE_IF_PRESENT )

    if(ctx->inf.b[1] == 0xff)
    {   uint_8t *ksp = kd_adr(ctx), *ivp = iv;
        aligned_auto(uint_8t, liv, AES_BLOCK_SIZE, 16);
        via_cwd(cwd, hybrid, dec, 2* ctx->inf.b[0] - 192);	

        if(addr_mod_16(ctx))
            return 1;

        if(addr_mod_16(iv))   /* ensure an aligned iv */
        {
            ivp = liv;
            memcpy(liv, iv, AES_BLOCK_SIZE);
        }

        if(!addr_mod_16(ibuf) && !addr_mod_16(obuf) && !addr_mod_16(iv))
        {
            via_cbc_op6(ksp,cwd,ibuf,obuf,nb,ivp);
        }
        else
        {   aligned_auto(uint_8t, buf, BFR_BLOCKS * AES_BLOCK_SIZE, 16);
            uint_8t *ip, *op;

            while(nb)
            {
                int m = (nb > BFR_BLOCKS ? BFR_BLOCKS : nb);

                ip = (addr_mod_16(ibuf) ? buf : (uint_8t*)ibuf);
                op = (addr_mod_16(obuf) ? buf : obuf);

                if(ip != ibuf)
                    memcpy(buf, ibuf, m * AES_BLOCK_SIZE);

                via_cbc_op6(ksp,cwd,ip,op,m,ivp);

                if(op != obuf)
                    memcpy(obuf, buf, m * AES_BLOCK_SIZE);

                ibuf += m * AES_BLOCK_SIZE;
                obuf += m * AES_BLOCK_SIZE;
                nb -= m;
            }
        }

        if(iv != ivp)
            memcpy(iv, ivp, AES_BLOCK_SIZE);

        return 0;
    }
#endif

#if !defined( ASSUME_VIA_ACE_PRESENT )
# ifdef FAST_BUFFER_OPERATIONS
    if(!addr_mod_04(obuf) && !addr_mod_04(iv))
        while(nb--)
        {
            memcpy(tmp, ibuf, AES_BLOCK_SIZE);
            aes_decrypt(ibuf, obuf, ctx);
            lp32(obuf)[0] ^= lp32(iv)[0];
            lp32(obuf)[1] ^= lp32(iv)[1];
            lp32(obuf)[2] ^= lp32(iv)[2];
            lp32(obuf)[3] ^= lp32(iv)[3];
            memcpy(iv, tmp, AES_BLOCK_SIZE);
            ibuf += AES_BLOCK_SIZE;
            obuf += AES_BLOCK_SIZE;
        }
    else
# endif
        while(nb--)
        {
            memcpy(tmp, ibuf, AES_BLOCK_SIZE);
            aes_decrypt(ibuf, obuf, ctx);
            obuf[ 0] ^= iv[ 0]; obuf[ 1] ^= iv[ 1];
            obuf[ 2] ^= iv[ 2]; obuf[ 3] ^= iv[ 3];
            obuf[ 4] ^= iv[ 4]; obuf[ 5] ^= iv[ 5];
            obuf[ 6] ^= iv[ 6]; obuf[ 7] ^= iv[ 7];
            obuf[ 8] ^= iv[ 8]; obuf[ 9] ^= iv[ 9];
            obuf[10] ^= iv[10]; obuf[11] ^= iv[11];
            obuf[12] ^= iv[12]; obuf[13] ^= iv[13];
            obuf[14] ^= iv[14]; obuf[15] ^= iv[15];
            memcpy(iv, tmp, AES_BLOCK_SIZE);
            ibuf += AES_BLOCK_SIZE;
            obuf += AES_BLOCK_SIZE;
        }
#endif
    return 0;
}

aes_rval aes_decrypt_cbc(const unsigned char *in_blk, const unsigned char *in_iv, unsigned int num_blk,
					 unsigned char *out_blk, const aes_decrypt_ctx cx[1])
{
		unsigned char tmp_iv[16];
		int i;
		
		for (i = 0; i < 16; i++)
			tmp_iv[i] = *(in_iv + i);
		
		return aes_cbc_decrypt(in_blk, out_blk, num_blk<<4, tmp_iv, cx);

}


#if defined(__cplusplus)
}
#endif
#endif
