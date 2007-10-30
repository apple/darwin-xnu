/*
 * Copyright (c) 2000-2006 Apple Computer, Inc. All rights reserved.
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

/*
 * ---------------------------------------------------------------------------
 * Copyright (c) 2002, Dr Brian Gladman, Worcester, UK.   All rights reserved.
 *
 * LICENSE TERMS
 *
 * The free distribution and use of this software in both source and binary
 * form is allowed (with or without changes) provided that:
 *
 *   1. distributions of this source code include the above copyright
 *      notice, this list of conditions and the following disclaimer;
 *
 *   2. distributions in binary form include the above copyright
 *      notice, this list of conditions and the following disclaimer
 *      in the documentation and/or other associated materials;
 *
 *   3. the copyright holder's name is not used to endorse products
 *      built using this software without specific written permission.
 *
 * ALTERNATIVELY, provided that this notice is retained in full, this product
 * may be distributed under the terms of the GNU General Public License (GPL),
 * in which case the provisions of the GPL apply INSTEAD OF those given above.
 *
 * DISCLAIMER
 *
 * This software is provided 'as is' with no explicit or implied warranties
 * in respect of its properties, including, but not limited to, correctness
 * and/or fitness for purpose.
 * ---------------------------------------------------------------------------
 * Issue 31/01/2006
 *
 * This code requires either ASM_X86_V2 or ASM_X86_V2C to be set in aesopt.h 
 * and the same define to be set here as well. If AES_V2C is set this file 
 * requires the C files aeskey.c and aestab.c for support.
 *
 * This is a full assembler implementation covering encryption, decryption and
 * key scheduling. It uses 2k bytes of tables but its encryption and decryption
 * performance is very close to that obtained using large tables.  Key schedule
 * expansion is slower for both encryption and decryption but this is likely to
 * be offset by the much smaller load that this version places on the processor
 * cache. I acknowledge the contribution made by Daniel Bernstein to aspects of
 * the design of the AES round function used here.
 *
 * This code provides the standard AES block size (128 bits, 16 bytes) and the
 * three standard AES key sizes (128, 192 and 256 bits). It has the same call
 * interface as my C implementation. The ebx, esi, edi and ebp registers are
 * preserved across calls but eax, ecx and edx and the artihmetic status flags
 * are not.
 */

#include <mach/i386/asm.h>

#define AES_128          /* define if AES with 128 bit keys is needed */
#define AES_192          /* define if AES with 192 bit keys is needed */
#define AES_256          /* define if AES with 256 bit keys is needed */
#define AES_VAR          /* define if a variable key size is needed */
#define ENCRYPTION       /* define if encryption is needed */
#define DECRYPTION       /* define if decryption is needed */
#define AES_REV_DKS      /* define if key decryption schedule is reversed */

#ifndef ASM_X86_V2C
#define ENCRYPTION_KEY_SCHEDULE /* define if enc. key expansion is needed */
#define DECRYPTION_KEY_SCHEDULE /* define if dec. key expansion is needed */
#endif

/*
 * The encryption key schedule has the following in memory layout where N is the
 * number of rounds (10, 12 or 14):
 *
 * lo: | input key (round 0)  |  ; each round is four 32-bit words
 *     | encryption round 1   |
 *     | encryption round 2   |
 *     ....
 *     | encryption round N-1 |
 * hi: | encryption round N   |
 *
 * The decryption key schedule is normally set up so that it has the same
 * layout as above by actually reversing the order of the encryption key
 * schedule in memory (this happens when AES_REV_DKS is set):
 *
 * lo: | decryption round 0   | =              | encryption round N   |
 *     | decryption round 1   | = INV_MIX_COL[ | encryption round N-1 | ]
 *     | decryption round 2   | = INV_MIX_COL[ | encryption round N-2 | ]
 *     ....                       ....
 *     | decryption round N-1 | = INV_MIX_COL[ | encryption round 1   | ]
 * hi: | decryption round N   | =              | input key (round 0)  |
 *
 * with rounds except the first and last modified using inv_mix_column()
 * But if AES_REV_DKS is NOT set the order of keys is left as it is for
 * encryption so that it has to be accessed in reverse when used for
 * decryption (although the inverse mix column modifications are done)
 *
 * lo: | decryption round 0   | =              | input key (round 0)  |
 *     | decryption round 1   | = INV_MIX_COL[ | encryption round 1   | ]
 *     | decryption round 2   | = INV_MIX_COL[ | encryption round 2   | ]
 *     ....                       ....
 *     | decryption round N-1 | = INV_MIX_COL[ | encryption round N-1 | ]
 * hi: | decryption round N   | =              | encryption round N   |
 *
 * This layout is faster when the assembler key scheduling provided here
 * is used.
 */

/* End of user defines */

#ifdef AES_VAR
#ifndef AES_128
#define AES_128 
#endif
#ifndef AES_192
#define AES_192 
#endif
#ifndef AES_256
#define AES_256 
#endif
#endif

#ifdef AES_VAR
#define KS_LENGTH 60
#else
#ifdef AES_256
#define KS_LENGTH 60
#else
#ifdef AES_192
#define KS_LENGTH 52
#else 
#define KS_LENGTH 44
#endif
#endif
#endif

/*
 * These macros implement stack based local variables
 */
#define	save(r1)			\
    movl    %r1, (%esp);

#define	restore(r1)			\
    movl    (%esp), %r1;

#define	do_call(f, n)			\
    call    EXT(f);			\
    addl    $(n), %esp;

/*
 * finite field multiplies by {02}, {04} and {08}
 */
#define f2(x) ((x<<1)^(((x>>7)&1)*0x11b))
#define f4(x) ((x<<2)^(((x>>6)&1)*0x11b)^(((x>>6)&2)*0x11b))
#define f8(x) ((x<<3)^(((x>>5)&1)*0x11b)^(((x>>5)&2)*0x11b)^(((x>>5)&4)*0x11b))

/*
 * finite field multiplies required in table generation
 */
#define	f3(x) (f2(x) ^ x)
#define	f9(x) (f8(x) ^ x)
#define	fb(x) (f8(x) ^ f2(x) ^ x)
#define	fd(x) (f8(x) ^ f4(x) ^ x)
#define	fe(x) (f8(x) ^ f4(x) ^ f2(x))

#define	etab_0(x) enc_tab+4(,x,8)
#define	etab_1(x) enc_tab+3(,x,8)
#define	etab_2(x) enc_tab+2(,x,8)
#define	etab_3(x) enc_tab+1(,x,8)

#define	etab_b(x) etab_3(x)

#define	btab_0(x) enc_tab+6(,x,8)
#define	btab_1(x) enc_tab+5(,x,8)
#define	btab_2(x) enc_tab+4(,x,8)
#define	btab_3(x) enc_tab+3(,x,8)

/*
 * ROUND FUNCTION.  Build column[2] on ESI and column[3] on EDI that have the
 * round keys pre-loaded. Build column[0] in EBP and column[1] in EBX.
 *
 * Input:
 *
 *   EAX     column[0]
 *   EBX     column[1]
 *   ECX     column[2]
 *   EDX     column[3]
 *   ESI     column key[round][2]
 *   EDI     column key[round][3]
 *   EBP     scratch
 *
 * Output:
 *
 *   EBP     column[0]   unkeyed
 *   EBX     column[1]   unkeyed
 *   ESI     column[2]   keyed
 *   EDI     column[3]   keyed
 *   EAX     scratch
 *   ECX     scratch
 *   EDX     scratch
 */
#define	rnd_fun(m1, m2)			\
    roll    $16, %ebx;			\
					\
    ## m1 ## _zo(esi, cl, 0, ebp);	\
    m1(esi, dh, 1, ebp);		\
    m1(esi, bh, 3, ebp);		\
    ## m1 ## _zo(edi, dl, 0, ebp);	\
    m1(edi, ah, 1, ebp);		\
    m1(edi, bl, 2, ebp);		\
    ## m2 ## _zo(ebp, al, 0, ebp);	\
					\
    shrl    $16, %ebx;			\
    andl    $0xffff0000, %eax;		\
    orl     %ebx, %eax;			\
    shrl    $16, %edx;			\
					\
    m1(ebp, ah, 1, ebx);		\
    m1(ebp, dh, 3, ebx);		\
    m2(ebx, dl, 2, ebx);		\
    m1(ebx, ch, 1, edx);		\
    ## m1 ## _zo(ebx, al, 0, edx);	\
					\
    shrl    $16, %eax;			\
    shrl    $16, %ecx;			\
					\
    m1(ebp, cl, 2, edx);		\
    m1(edi, ch, 3, edx);		\
    m1(esi, al, 2, edx);		\
    m1(ebx, ah, 3, edx)

/*
 * Basic MOV and XOR Operations for normal rounds
 */
#define	nr_xor_zo	nr_xor
#define	nr_xor(r1, r2, r3, r4)		\
    movzbl  %r2, %r4;			\
    xorl    etab_ ## r3(%r4), %r1;

#define	nr_mov_zo	nr_mov
#define	nr_mov(r1, r2, r3, r4)		\
    movzbl  %r2, %r4;			\
    movl    etab_ ## r3(%r4), %r1;

/*
 * Basic MOV and XOR Operations for last round
 */

#if 1

#define	lr_xor_zo(r1, r2, r3, r4)	\
    movzbl  %r2, %r4;			\
    movzbl  etab_b(%r4), %r4;		\
    xor     %r4, %r1;

#define	lr_xor(r1, r2, r3, r4)		\
    movzbl  %r2, %r4;			\
    movzbl  etab_b(%r4), %r4;		\
    shll    $(8*r3), %r4;		\
    xor     %r4, %r1;

#define	lr_mov_zo(r1, r2, r3, r4)	\
    movzbl  %r2, %r4;			\
    movzbl  etab_b(%r4), %r1;

#define	lr_mov(r1, r2, r3, r4)		\
    movzbl  %r2, %r4;			\
    movzbl  etab_b(%r4), %r1;		\
    shll    $(8*r3), %r1;

#else        /* less effective but worth leaving as an option */

#define	lr_xor_zo	lr_xor
#define	lr_xor(r1, r2, r3, r4)			\
    movzbl  %r2, %r4;				\
    mov     btab_ ## r3(%r4), %r4;		\
    andl    $(0x000000ff << 8 * r3), %r4;	\
    xor     %r4, %r1;

#define	lr_mov_zo	lr_mov
#define	lr_mov(r1, r2, r3, r4)			\
    movzbl  %r2, %r4;				\
    mov     btab_ ## r3(%r4), %r1;		\
    andl    $(0x000000ff << 8 * r3), %r1;

#endif

/*
 * Apply S-Box to the 4 bytes in a 32-bit word and rotate left 3 byte positions
 *
 *   r1 : output is xored into this register
 *   r2 : input: a => eax, b => ebx, c => ecx, d => edx
 *   r3 : scratch register
 */

#define	l3s_col(r1, r2, r3)			\
    lr_xor_zo(r1, ## r2 ## h, 0, r3);		\
    lr_xor(r1, ## r2 ## l, 3, r3);		\
    shrl    $16, %e ## r2 ## x;			\
    lr_xor(r1, ## r2 ## h, 2, r3);		\
    lr_xor(r1, ## r2 ## l, 1, r3);

/*
 * offsets to parameters
 */
#define	in_blk		4	/* input byte array address parameter */
#define	out_blk		8	/* output byte array address parameter */
#define	ctx		12	/* AES context structure */
#define	stk_spc		20	/* stack space */

#ifdef  ENCRYPTION

#define ENCRYPTION_TABLE 

#define	enc_round			\
    addl    $16, %ebp;			\
    save(ebp);				\
    movl    8(%ebp), %esi;		\
    movl    12(%ebp), %edi;		\
					\
    rnd_fun(nr_xor, nr_mov);		\
					\
    movl    %ebp, %eax;			\
    movl    %esi, %ecx;			\
    movl    %edi, %edx;			\
    restore(ebp);			\
    xorl    (%ebp), %eax;		\
    xorl    4(%ebp), %ebx;

#define enc_last_round			\
    addl    $16, %ebp;			\
    save(ebp);				\
    movl    8(%ebp), %esi;		\
    movl    12(%ebp), %edi;		\
					\
    rnd_fun(lr_xor, lr_mov);		\
					\
    movl    %ebp, %eax;			\
    restore(ebp);			\
    xorl    (%ebp), %eax;		\
    xorl    4(%ebp), %ebx;

    .section __TEXT, __text

/*
 * AES Encryption Subroutine
 */
Entry(aes_encrypt)

    subl    $stk_spc, %esp
    movl    %ebp, 16(%esp)
    movl    %ebx, 12(%esp)
    movl    %esi, 8(%esp)
    movl    %edi, 4(%esp)

    movl    in_blk+stk_spc(%esp), %esi	/* input pointer */
    movl    (%esi), %eax
    movl    4(%esi), %ebx
    movl    8(%esi), %ecx
    movl    12(%esi), %edx

    movl    ctx+stk_spc(%esp), %ebp	/* key pointer */
    movzbl  4*KS_LENGTH(%ebp), %edi
    xorl    (%ebp), %eax
    xorl    4(%ebp), %ebx
    xorl    8(%ebp), %ecx
    xorl    12(%ebp), %edx

    /*
     * determine the number of rounds
     */
    cmpl    $10*16, %edi
    je     aes_encrypt.3
    cmpl    $12*16, %edi
    je     aes_encrypt.2
    cmpl    $14*16, %edi
    je      aes_encrypt.1
    movl    $-1, %eax
    jmp     aes_encrypt.5

aes_encrypt.1:
    enc_round
    enc_round
aes_encrypt.2:
    enc_round
    enc_round
aes_encrypt.3:
    enc_round
    enc_round
    enc_round
    enc_round
    enc_round
    enc_round
    enc_round
    enc_round
    enc_round
    enc_last_round

    movl    out_blk+stk_spc(%esp), %edx
    movl    %eax, (%edx)
    movl    %ebx, 4(%edx)
    movl    %esi, 8(%edx)
    movl    %edi, 12(%edx)
    xorl    %eax, %eax

aes_encrypt.5:
    movl    16(%esp), %ebp
    movl    12(%esp), %ebx
    movl    8(%esp), %esi
    movl    4(%esp), %edi
    addl    $stk_spc, %esp
    ret

#endif

/*
 * For r2 == 16, or r2 == 24 && r1 == 7, or r2 ==32 && r1 == 6
 */
#define	f_key(r1, r2, rc_val)		\
    l3s_col(esi, a, ebx);		\
    xorl    $rc_val, %esi;		\
					\
    movl    %esi, r1*r2(%ebp);		\
    xorl    %esi, %edi;			\
    movl    %edi, r1*r2+4(%ebp);	\
    xorl    %edi, %ecx;			\
    movl    %ecx, r1*r2+8(%ebp);	\
    xorl    %ecx, %edx;			\
    movl    %edx, r1*r2+12(%ebp);	\
    movl    %edx, %eax;

/*
 * For r2 == 24 && r1 == 0 to 6
 */
#define	f_key_24(r1, r2, rc_val)	\
    f_key(r1, r2, rc_val);		\
					\
    xorl    r1*r2+16-r2(%ebp), %eax;	\
    movl    %eax, r1*r2+16(%ebp);	\
    xorl    r1*r2+20-r2(%ebp), %eax;	\
    movl    %eax, r1*r2+20(%ebp);

/*
 * For r2 ==32 && r1 == 0 to 5
 */
#define	f_key_32(r1, r2, rc_val)	\
    f_key(r1, r2, rc_val);		\
					\
    roll    $8, %eax;			\
    pushl   %edx;			\
    movl    r1*r2+16-r2(%ebp), %edx;	\
    l3s_col(edx, a, ebx);		\
    movl    %edx, %eax;			\
    popl    %edx;			\
    movl    %eax, r1*r2+16(%ebp);	\
    xorl    r1*r2+20-r2(%ebp), %eax;	\
    movl    %eax, r1*r2+20(%ebp);	\
    xorl    r1*r2+24-r2(%ebp), %eax;	\
    movl    %eax, r1*r2+24(%ebp);	\
    xorl    r1*r2+28-r2(%ebp), %eax;	\
    movl    %eax, r1*r2+28(%ebp);

#ifdef ENCRYPTION_KEY_SCHEDULE

#ifdef  AES_128

#ifndef ENCRYPTION_TABLE
#define ENCRYPTION_TABLE 
#endif

Entry(aes_encrypt_key128)

    pushl   %ebp
    pushl   %ebx
    pushl   %esi
    pushl   %edi

    movl    24(%esp), %ebp
    movl    $10*16, 4*KS_LENGTH(%ebp)
    movl    20(%esp), %ebx

    movl    (%ebx), %esi
    movl    %esi, (%ebp)
    movl    4(%ebx), %edi
    movl    %edi, 4(%ebp)
    movl    8(%ebx), %ecx
    movl    %ecx, 8(%ebp)
    movl    12(%ebx), %edx
    movl    %edx, 12(%ebp)
    addl    $16, %ebp
    movl    %edx, %eax

    f_key(0, 16, 1)
    f_key(1, 16, 2)
    f_key(2, 16, 4)
    f_key(3, 16, 8)
    f_key(4, 16, 16)
    f_key(5, 16, 32)
    f_key(6, 16, 64)
    f_key(7, 16, 128)
    f_key(8, 16, 27)
    f_key(9, 16, 54)

    popl    %edi
    popl    %esi
    popl    %ebx
    popl    %ebp
    xorl    %eax, %eax
    ret

#endif

#ifdef  AES_192

#ifndef ENCRYPTION_TABLE
#define ENCRYPTION_TABLE 
#endif

Entry(aes_encrypt_key192)

    pushl   %ebp
    pushl   %ebx
    pushl   %esi
    pushl   %edi

    movl    24(%esp), %ebp
    movl    $12*16, 4*KS_LENGTH(%ebp)
    movl    20(%esp), %ebx

    movl    (%ebx), %esi
    movl    %esi, (%ebp)
    movl    4(%ebx), %edi
    movl    %edi, 4(%ebp)
    movl    8(%ebx), %ecx
    movl    %ecx, 8(%ebp)
    movl    12(%ebx), %edx
    movl    %edx, 12(%ebp)
    movl    16(%ebx), %eax
    movl    %eax, 16(%ebp)
    movl    20(%ebx), %eax
    movl    %eax, 20(%ebp)
    addl    $24, %ebp

    f_key_24(0, 24, 1)
    f_key_24(1, 24, 2)
    f_key_24(2, 24, 4)
    f_key_24(3, 24, 8)
    f_key_24(4, 24, 16)
    f_key_24(5, 24, 32)
    f_key_24(6, 24, 64)
    f_key(7, 24, 128)

    popl    %edi
    popl    %esi
    popl    %ebx
    popl    %ebp
    xorl    %eax, %eax
    ret

#endif

#ifdef  AES_256

#ifndef ENCRYPTION_TABLE
#define ENCRYPTION_TABLE 
#endif

Entry(aes_encrypt_key256)

    pushl   %ebp
    pushl   %ebx
    pushl   %esi
    pushl   %edi

    movl    24(%esp), %ebp
    movl    $14*16, 4*KS_LENGTH(%ebp)
    movl    20(%esp), %ebx

    movl    (%ebx), %esi
    movl    %esi, (%ebp)
    movl    4(%ebx), %edi
    movl    %edi, 4(%ebp)
    movl    8(%ebx), %ecx
    movl    %ecx, 8(%ebp)
    movl    12(%ebx), %edx
    movl    %edx, 12(%ebp)
    movl    16(%ebx), %eax
    movl    %eax, 16(%ebp)
    movl    20(%ebx), %eax
    movl    %eax, 20(%ebp)
    movl    24(%ebx), %eax
    movl    %eax, 24(%ebp)
    movl    28(%ebx), %eax
    movl    %eax, 28(%ebp)
    addl    $32, %ebp

    f_key_32(0, 32, 1)
    f_key_32(1, 32, 2)
    f_key_32(2, 32, 4)
    f_key_32(3, 32, 8)
    f_key_32(4, 32, 16)
    f_key_32(5, 32, 32)
    f_key(6, 32, 64)

    popl    %edi
    popl    %esi
    popl    %ebx
    popl    %ebp
    xorl    %eax, %eax
    ret

#endif

#ifdef  AES_VAR

#ifndef ENCRYPTION_TABLE
#define ENCRYPTION_TABLE 
#endif

Entry(aes_encrypt_key)

    movl    4(%esp), %ecx
    movl    8(%esp), %eax
    movl    12(%esp), %edx
    pushl   %edx
    pushl   %ecx

    cmpl    $16, %eax
    je      aes_encrypt_key.1
    cmpl    $128, %eax
    je      aes_encrypt_key.1

    cmpl    $24, %eax
    je      aes_encrypt_key.2
    cmpl    $192, %eax
    je      aes_encrypt_key.2

    cmpl    $32, %eax
    je      aes_encrypt_key.3
    cmpl    $256, %eax
    je      aes_encrypt_key.3
    movl    $-1, %eax
    addl    $8, %esp
    ret

aes_encrypt_key.1:
    do_call(aes_encrypt_key128, 8)
    ret
aes_encrypt_key.2:
    do_call(aes_encrypt_key192, 8)
    ret
aes_encrypt_key.3:
    do_call(aes_encrypt_key256, 8)
    ret

#endif

#endif

#ifdef ENCRYPTION_TABLE

# S-box data - 256 entries

    .section __DATA, __data
    .align ALIGN

#define u8(x) 0, x, x, f3(x), f2(x), x, x, f3(x)

enc_tab: 
   .byte u8(0x63),u8(0x7c),u8(0x77),u8(0x7b),u8(0xf2),u8(0x6b),u8(0x6f),u8(0xc5)
   .byte u8(0x30),u8(0x01),u8(0x67),u8(0x2b),u8(0xfe),u8(0xd7),u8(0xab),u8(0x76)
   .byte u8(0xca),u8(0x82),u8(0xc9),u8(0x7d),u8(0xfa),u8(0x59),u8(0x47),u8(0xf0)
   .byte u8(0xad),u8(0xd4),u8(0xa2),u8(0xaf),u8(0x9c),u8(0xa4),u8(0x72),u8(0xc0)
   .byte u8(0xb7),u8(0xfd),u8(0x93),u8(0x26),u8(0x36),u8(0x3f),u8(0xf7),u8(0xcc)
   .byte u8(0x34),u8(0xa5),u8(0xe5),u8(0xf1),u8(0x71),u8(0xd8),u8(0x31),u8(0x15)
   .byte u8(0x04),u8(0xc7),u8(0x23),u8(0xc3),u8(0x18),u8(0x96),u8(0x05),u8(0x9a)
   .byte u8(0x07),u8(0x12),u8(0x80),u8(0xe2),u8(0xeb),u8(0x27),u8(0xb2),u8(0x75)
   .byte u8(0x09),u8(0x83),u8(0x2c),u8(0x1a),u8(0x1b),u8(0x6e),u8(0x5a),u8(0xa0)
   .byte u8(0x52),u8(0x3b),u8(0xd6),u8(0xb3),u8(0x29),u8(0xe3),u8(0x2f),u8(0x84)
   .byte u8(0x53),u8(0xd1),u8(0x00),u8(0xed),u8(0x20),u8(0xfc),u8(0xb1),u8(0x5b)
   .byte u8(0x6a),u8(0xcb),u8(0xbe),u8(0x39),u8(0x4a),u8(0x4c),u8(0x58),u8(0xcf)
   .byte u8(0xd0),u8(0xef),u8(0xaa),u8(0xfb),u8(0x43),u8(0x4d),u8(0x33),u8(0x85)
   .byte u8(0x45),u8(0xf9),u8(0x02),u8(0x7f),u8(0x50),u8(0x3c),u8(0x9f),u8(0xa8)
   .byte u8(0x51),u8(0xa3),u8(0x40),u8(0x8f),u8(0x92),u8(0x9d),u8(0x38),u8(0xf5)
   .byte u8(0xbc),u8(0xb6),u8(0xda),u8(0x21),u8(0x10),u8(0xff),u8(0xf3),u8(0xd2)
   .byte u8(0xcd),u8(0x0c),u8(0x13),u8(0xec),u8(0x5f),u8(0x97),u8(0x44),u8(0x17)
   .byte u8(0xc4),u8(0xa7),u8(0x7e),u8(0x3d),u8(0x64),u8(0x5d),u8(0x19),u8(0x73)
   .byte u8(0x60),u8(0x81),u8(0x4f),u8(0xdc),u8(0x22),u8(0x2a),u8(0x90),u8(0x88)
   .byte u8(0x46),u8(0xee),u8(0xb8),u8(0x14),u8(0xde),u8(0x5e),u8(0x0b),u8(0xdb)
   .byte u8(0xe0),u8(0x32),u8(0x3a),u8(0x0a),u8(0x49),u8(0x06),u8(0x24),u8(0x5c)
   .byte u8(0xc2),u8(0xd3),u8(0xac),u8(0x62),u8(0x91),u8(0x95),u8(0xe4),u8(0x79)
   .byte u8(0xe7),u8(0xc8),u8(0x37),u8(0x6d),u8(0x8d),u8(0xd5),u8(0x4e),u8(0xa9)
   .byte u8(0x6c),u8(0x56),u8(0xf4),u8(0xea),u8(0x65),u8(0x7a),u8(0xae),u8(0x08)
   .byte u8(0xba),u8(0x78),u8(0x25),u8(0x2e),u8(0x1c),u8(0xa6),u8(0xb4),u8(0xc6)
   .byte u8(0xe8),u8(0xdd),u8(0x74),u8(0x1f),u8(0x4b),u8(0xbd),u8(0x8b),u8(0x8a)
   .byte u8(0x70),u8(0x3e),u8(0xb5),u8(0x66),u8(0x48),u8(0x03),u8(0xf6),u8(0x0e)
   .byte u8(0x61),u8(0x35),u8(0x57),u8(0xb9),u8(0x86),u8(0xc1),u8(0x1d),u8(0x9e)
   .byte u8(0xe1),u8(0xf8),u8(0x98),u8(0x11),u8(0x69),u8(0xd9),u8(0x8e),u8(0x94)
   .byte u8(0x9b),u8(0x1e),u8(0x87),u8(0xe9),u8(0xce),u8(0x55),u8(0x28),u8(0xdf)
   .byte u8(0x8c),u8(0xa1),u8(0x89),u8(0x0d),u8(0xbf),u8(0xe6),u8(0x42),u8(0x68)
   .byte u8(0x41),u8(0x99),u8(0x2d),u8(0x0f),u8(0xb0),u8(0x54),u8(0xbb),u8(0x16)

#endif

#ifdef  DECRYPTION

#define DECRYPTION_TABLE 

#define dtab_0(x) dec_tab(,x,8)
#define dtab_1(x) dec_tab+3(,x,8)
#define dtab_2(x) dec_tab+2(,x,8)
#define dtab_3(x) dec_tab+1(,x,8)
#define dtab_x(x) dec_tab+7(,x,8)

#define	irn_fun(m1, m2)			\
    roll    $16, %eax;			\
					\
    ## m1 ## _zo(esi, cl, 0, ebp);	\
    m1(esi, bh, 1, ebp);		\
    m1(esi, al, 2, ebp);		\
    ## m1 ## _zo(edi, dl, 0, ebp);	\
    m1(edi, ch, 1, ebp);		\
    m1(edi, ah, 3, ebp);		\
    ## m2 ## _zo(ebp, bl, 0, ebp);	\
					\
    shrl    $16, %eax;			\
    andl    $0xffff0000, %ebx;		\
    orl     %eax, %ebx;			\
    shrl    $16, %ecx;			\
					\
    m1(ebp, bh, 1, eax);		\
    m1(ebp, ch, 3, eax);		\
    m2(eax, cl, 2, ecx);		\
    ## m1 ## _zo(eax, bl, 0, ecx);	\
    m1(eax, dh, 1, ecx);		\
					\
    shrl    $16, %ebx;			\
    shrl    $16, %edx;			\
					\
    m1(esi, dh, 3, ecx);		\
    m1(ebp, dl, 2, ecx);		\
    m1(eax, bh, 3, ecx);		\
    m1(edi, bl, 2, ecx);

/*
 * Basic MOV and XOR Operations for normal rounds
 */
#define	ni_xor_zo	ni_xor
#define	ni_xor(r1, r2, r3, r4)		\
    movzbl  %r2, %r4;			\
    xorl    dtab_ ## r3 ## (%r4), %r1;

#define	ni_mov_zo	ni_mov
#define	ni_mov(r1, r2, r3, r4)		\
    movzbl  %r2, %r4;			\
    movl    dtab_ ## r3 ## (%r4), %r1;

/*
 * Basic MOV and XOR Operations for last round
 */

#define	li_xor_zo(r1, r2, r3, r4)	\
    movzbl %r2, %r4;			\
    movzbl dtab_x(%r4), %r4;		\
    xor    %r4, %r1;

#define	li_xor(r1, r2, r3, r4)		\
    movzbl %r2, %r4;			\
    movzbl dtab_x(%r4), %r4;		\
    shll   $(8*r3), %r4;		\
    xor    %r4, %r1;

#define	li_mov_zo(r1, r2, r3, r4)	\
    movzbl %r2, %r4;			\
    movzbl dtab_x(%r4), %r1;

#define	li_mov(r1, r2, r3, r4)		\
    movzbl %r2, %r4;			\
    movzbl dtab_x(%r4), %r1;		\
    shl    $(8*r3), %r1;

#ifdef AES_REV_DKS

#define	dec_round			\
    addl    $16, %ebp;			\
    save(ebp);				\
    movl    8(%ebp), %esi;		\
    movl    12(%ebp), %edi;		\
					\
    irn_fun(ni_xor, ni_mov);		\
					\
    movl    %ebp, %ebx;			\
    movl    %esi, %ecx;			\
    movl    %edi, %edx;			\
    restore(ebp);			\
    xorl    (%ebp), %eax;		\
    xorl    4(%ebp), %ebx;

#define	dec_last_round			\
    addl    $16, %ebp;			\
    save(ebp);				\
    movl    8(%ebp), %esi;		\
    movl    12(%ebp), %edi;		\
					\
    irn_fun(li_xor, li_mov);		\
					\
    movl    %ebp, %ebx;			\
    restore(ebp);			\
    xorl    (%ebp), %eax;		\
    xorl    4(%ebp), %ebx;

#else

#define	dec_round			\
    subl    $16, %ebp;			\
    save(ebp);				\
    movl    8(%ebp), %esi;		\
    movl    12(%ebp), %edi;		\
					\
    irn_fun(ni_xor, ni_mov);		\
					\
    movl    %ebp, %ebx;			\
    movl    %esi, %ecx;			\
    movl    %edi, %edx;			\
    restore(ebp);			\
    xorl    (%ebp), %eax;		\
    xorl    4(%ebp), %ebx;

#define	dec_last_round			\
    subl    $16, %ebp;			\
    save(ebp);				\
    movl    8(%ebp), %esi;		\
    movl    12(%ebp), %edi;		\
					\
    irn_fun(li_xor, li_mov);		\
					\
    movl    %ebp, %ebx;			\
    restore(ebp);			\
    xorl    (%ebp), %eax;		\
    xorl    4(%ebp), %ebx;

#endif /* AES_REV_DKS */

    .section __TEXT, __text

/*
 * AES Decryption Subroutine
 */
Entry(aes_decrypt)

    subl    $stk_spc, %esp
    movl    %ebp, 16(%esp)
    movl    %ebx, 12(%esp)
    movl    %esi, 8(%esp)
    movl    %edi, 4(%esp)

    /*
     * input four columns and xor in first round key
     */
    movl    in_blk+stk_spc(%esp), %esi	/* input pointer */
    movl    (%esi), %eax
    movl    4(%esi), %ebx
    movl    8(%esi), %ecx
    movl    12(%esi), %edx
    leal    16(%esi), %esi

    movl    ctx+stk_spc(%esp), %ebp	/* key pointer */
    movzbl  4*KS_LENGTH(%ebp), %edi
#ifndef  AES_REV_DKS		/* if decryption key schedule is not reversed */
    leal    (%ebp,%edi), %ebp	/* we have to access it from the top down */
#endif
    xorl    (%ebp), %eax	/* key schedule */
    xorl    4(%ebp), %ebx
    xorl    8(%ebp), %ecx
    xorl    12(%ebp), %edx

    /*
     * determine the number of rounds
     */
    cmpl    $10*16, %edi
    je     aes_decrypt.3
    cmpl    $12*16, %edi
    je     aes_decrypt.2
    cmpl    $14*16, %edi
    je      aes_decrypt.1
    movl    $-1, %eax
    jmp     aes_decrypt.5

aes_decrypt.1:
    dec_round
    dec_round
aes_decrypt.2:
    dec_round
    dec_round
aes_decrypt.3:
    dec_round
    dec_round
    dec_round
    dec_round
    dec_round
    dec_round
    dec_round
    dec_round
    dec_round
    dec_last_round

    /*
     * move final values to the output array.
     */
    movl    out_blk+stk_spc(%esp), %ebp
    movl    %eax, (%ebp)
    movl    %ebx, 4(%ebp)
    movl    %esi, 8(%ebp)
    movl    %edi, 12(%ebp)
    xorl    %eax, %eax

aes_decrypt.5:
    movl    16(%esp), %ebp
    movl    12(%esp), %ebx
    movl    8(%esp), %esi
    movl    4(%esp), %edi
    addl    $stk_spc, %esp
    ret

#endif

#define	inv_mix_col			\
    movzbl  %dl, %ebx;			\
    movzbl  etab_b(%ebx), %ebx;		\
    movl    dtab_0(%ebx), %eax;		\
    movzbl  %dh, %ebx;			\
    shrl    $16, %edx;			\
    movzbl  etab_b(%ebx), %ebx;		\
    xorl    dtab_1(%ebx), %eax;		\
    movzbl  %dl, %ebx;			\
    movzbl  etab_b(%ebx), %ebx;		\
    xorl    dtab_2(%ebx), %eax;		\
    movzbl  %dh, %ebx;			\
    movzbl  etab_b(%ebx), %ebx;		\
    xorl    dtab_3(%ebx), %eax;

#ifdef DECRYPTION_KEY_SCHEDULE

#ifdef AES_128

#ifndef DECRYPTION_TABLE
#define DECRYPTION_TABLE 
#endif

Entry(aes_decrypt_key128)

    pushl   %ebp
    pushl   %ebx
    pushl   %esi
    pushl   %edi
    movl    24(%esp), %eax	/* context */
    movl    20(%esp), %edx	/* key */
    pushl   %eax
    pushl   %edx
    do_call(aes_encrypt_key128, 8)
    movl    $10*16, %eax
    movl    24(%esp), %esi	/* pointer to first round key */
    leal    (%esi,%eax), %edi	/* pointer to last round key */
    addl    $32, %esi
				/* the inverse mix column transformation */
    movl    -16(%esi), %edx	/* needs to be applied to all round keys */
    inv_mix_col
    movl    %eax, -16(%esi)	/* transforming the four sub-keys in the */
    movl    -12(%esi), %edx	/* second round key */
    inv_mix_col
    movl    %eax, -12(%esi)	/* transformations for subsequent rounds */
    movl    -8(%esi), %edx	/* can then be made more efficient by */
    inv_mix_col
    movl    %eax, -8(%esi)	/* in the encryption round key ek[r]: */
    movl    -4(%esi), %edx
    inv_mix_col
    movl    %eax, -4(%esi)	/* where n is 1..3. Hence the corresponding */

aes_decrypt_key128.0:
    movl    (%esi), %edx	/* subkeys in the decryption round key dk[r] */
    inv_mix_col
    movl    %eax, (%esi)	/* GF(256): */
    xorl    -12(%esi), %eax
    movl    %eax, 4(%esi)	/* dk[r][n] = dk[r][n-1] ^ dk[r-1][n] */
    xorl    -8(%esi), %eax
    movl    %eax, 8(%esi)	/* So we only need one inverse mix column */
    xorl    -4(%esi), %eax	/* operation (n = 0) for each four word cycle */
    movl    %eax, 12(%esi)	/* in the expanded key. */
    addl    $16, %esi
    cmpl    %esi, %edi
    jg      aes_decrypt_key128.0
    jmp     dec_end

#endif

#ifdef AES_192

#ifndef DECRYPTION_TABLE
#define DECRYPTION_TABLE 
#endif

Entry(aes_decrypt_key192)

    pushl   %ebp
    pushl   %ebx
    pushl   %esi
    pushl   %edi
    movl    24(%esp), %eax	/* context */
    movl    20(%esp), %edx	/* key */
    pushl   %eax
    pushl   %edx
    do_call(aes_encrypt_key192, 8)
    movl    $12*16, %eax
    movl    24(%esp), %esi	/* first round key */
    leal    (%esi,%eax), %edi	/* last round key */
    addl    $48, %esi		/* the first 6 words are the key, of */
				/* which the top 2 words are part of */
    movl    -32(%esi), %edx	/* the second round key and hence */
    inv_mix_col
    movl    %eax, -32(%esi)	/* need to do a further six values prior */
    movl    -28(%esi), %edx	/* to using a more efficient technique */
    inv_mix_col
    movl    %eax, -28(%esi)
				/* dk[r][n] = dk[r][n-1] ^ dk[r-1][n] */
    movl    -24(%esi), %edx
    inv_mix_col
    movl    %eax, -24(%esi)	/* cycle is now 6 words long */
    movl    -20(%esi), %edx
    inv_mix_col
    movl    %eax, -20(%esi)
    movl    -16(%esi), %edx
    inv_mix_col
    movl    %eax, -16(%esi)
    movl    -12(%esi), %edx
    inv_mix_col
    movl    %eax, -12(%esi)
    movl    -8(%esi), %edx
    inv_mix_col
    movl    %eax, -8(%esi)
    movl    -4(%esi), %edx
    inv_mix_col
    movl    %eax, -4(%esi)

aes_decrypt_key192.0:
    movl    (%esi), %edx	/* expanded key is 13 * 4 = 44 32-bit words */
    inv_mix_col
    movl    %eax, (%esi)	/* using inv_mix_col.  We have already done 8 */
    xorl    -20(%esi), %eax	/* of these so 36 are left - hence we need */
    movl    %eax, 4(%esi)	/* exactly 6 loops of six here */
    xorl    -16(%esi), %eax
    movl    %eax, 8(%esi)
    xorl    -12(%esi), %eax
    movl    %eax, 12(%esi)
    xorl    -8(%esi), %eax
    movl    %eax, 16(%esi)
    xorl    -4(%esi), %eax
    movl    %eax, 20(%esi)
    addl    $24, %esi
    cmpl    %esi, %edi
    jg      aes_decrypt_key192.0
    jmp     dec_end

#endif

#ifdef AES_256

#ifndef DECRYPTION_TABLE
#define DECRYPTION_TABLE 
#endif

Entry(aes_decrypt_key256)

    pushl   %ebp
    pushl   %ebx
    pushl   %esi
    pushl   %edi
    movl    24(%esp), %eax
    movl    20(%esp), %edx
    pushl   %eax
    pushl   %edx
    do_call(aes_encrypt_key256, 8)
    movl    $14*16, %eax
    movl    24(%esp), %esi
    leal    (%esi,%eax), %edi
    addl    $64, %esi

    movl    -48(%esi), %edx	/* the primary key is 8 words, of which */
    inv_mix_col
    movl    %eax, -48(%esi)
    movl    -44(%esi), %edx
    inv_mix_col
    movl    %eax, -44(%esi)
    movl    -40(%esi), %edx
    inv_mix_col
    movl    %eax, -40(%esi)
    movl    -36(%esi), %edx
    inv_mix_col
    movl    %eax, -36(%esi)

    movl    -32(%esi), %edx	/* the encryption key expansion cycle is */
    inv_mix_col
    movl    %eax, -32(%esi)	/* start by doing one complete block */
    movl    -28(%esi), %edx
    inv_mix_col
    movl    %eax, -28(%esi)
    movl    -24(%esi), %edx
    inv_mix_col
    movl    %eax, -24(%esi)
    movl    -20(%esi), %edx
    inv_mix_col
    movl    %eax, -20(%esi)
    movl    -16(%esi), %edx
    inv_mix_col
    movl    %eax, -16(%esi)
    movl    -12(%esi), %edx
    inv_mix_col
    movl    %eax, -12(%esi)
    movl    -8(%esi), %edx
    inv_mix_col
    movl    %eax, -8(%esi)
    movl    -4(%esi), %edx
    inv_mix_col
    movl    %eax, -4(%esi)

aes_decrypt_key256.0:
    movl    (%esi), %edx	/* we can now speed up the remaining */
    inv_mix_col
    movl    %eax, (%esi)	/* outlined earlier.  But note that */
    xorl    -28(%esi), %eax	/* there is one extra inverse mix */
    movl    %eax, 4(%esi)	/* column operation as the 256 bit */
    xorl    -24(%esi), %eax	/* key has an extra non-linear step */
    movl    %eax, 8(%esi)	/* for the midway element. */
    xorl    -20(%esi), %eax
    movl    %eax, 12(%esi)	/* the expanded key is 15 * 4 = 60 */
    movl    16(%esi), %edx	/* 32-bit words of which 52 need to */
    inv_mix_col
    movl    %eax, 16(%esi)	/* 12 so 40 are left - which means */
    xorl    -12(%esi), %eax	/* that we need exactly 5 loops of 8 */
    movl    %eax, 20(%esi)
    xorl    -8(%esi), %eax
    movl    %eax, 24(%esi)
    xorl    -4(%esi), %eax
    movl    %eax, 28(%esi)
    addl    $32, %esi
    cmpl    %esi, %edi
    jg      aes_decrypt_key256.0

#endif

dec_end: 

#ifdef AES_REV_DKS

    movl    24(%esp), %esi	/* this reverses the order of the */
dec_end.1:
    movl    (%esi), %eax	/* round keys if required */
    movl    4(%esi), %ebx
    movl    (%edi), %ebp
    movl    4(%edi), %edx
    movl    %ebp, (%esi)
    movl    %edx, 4(%esi)
    movl    %eax, (%edi)
    movl    %ebx, 4(%edi)

    movl    8(%esi), %eax
    movl    12(%esi), %ebx
    movl    8(%edi), %ebp
    movl    12(%edi), %edx
    movl    %ebp, 8(%esi)
    movl    %edx, 12(%esi)
    movl    %eax, 8(%edi)
    movl    %ebx, 12(%edi)

    addl    $16, %esi
    subl    $16, %edi
    cmpl    %esi, %edi
    jg      dec_end.1

#endif

    popl    %edi
    popl    %esi
    popl    %ebx
    popl    %ebp
    xorl    %eax, %eax
    ret

#ifdef AES_VAR

Entry(aes_decrypt_key)

    movl    4(%esp), %ecx
    movl    8(%esp), %eax
    movl    12(%esp), %edx
    pushl   %edx
    pushl   %ecx

    cmpl    $16, %eax
    je      aes_decrypt_key.1
    cmpl    $128, %eax
    je      aes_decrypt_key.1

    cmpl    $24, %eax
    je      aes_decrypt_key.2
    cmpl    $192, %eax
    je      aes_decrypt_key.2

    cmpl    $32, %eax
    je      aes_decrypt_key.3
    cmpl    $256, %eax
    je      aes_decrypt_key.3
    movl    $-1, %eax
    addl    $8, %esp
    ret

aes_decrypt_key.1:
    do_call(aes_decrypt_key128, 8)
    ret
aes_decrypt_key.2:
    do_call(aes_decrypt_key192, 8)
    ret
aes_decrypt_key.3:
    do_call(aes_decrypt_key256, 8)
    ret

#endif

#endif

#ifdef DECRYPTION_TABLE

/*
 * Inverse S-box data - 256 entries
 */

    .section __DATA, __data
    .align ALIGN

#define v8(x) fe(x), f9(x), fd(x), fb(x), fe(x), f9(x), fd(x), x

dec_tab: 
   .byte v8(0x52),v8(0x09),v8(0x6a),v8(0xd5),v8(0x30),v8(0x36),v8(0xa5),v8(0x38)
   .byte v8(0xbf),v8(0x40),v8(0xa3),v8(0x9e),v8(0x81),v8(0xf3),v8(0xd7),v8(0xfb)
   .byte v8(0x7c),v8(0xe3),v8(0x39),v8(0x82),v8(0x9b),v8(0x2f),v8(0xff),v8(0x87)
   .byte v8(0x34),v8(0x8e),v8(0x43),v8(0x44),v8(0xc4),v8(0xde),v8(0xe9),v8(0xcb)
   .byte v8(0x54),v8(0x7b),v8(0x94),v8(0x32),v8(0xa6),v8(0xc2),v8(0x23),v8(0x3d)
   .byte v8(0xee),v8(0x4c),v8(0x95),v8(0x0b),v8(0x42),v8(0xfa),v8(0xc3),v8(0x4e)
   .byte v8(0x08),v8(0x2e),v8(0xa1),v8(0x66),v8(0x28),v8(0xd9),v8(0x24),v8(0xb2)
   .byte v8(0x76),v8(0x5b),v8(0xa2),v8(0x49),v8(0x6d),v8(0x8b),v8(0xd1),v8(0x25)
   .byte v8(0x72),v8(0xf8),v8(0xf6),v8(0x64),v8(0x86),v8(0x68),v8(0x98),v8(0x16)
   .byte v8(0xd4),v8(0xa4),v8(0x5c),v8(0xcc),v8(0x5d),v8(0x65),v8(0xb6),v8(0x92)
   .byte v8(0x6c),v8(0x70),v8(0x48),v8(0x50),v8(0xfd),v8(0xed),v8(0xb9),v8(0xda)
   .byte v8(0x5e),v8(0x15),v8(0x46),v8(0x57),v8(0xa7),v8(0x8d),v8(0x9d),v8(0x84)
   .byte v8(0x90),v8(0xd8),v8(0xab),v8(0x00),v8(0x8c),v8(0xbc),v8(0xd3),v8(0x0a)
   .byte v8(0xf7),v8(0xe4),v8(0x58),v8(0x05),v8(0xb8),v8(0xb3),v8(0x45),v8(0x06)
   .byte v8(0xd0),v8(0x2c),v8(0x1e),v8(0x8f),v8(0xca),v8(0x3f),v8(0x0f),v8(0x02)
   .byte v8(0xc1),v8(0xaf),v8(0xbd),v8(0x03),v8(0x01),v8(0x13),v8(0x8a),v8(0x6b)
   .byte v8(0x3a),v8(0x91),v8(0x11),v8(0x41),v8(0x4f),v8(0x67),v8(0xdc),v8(0xea)
   .byte v8(0x97),v8(0xf2),v8(0xcf),v8(0xce),v8(0xf0),v8(0xb4),v8(0xe6),v8(0x73)
   .byte v8(0x96),v8(0xac),v8(0x74),v8(0x22),v8(0xe7),v8(0xad),v8(0x35),v8(0x85)
   .byte v8(0xe2),v8(0xf9),v8(0x37),v8(0xe8),v8(0x1c),v8(0x75),v8(0xdf),v8(0x6e)
   .byte v8(0x47),v8(0xf1),v8(0x1a),v8(0x71),v8(0x1d),v8(0x29),v8(0xc5),v8(0x89)
   .byte v8(0x6f),v8(0xb7),v8(0x62),v8(0x0e),v8(0xaa),v8(0x18),v8(0xbe),v8(0x1b)
   .byte v8(0xfc),v8(0x56),v8(0x3e),v8(0x4b),v8(0xc6),v8(0xd2),v8(0x79),v8(0x20)
   .byte v8(0x9a),v8(0xdb),v8(0xc0),v8(0xfe),v8(0x78),v8(0xcd),v8(0x5a),v8(0xf4)
   .byte v8(0x1f),v8(0xdd),v8(0xa8),v8(0x33),v8(0x88),v8(0x07),v8(0xc7),v8(0x31)
   .byte v8(0xb1),v8(0x12),v8(0x10),v8(0x59),v8(0x27),v8(0x80),v8(0xec),v8(0x5f)
   .byte v8(0x60),v8(0x51),v8(0x7f),v8(0xa9),v8(0x19),v8(0xb5),v8(0x4a),v8(0x0d)
   .byte v8(0x2d),v8(0xe5),v8(0x7a),v8(0x9f),v8(0x93),v8(0xc9),v8(0x9c),v8(0xef)
   .byte v8(0xa0),v8(0xe0),v8(0x3b),v8(0x4d),v8(0xae),v8(0x2a),v8(0xf5),v8(0xb0)
   .byte v8(0xc8),v8(0xeb),v8(0xbb),v8(0x3c),v8(0x83),v8(0x53),v8(0x99),v8(0x61)
   .byte v8(0x17),v8(0x2b),v8(0x04),v8(0x7e),v8(0xba),v8(0x77),v8(0xd6),v8(0x26)
   .byte v8(0xe1),v8(0x69),v8(0x14),v8(0x63),v8(0x55),v8(0x21),v8(0x0c),v8(0x7d)

#endif
