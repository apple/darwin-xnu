/*
 * Copyright (C) 1995, 1996, 1997, and 1998 WIDE Project.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. Neither the name of the project nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE PROJECT AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE PROJECT OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef _RFC2040_RC5_H_
#define _RFC2040_RC5_H_

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/mbuf.h>

/*
 * if RC5_WORD change, W also may be changed.
 */
typedef u_int32_t	RC5_WORD;

#define W		(32)
#define WW		(W / 8)
#define ROT_MASK	(W - 1)
#define BB		((2 * W) / 8)

#define SHLL(x, s)	((RC5_WORD)((x) << ((s)&ROT_MASK)))
#define SHLR(x, s, w)	((RC5_WORD)((x) >> ((w)-((s)&ROT_MASK))))
#define SHRL(x, s, w)	((RC5_WORD)((x) << ((w)-((s)&ROT_MASK))))
#define SHRR(x, s)	((RC5_WORD)((x) >> ((s)&ROT_MASK)))

#define ROTL(x, s, w)	((RC5_WORD)(SHLL((x), (s))|SHLR((x), (s), (w))))
#define ROTR(x, s, w)	((RC5_WORD)(SHRL((x), (s), (w))|SHRR((x), (s))))

#define P16	0xb7e1
#define Q16	0x9e37
#define P32	0xb7e15163
#define Q32	0x9e3779b9
#define P64	0xb7e151628aed2a6b
#define Q64	0x9e3779b97f4a7c15

#if W == 16
#define Pw	P16
#define Qw	Q16
#elif W == 32
#define Pw	P32
#define Qw	Q32
#elif W == 64
#define Pw	P64
#define Qw	Q64
#endif

#define RC5_ENCRYPT	1
#define RC5_DECRYPT	0

extern void set_rc5_expandkey __P((RC5_WORD *, u_int8_t *, size_t, int));
extern void rc5_encrypt_round16 __P((u_int8_t *, const u_int8_t *,
				const RC5_WORD *));
extern void rc5_decrypt_round16 __P((u_int8_t *, const u_int8_t *,
				const RC5_WORD *));
extern void rc5_cbc_process __P((struct mbuf *, size_t, size_t, RC5_WORD *,
				u_int8_t *, int));

#endif
