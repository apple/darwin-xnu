/*	$FreeBSD: src/sys/crypto/cast128/cast128.h,v 1.1.2.3 2001/12/05 05:54:57 ume Exp $	*/
/*	$KAME: cast128.h,v 1.7 2001/11/27 09:47:32 sakane Exp $	*/

/*
 * heavily modified by Tomomi Suzuki <suzuki@grelot.elec.ryukoku.ac.jp>
 */
/*
 * The CAST-128 Encryption Algorithm (RFC 2144)
 *
 * original implementation <Hideo "Sir MaNMOS" Morisita>
 * 1997/08/21
 */
/*
 * Copyright (C) 1997 Hideo "Sir MANMOS" Morishita
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
 *
 * THIS SOFTWARE IS PROVIDED BY Hideo "Sir MaNMOS" Morishita ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL Hideo "Sir MaNMOS" Morishita BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 */

#ifndef RFC2144_CAST_128_H
#define RFC2144_CAST_128_H

#include <sys/param.h>


#define	CAST128_ENCRYPT	1
#define	CAST128_DECRYPT	0


extern void set_cast128_subkey __P((u_int32_t *, u_int8_t *, int));
extern void cast128_encrypt_round16 __P((u_int8_t *, const u_int8_t *,
					u_int32_t *));
extern void cast128_decrypt_round16 __P((u_int8_t *, const u_int8_t *,
					u_int32_t *));
extern void cast128_encrypt_round12 __P((u_int8_t *, const u_int8_t *,
					u_int32_t *));
extern void cast128_decrypt_round12 __P((u_int8_t *, const u_int8_t *,
					u_int32_t *));
#endif

