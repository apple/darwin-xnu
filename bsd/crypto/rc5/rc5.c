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
#include <crypto/rc5/rc5.h>


void
set_rc5_expandkey(e_key, key, keylen, rounds)
	RC5_WORD *e_key;
	u_int8_t *key;
	size_t keylen;
	int rounds;
{
	int i, j, k, LL, t, T;
	RC5_WORD L[256/WW];
	RC5_WORD A, B;

	LL = (keylen + WW - 1) / WW;

	bzero(L, sizeof(RC5_WORD)*LL);

	for (i = 0; i < keylen; i++) {
		t = (key[i] & 0xff) << (8*(i%4));
		L[i/WW] = L[i/WW] + t;
	}

	T = 2 * (rounds + 1);
	e_key[0] = Pw;
	for (i = 1; i < T; i++)
		e_key[i] = e_key[i-1] + Qw;

	i = j = 0;
	A = B = 0;
	if (LL > T)
		k = 3 * LL;
	else
		k = 3 * T;

	for (; k > 0; k--) {
		A = ROTL(e_key[i]+A+B, 3, W);
		e_key[i] = A;
		B = ROTL(L[j]+A+B, A+B, W);
		L[j] = B;

		i = (i + 1) % T;
		j = (j + 1) % LL;
	}
}


/*
 *
 */
void
rc5_encrypt_round16(out, in, e_key)
	u_int8_t *out;
	const u_int8_t *in;
	const RC5_WORD *e_key;
{
	RC5_WORD A, B;
	const RC5_WORD *e_keyA, *e_keyB;

	A  =  in[0] & 0xff;
	A += (in[1] & 0xff) << 8;
	A += (in[2] & 0xff) << 16;
	A += (in[3] & 0xff) << 24;
	B  =  in[4] & 0xff;
	B += (in[5] & 0xff) << 8;
	B += (in[6] & 0xff) << 16;
	B += (in[7] & 0xff) << 24;

	e_keyA = e_key;
	e_keyB = e_key + 1;

	A += *e_keyA; e_keyA += 2;
	B += *e_keyB; e_keyB += 2;

	A = ROTL(A^B, B, W) + *e_keyA; e_keyA += 2;
	B = ROTL(B^A, A, W) + *e_keyB; e_keyB += 2;
	A = ROTL(A^B, B, W) + *e_keyA; e_keyA += 2;
	B = ROTL(B^A, A, W) + *e_keyB; e_keyB += 2;
	A = ROTL(A^B, B, W) + *e_keyA; e_keyA += 2;
	B = ROTL(B^A, A, W) + *e_keyB; e_keyB += 2;
	A = ROTL(A^B, B, W) + *e_keyA; e_keyA += 2;
	B = ROTL(B^A, A, W) + *e_keyB; e_keyB += 2; /* round 4 */
	A = ROTL(A^B, B, W) + *e_keyA; e_keyA += 2;
	B = ROTL(B^A, A, W) + *e_keyB; e_keyB += 2;
	A = ROTL(A^B, B, W) + *e_keyA; e_keyA += 2;
	B = ROTL(B^A, A, W) + *e_keyB; e_keyB += 2;
	A = ROTL(A^B, B, W) + *e_keyA; e_keyA += 2;
	B = ROTL(B^A, A, W) + *e_keyB; e_keyB += 2;
	A = ROTL(A^B, B, W) + *e_keyA; e_keyA += 2;
	B = ROTL(B^A, A, W) + *e_keyB; e_keyB += 2; /* round 8 */
	A = ROTL(A^B, B, W) + *e_keyA; e_keyA += 2;
	B = ROTL(B^A, A, W) + *e_keyB; e_keyB += 2;
	A = ROTL(A^B, B, W) + *e_keyA; e_keyA += 2;
	B = ROTL(B^A, A, W) + *e_keyB; e_keyB += 2;
	A = ROTL(A^B, B, W) + *e_keyA; e_keyA += 2;
	B = ROTL(B^A, A, W) + *e_keyB; e_keyB += 2;
	A = ROTL(A^B, B, W) + *e_keyA; e_keyA += 2;
	B = ROTL(B^A, A, W) + *e_keyB; e_keyB += 2; /* round 12 */
	A = ROTL(A^B, B, W) + *e_keyA; e_keyA += 2;
	B = ROTL(B^A, A, W) + *e_keyB; e_keyB += 2;
	A = ROTL(A^B, B, W) + *e_keyA; e_keyA += 2;
	B = ROTL(B^A, A, W) + *e_keyB; e_keyB += 2;
	A = ROTL(A^B, B, W) + *e_keyA; e_keyA += 2;
	B = ROTL(B^A, A, W) + *e_keyB; e_keyB += 2;
	A = ROTL(A^B, B, W) + *e_keyA; e_keyA += 2;
	B = ROTL(B^A, A, W) + *e_keyB; e_keyB += 2; /* round 16 */

	out[0] =  A        & 0xff;
	out[1] = (A >>  8) & 0xff;
	out[2] = (A >> 16) & 0xff;
	out[3] = (A >> 24) & 0xff;
	out[4] =  B        & 0xff;
	out[5] = (B >>  8) & 0xff;
	out[6] = (B >> 16) & 0xff;
	out[7] = (B >> 24) & 0xff;
}


/*
 *
 */
void
rc5_decrypt_round16(out, in, e_key)
	u_int8_t *out;
	const u_int8_t *in;
	const RC5_WORD *e_key;
{
	RC5_WORD A, B;
	const RC5_WORD *e_keyA, *e_keyB;

	A  =  in[0] & 0xff;
	A += (in[1] & 0xff) << 8;
	A += (in[2] & 0xff) << 16;
	A += (in[3] & 0xff) << 24;
	B  =  in[4] & 0xff;
	B += (in[5] & 0xff) << 8;
	B += (in[6] & 0xff) << 16;
	B += (in[7] & 0xff) << 24;

	e_keyA = e_key + 2*16;
	e_keyB = e_key + 2*16 + 1;

	B = ROTR(B-*e_keyB, A, W) ^ A; e_keyB -= 2;
	A = ROTR(A-*e_keyA, B, W) ^ B; e_keyA -= 2;
	B = ROTR(B-*e_keyB, A, W) ^ A; e_keyB -= 2;
	A = ROTR(A-*e_keyA, B, W) ^ B; e_keyA -= 2;
	B = ROTR(B-*e_keyB, A, W) ^ A; e_keyB -= 2;
	A = ROTR(A-*e_keyA, B, W) ^ B; e_keyA -= 2;
	B = ROTR(B-*e_keyB, A, W) ^ A; e_keyB -= 2;
	A = ROTR(A-*e_keyA, B, W) ^ B; e_keyA -= 2; /* round 4 */
	B = ROTR(B-*e_keyB, A, W) ^ A; e_keyB -= 2;
	A = ROTR(A-*e_keyA, B, W) ^ B; e_keyA -= 2;
	B = ROTR(B-*e_keyB, A, W) ^ A; e_keyB -= 2;
	A = ROTR(A-*e_keyA, B, W) ^ B; e_keyA -= 2;
	B = ROTR(B-*e_keyB, A, W) ^ A; e_keyB -= 2;
	A = ROTR(A-*e_keyA, B, W) ^ B; e_keyA -= 2;
	B = ROTR(B-*e_keyB, A, W) ^ A; e_keyB -= 2;
	A = ROTR(A-*e_keyA, B, W) ^ B; e_keyA -= 2; /* round 8 */
	B = ROTR(B-*e_keyB, A, W) ^ A; e_keyB -= 2;
	A = ROTR(A-*e_keyA, B, W) ^ B; e_keyA -= 2;
	B = ROTR(B-*e_keyB, A, W) ^ A; e_keyB -= 2;
	A = ROTR(A-*e_keyA, B, W) ^ B; e_keyA -= 2;
	B = ROTR(B-*e_keyB, A, W) ^ A; e_keyB -= 2;
	A = ROTR(A-*e_keyA, B, W) ^ B; e_keyA -= 2;
	B = ROTR(B-*e_keyB, A, W) ^ A; e_keyB -= 2;
	A = ROTR(A-*e_keyA, B, W) ^ B; e_keyA -= 2; /* round 12 */
	B = ROTR(B-*e_keyB, A, W) ^ A; e_keyB -= 2;
	A = ROTR(A-*e_keyA, B, W) ^ B; e_keyA -= 2;
	B = ROTR(B-*e_keyB, A, W) ^ A; e_keyB -= 2;
	A = ROTR(A-*e_keyA, B, W) ^ B; e_keyA -= 2;
	B = ROTR(B-*e_keyB, A, W) ^ A; e_keyB -= 2;
	A = ROTR(A-*e_keyA, B, W) ^ B; e_keyA -= 2;
	B = ROTR(B-*e_keyB, A, W) ^ A; e_keyB -= 2;
	A = ROTR(A-*e_keyA, B, W) ^ B; e_keyA -= 2; /* round 16 */

	B = B - *e_keyB;
	A = A - *e_keyA;

	out[0] =  A        & 0xff;
	out[1] = (A >>  8) & 0xff;
	out[2] = (A >> 16) & 0xff;
	out[3] = (A >> 24) & 0xff;
	out[4] =  B        & 0xff;
	out[5] = (B >>  8) & 0xff;
	out[6] = (B >> 16) & 0xff;
	out[7] = (B >> 24) & 0xff;
}

