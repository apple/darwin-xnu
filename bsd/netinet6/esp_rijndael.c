/*	$FreeBSD: src/sys/netinet6/esp_rijndael.c,v 1.1.2.1 2001/07/03 11:01:50 ume Exp $	*/
/*	$KAME: esp_rijndael.c,v 1.4 2001/03/02 05:53:05 itojun Exp $	*/

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

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/socket.h>
#include <sys/queue.h>

#include <net/if.h>
#include <net/route.h>

#include <netinet6/ipsec.h>
#include <netinet6/esp.h>
#include <netinet6/esp_rijndael.h>

#include <crypto/rijndael/rijndael.h>

#include <net/net_osdep.h>

/* as rijndael uses assymetric scheduled keys, we need to do it twice. */
int
esp_rijndael_schedlen(algo)
	const struct esp_algorithm *algo;
{

	return sizeof(keyInstance) * 2;
}

int
esp_rijndael_schedule(algo, sav)
	const struct esp_algorithm *algo;
	struct secasvar *sav;
{
	keyInstance *k;

	k = (keyInstance *)sav->sched;
	if (rijndael_makeKey(&k[0], DIR_DECRYPT, _KEYLEN(sav->key_enc) * 8,
	    _KEYBUF(sav->key_enc)) < 0)
		return -1;
	if (rijndael_makeKey(&k[1], DIR_ENCRYPT, _KEYLEN(sav->key_enc) * 8,
	    _KEYBUF(sav->key_enc)) < 0)
		return -1;
	return 0;
}

int
esp_rijndael_blockdecrypt(algo, sav, s, d)
	const struct esp_algorithm *algo;
	struct secasvar *sav;
	u_int8_t *s;
	u_int8_t *d;
{
	cipherInstance c;
	keyInstance *p;

	/* does not take advantage of CBC mode support */
	bzero(&c, sizeof(c));
	if (rijndael_cipherInit(&c, MODE_ECB, NULL) < 0)
		return -1;
	p = (keyInstance *)sav->sched;
	if (rijndael_blockDecrypt(&c, &p[0], s, algo->padbound * 8, d) < 0)
		return -1;
	return 0;
}

int
esp_rijndael_blockencrypt(algo, sav, s, d)
	const struct esp_algorithm *algo;
	struct secasvar *sav;
	u_int8_t *s;
	u_int8_t *d;
{
	cipherInstance c;
	keyInstance *p;

	/* does not take advantage of CBC mode support */
	bzero(&c, sizeof(c));
	if (rijndael_cipherInit(&c, MODE_ECB, NULL) < 0)
		return -1;
	p = (keyInstance *)sav->sched;
	if (rijndael_blockEncrypt(&c, &p[1], s, algo->padbound * 8, d) < 0)
		return -1;
	return 0;
}
