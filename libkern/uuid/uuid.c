/*
 * Copyright (c) 2004 Apple Computer, Inc. All rights reserved.
 *
 * %Begin-Header%
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, and the entire permission notice in its entirety,
 *    including the disclaimer of warranties.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. The name of the author may not be used to endorse or promote
 *    products derived from this software without specific prior
 *    written permission.
 * 
 * THIS SOFTWARE IS PROVIDED ``AS IS'' AND ANY EXPRESS OR IMPLIED
 * WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE, ALL OF
 * WHICH ARE HEREBY DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR BE
 * LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT
 * OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF
 * LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE
 * USE OF THIS SOFTWARE, EVEN IF NOT ADVISED OF THE POSSIBILITY OF SUCH
 * DAMAGE.
 * %End-Header%
 */

#include <uuid/uuid.h>

#include <stdint.h>
#include <string.h>

#include <sys/random.h>
#include <sys/socket.h>
#include <sys/systm.h>
#include <sys/time.h>

#include <net/if.h>
#include <net/if_dl.h>
#include <net/if_types.h>

UUID_DEFINE(UUID_NULL, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0);

static void
read_node(uint8_t *node)
{
#if NETWORKING
	struct ifnet *ifp;
	struct ifaddr *ifa;
	struct sockaddr_dl *sdl;

	ifnet_head_lock_shared();
	TAILQ_FOREACH(ifp, &ifnet_head, if_link) {
		TAILQ_FOREACH(ifa, &ifp->if_addrhead, ifa_link) {
			sdl = (struct sockaddr_dl *)ifa->ifa_addr;
			if (sdl && sdl->sdl_family == AF_LINK && sdl->sdl_type == IFT_ETHER) {
				memcpy(node, LLADDR(sdl), 6);
				ifnet_head_done();
				return;
			}
		}
	}
	ifnet_head_done();
#endif /* NETWORKING */

	read_random(node, 6);
	node[0] |= 0x01;
}

static uint64_t
read_time(void)
{
	struct timespec tv;

	nanotime(&tv);

	return (tv.tv_sec * 10000000ULL) + (tv.tv_nsec / 100ULL) + 0x01B21DD213814000ULL;
}

void
uuid_clear(uuid_t uu)
{
	memset(uu, 0, sizeof(uuid_t));
}

int
uuid_compare(const uuid_t uu1, const uuid_t uu2)
{
	return memcmp(uu1, uu2, sizeof(uuid_t));
}

void
uuid_copy(uuid_t dst, const uuid_t src)
{
	memcpy(dst, src, sizeof(uuid_t));
}

void
uuid_generate_random(uuid_t out)
{
	read_random(out, sizeof(uuid_t));

	out[6] = (out[6] & 0x0F) | 0x40;
	out[8] = (out[8] & 0x3F) | 0x80;
}

void
uuid_generate_time(uuid_t out)
{
	uint64_t time;

	read_node(&out[10]);
	read_random(&out[8], 2);

	time = read_time();
	out[0] = (uint8_t)(time >> 24);
	out[1] = (uint8_t)(time >> 16);
	out[2] = (uint8_t)(time >> 8);
	out[3] = (uint8_t)time;
	out[4] = (uint8_t)(time >> 40);
	out[5] = (uint8_t)(time >> 32);
	out[6] = (uint8_t)(time >> 56);
	out[7] = (uint8_t)(time >> 48);
 
	out[6] = (out[6] & 0x0F) | 0x10;
	out[8] = (out[8] & 0x3F) | 0x80;
}

void
uuid_generate(uuid_t out)
{
	uuid_generate_random(out);
}

int
uuid_is_null(const uuid_t uu)
{
	return !memcmp(uu, UUID_NULL, sizeof(uuid_t));
}

int
uuid_parse(const char *in, uuid_t uu)
{
	int n = 0;

	sscanf(in,
		"%hh2x%hh2x%hh2x%hh2x-"
		"%hh2x%hh2x-"
		"%hh2x%hh2x-"
		"%hh2x%hh2x-"
		"%hh2x%hh2x%hh2x%hh2x%hh2x%hh2x%n",
		&uu[0], &uu[1], &uu[2], &uu[3],
		&uu[4], &uu[5],
		&uu[6], &uu[7],
		&uu[8], &uu[9],
		&uu[10], &uu[11], &uu[12], &uu[13], &uu[14], &uu[15], &n);

	return (n != 36 || in[n] != '\0' ? -1 : 0);
}

void
uuid_unparse_lower(const uuid_t uu, char *out)
{
	sprintf(out,
		"%02x%02x%02x%02x-"
		"%02x%02x-"
		"%02x%02x-"
		"%02x%02x-"
		"%02x%02x%02x%02x%02x%02x",
		uu[0], uu[1], uu[2], uu[3],
		uu[4], uu[5],
		uu[6], uu[7],
		uu[8], uu[9],
		uu[10], uu[11], uu[12], uu[13], uu[14], uu[15]);
}

void
uuid_unparse_upper(const uuid_t uu, char *out)
{
	sprintf(out,
		"%02X%02X%02X%02X-"
		"%02X%02X-"
		"%02X%02X-"
		"%02X%02X-"
		"%02X%02X%02X%02X%02X%02X",
		uu[0], uu[1], uu[2], uu[3],
		uu[4], uu[5],
		uu[6], uu[7],
		uu[8], uu[9],
		uu[10], uu[11], uu[12], uu[13], uu[14], uu[15]);
}

void
uuid_unparse(const uuid_t uu, char *out)
{
	uuid_unparse_upper(uu, out);
}
