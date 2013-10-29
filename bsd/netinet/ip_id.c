/*
 * Copyright (c) 2002-2013 Apple Inc. All rights reserved.
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

/*-
 * Copyright (c) 2008 Michael J. Silbersack.
 * All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice unmodified, this list of conditions, and the following
 *    disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR ``AS IS'' AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES
 * OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED.
 * IN NO EVENT SHALL THE AUTHOR BE LIABLE FOR ANY DIRECT, INDIRECT,
 * INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING, BUT
 * NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE,
 * DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY
 * THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT
 * (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF
 * THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 */

/*
 * IP ID generation is a fascinating topic.
 *
 * In order to avoid ID collisions during packet reassembly, common sense
 * dictates that the period between reuse of IDs be as large as possible.
 * This leads to the classic implementation of a system-wide counter, thereby
 * ensuring that IDs repeat only once every 2^16 packets.
 *
 * Subsequent security researchers have pointed out that using a global
 * counter makes ID values predictable.  This predictability allows traffic
 * analysis, idle scanning, and even packet injection in specific cases.
 * These results suggest that IP IDs should be as random as possible.
 *
 * The "searchable queues" algorithm used in this IP ID implementation was
 * proposed by Amit Klein.  It is a compromise between the above two
 * viewpoints that has provable behavior that can be tuned to the user's
 * requirements.
 *
 * The basic concept is that we supplement a standard random number generator
 * with a queue of the last L IDs that we have handed out to ensure that all
 * IDs have a period of at least L.
 *
 * To efficiently implement this idea, we keep two data structures: a
 * circular array of IDs of size L and a bitstring of 65536 bits.
 *
 * To start, we ask the RNG for a new ID.  A quick index into the bitstring
 * is used to determine if this is a recently used value.  The process is
 * repeated until a value is returned that is not in the bitstring.
 *
 * Having found a usable ID, we remove the ID stored at the current position
 * in the queue from the bitstring and replace it with our new ID.  Our new
 * ID is then added to the bitstring and the queue pointer is incremented.
 *
 * The lower limit of 512 was chosen because there doesn't seem to be much
 * point to having a smaller value.  The upper limit of 32768 was chosen for
 * two reasons.  First, every step above 32768 decreases the entropy.  Taken
 * to an extreme, 65533 would offer 1 bit of entropy.  Second, the number of
 * attempts it takes the algorithm to find an unused ID drastically
 * increases, killing performance.  The default value of 4096 was chosen
 * because it provides a good tradeoff between randomness and non-repetition,
 * while taking performance into account.
 *
 * With L=4096, the queue will use 8K of memory.  The bitstring always uses
 * 8K of memory (2^16/8).  This yields to around 7% ID collisions.  No memory
 * is allocated until the use of random ids is enabled.
 */

#include <sys/param.h>
#include <sys/time.h>
#include <sys/kernel.h>
#include <sys/random.h>
#include <sys/protosw.h>
#include <sys/bitstring.h>
#include <kern/locks.h>
#include <net/if_var.h>
#include <netinet/in.h>
#include <netinet/in_var.h>
#include <netinet/ip_var.h>
#include <dev/random/randomdev.h>

/*
 * Size of L (see comments above on the lower and upper limits.)
 */
#define	ARRAY_SIZE	(4096)

static uint16_t *id_array = NULL;
static bitstr_t *id_bits = NULL;
static uint32_t array_ptr = 0;
static uint32_t random_id_statistics = 0;
static uint64_t random_id_collisions = 0;
static uint64_t random_id_total = 0;

decl_lck_mtx_data(static, ipid_lock);
static lck_attr_t *ipid_lock_attr;
static lck_grp_t *ipid_lock_grp;
static lck_grp_attr_t *ipid_lock_grp_attr;

SYSCTL_UINT(_net_inet_ip, OID_AUTO, random_id_statistics,
	CTLFLAG_RW | CTLFLAG_LOCKED, &random_id_statistics, 0,
	"Enable IP ID statistics");
SYSCTL_QUAD(_net_inet_ip, OID_AUTO, random_id_collisions,
	CTLFLAG_RD | CTLFLAG_LOCKED, &random_id_collisions,
	"Count of IP ID collisions");
SYSCTL_QUAD(_net_inet_ip, OID_AUTO, random_id_total,
	CTLFLAG_RD | CTLFLAG_LOCKED, &random_id_total,
	"Count of IP IDs created");

/*
 * Called once from ip_init().
 */
void
ip_initid(void)
{
	VERIFY(id_array == NULL);
	VERIFY(id_bits == NULL);

	_CASSERT(ARRAY_SIZE >= 512 && ARRAY_SIZE <= 32768);

	ipid_lock_grp_attr  = lck_grp_attr_alloc_init();
	ipid_lock_grp = lck_grp_alloc_init("ipid", ipid_lock_grp_attr);
	ipid_lock_attr = lck_attr_alloc_init();
	lck_mtx_init(&ipid_lock, ipid_lock_grp, ipid_lock_attr);

	id_array = (uint16_t *)_MALLOC(ARRAY_SIZE * sizeof (uint16_t),
	    M_TEMP, M_WAITOK | M_ZERO);
	id_bits = (bitstr_t *)_MALLOC(bitstr_size(65536), M_TEMP,
	    M_WAITOK | M_ZERO);
	if (id_array == NULL || id_bits == NULL) {
		/* Just in case; neither or both. */
		if (id_array != NULL) {
			_FREE(id_array, M_TEMP);
			id_array = NULL;
		}
		if (id_bits != NULL) {
			_FREE(id_bits, M_TEMP);
			id_bits = NULL;
		}
	}
}

uint16_t
ip_randomid(void)
{
	uint16_t new_id;

	/*
	 * If net.inet.ip.random_id is disabled, revert to incrementing ip_id.
	 * Given that we don't allow the size of the array to change, accessing
	 * id_array and id_bits prior to acquiring the lock below is safe.
	 */
	if (id_array == NULL || ip_use_randomid == 0)
		return (htons(ip_id++));

	/*
	 * To avoid a conflict with the zeros that the array is initially
	 * filled with, we never hand out an id of zero.  bit_test() below
	 * uses single memory access, therefore no lock is needed.
	 */
	new_id = 0;
	do {
		if (random_id_statistics && new_id != 0)
			random_id_collisions++;
		read_random(&new_id, sizeof (new_id));
	} while (bit_test(id_bits, new_id) || new_id == 0);

	/*
	 * These require serialization to maintain correctness.
	 */
	lck_mtx_lock_spin(&ipid_lock);
	bit_clear(id_bits, id_array[array_ptr]);
	bit_set(id_bits, new_id);
	id_array[array_ptr] = new_id;
	if (++array_ptr == ARRAY_SIZE)
		array_ptr = 0;
	lck_mtx_unlock(&ipid_lock);

	if (random_id_statistics)
		random_id_total++;

	return (new_id);
}
