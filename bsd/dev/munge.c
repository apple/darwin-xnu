/*
 * Coyright (c) 2005-2006 Apple Computer, Inc. All rights reserved.
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

#include <sys/cdefs.h>
#include <sys/types.h>
#include <sys/munge.h>
#include <stdint.h>

static inline __attribute__((always_inline)) void 
munge_32_to_64_unsigned(volatile uint64_t *dest, volatile uint32_t *src, int count);

/*
 * Refer to comments in bsd/sys/munge.h
 */
void 
munge_w(const void *arg0 __unused, void *args)
{
	munge_32_to_64_unsigned(args, args, 1);
}

void 
munge_ww(const void *arg0 __unused, void *args)
{
	munge_32_to_64_unsigned(args, args, 2);
}

void 
munge_www(const void *arg0 __unused, void *args)
{
	munge_32_to_64_unsigned(args, args, 3);
}

void 
munge_wwww(const void *arg0 __unused, void *args)
{
	munge_32_to_64_unsigned(args, args, 4);
}

void 
munge_wwwww(const void *arg0 __unused, void *args)
{
	munge_32_to_64_unsigned(args, args, 5);
}

void 
munge_wwwwww(const void *arg0 __unused, void *args)
{
	munge_32_to_64_unsigned(args, args, 6);
}

void 
munge_wwwwwww(const void *arg0 __unused, void *args)
{
	munge_32_to_64_unsigned(args, args, 7);
}

void 
munge_wwwwwwww(const void *arg0 __unused, void *args)
{
	munge_32_to_64_unsigned(args, args, 8);
}

void 
munge_wl(const void *arg0 __unused, void *args)
{
	volatile uint64_t *out_args = (volatile uint64_t*)args;
	volatile uint32_t *in_args = (volatile uint32_t*)args;

	out_args[1] = *(uint64_t*)&in_args[1];
	out_args[0] = in_args[0];
}

void 
munge_wwl(const void *arg0 __unused, void *args)
{
	volatile uint64_t *out_args = (volatile uint64_t*)args;
	volatile uint32_t *in_args = (volatile uint32_t*)args;

	out_args[2] = *(uint64_t*)&in_args[2];
	out_args[1] = in_args[1];
	out_args[0] = in_args[0];
}

void 
munge_wwlw(const void *arg0 __unused, void *args)
{
	volatile uint64_t *out_args = (volatile uint64_t*)args;
	volatile uint32_t *in_args = (volatile uint32_t*)args;

	out_args[3] = in_args[4];
	out_args[2] = *(uint64_t*)&in_args[2];
	out_args[1] = in_args[1];
	out_args[0] = in_args[0];
}
void 
munge_wwlll(const void *arg0 __unused, void *args)
{
	volatile uint64_t *out_args = (volatile uint64_t*)args;
	volatile uint32_t *in_args = (volatile uint32_t*)args;

	out_args[4] = *(uint64_t*)&in_args[6];
	out_args[3] = *(uint64_t*)&in_args[4];
	out_args[2] = *(uint64_t*)&in_args[2];
	out_args[1] = in_args[1];
	out_args[0] = in_args[0];
}

void
munge_wwllww(const void *arg0 __unused, void *args)
{
	volatile uint64_t *out_args = (volatile uint64_t*)args;
	volatile uint32_t *in_args = (volatile uint32_t*)args;

	out_args[5] = in_args[7];
	out_args[4] = in_args[6];
	out_args[3] = *(uint64_t*)&in_args[4];
	out_args[2] = *(uint64_t*)&in_args[2];
	out_args[1] = in_args[1];
	out_args[0] = in_args[0];
}

void
munge_wlw(const void *arg0 __unused, void *args)
{
	volatile uint64_t *out_args = (volatile uint64_t*)args;
	volatile uint32_t *in_args = (volatile uint32_t*)args;

	out_args[2] = in_args[3];
	out_args[1] = *(uint64_t*)&in_args[1];
	out_args[0] = in_args[0];
}

void
munge_wlwwwll(const void *arg0 __unused, void *args)
{
	volatile uint64_t *out_args = (volatile uint64_t*)args;
	volatile uint32_t *in_args = (volatile uint32_t*)args;

	out_args[6] = *(uint64_t*)&in_args[8];
	out_args[5] = *(uint64_t*)&in_args[6];
	out_args[4] = in_args[5];
	out_args[3] = in_args[4];
	out_args[2] = in_args[3];
	out_args[1] = *(uint64_t*)&in_args[1];
	out_args[0] = in_args[0];
}

void
munge_wlwwwllw(const void *arg0 __unused, void *args)
{
	volatile uint64_t *out_args = (volatile uint64_t*)args;
	volatile uint32_t *in_args = (volatile uint32_t*)args;

	out_args[7] = in_args[10];
	munge_wlwwwll(args, args);
}

void 
munge_wlwwlwlw(const void *arg0 __unused, void *args)
{
	volatile uint64_t *out_args = (volatile uint64_t*)args;
	volatile uint32_t *in_args = (volatile uint32_t*)args;

	out_args[7] = in_args[10];
	out_args[6] = *(uint64_t*)&in_args[8];
	out_args[5] = in_args[7];
	out_args[4] = *(uint64_t*)&in_args[5];
	out_args[3] = in_args[4];
	out_args[2] = in_args[3];
	out_args[1] = *(uint64_t*)&in_args[1];
	out_args[0] = in_args[0];
}

void 
munge_wll(const void *arg0 __unused, void *args)
{
	volatile uint64_t *out_args = (volatile uint64_t*)args;
	volatile uint32_t *in_args = (volatile uint32_t*)args;

	out_args[2] = *(uint64_t*)&in_args[3];
	out_args[1] = *(uint64_t*)&in_args[1];
	out_args[0] = in_args[0];
}

void 
munge_wlll(const void *arg0 __unused, void *args)
{
	volatile uint64_t *out_args = (volatile uint64_t*)args;
	volatile uint32_t *in_args = (volatile uint32_t*)args;

	out_args[3] = *(uint64_t*)&in_args[5];
	out_args[2] = *(uint64_t*)&in_args[3];
	out_args[1] = *(uint64_t*)&in_args[1];
	out_args[0] = in_args[0];
}

void
munge_wllww(const void *arg0 __unused, void *args)
{
	volatile uint64_t *out_args = (volatile uint64_t*)args;
	volatile uint32_t *in_args = (volatile uint32_t*)args;

	out_args[4] = in_args[6];
	out_args[3] = in_args[5];
	out_args[2] = *(uint64_t*)&in_args[3];
	out_args[1] = *(uint64_t*)&in_args[1];
	out_args[0] = in_args[0];
}

void 
munge_wllwwll(const void *arg0 __unused, void *args)
{
	volatile uint64_t *out_args = (volatile uint64_t*)args;
	volatile uint32_t *in_args = (volatile uint32_t*)args;

	out_args[6] = *(uint64_t*)&in_args[9];
	out_args[5] = *(uint64_t*)&in_args[7];
	out_args[4] = in_args[6];
	out_args[3] = in_args[5];
	out_args[2] = *(uint64_t*)&in_args[3];
	out_args[1] = *(uint64_t*)&in_args[1];
	out_args[0] = in_args[0];
}

void 
munge_wwwlw(const void *arg0 __unused, void *args)
{
	volatile uint64_t *out_args = (volatile uint64_t*)args;
	volatile uint32_t *in_args = (volatile uint32_t*)args;

	out_args[4] = in_args[5];
	out_args[3] = *(uint64_t*)&in_args[3];
	out_args[2] = in_args[2];
	out_args[1] = in_args[1];
	out_args[0] = in_args[0];
}

void 
munge_wwwlww(const void *arg0 __unused, void *args)
{
	volatile uint64_t *out_args = (volatile uint64_t*)args;
	volatile uint32_t *in_args = (volatile uint32_t*)args;

	out_args[5] = in_args[6];
	out_args[4] = in_args[5];
	out_args[3] = *(uint64_t*)&in_args[3];
	out_args[2] = in_args[2];
	out_args[1] = in_args[1];
	out_args[0] = in_args[0];
}
	
void 
munge_wwwl(const void *arg0 __unused, void *args)
{
	volatile uint64_t *out_args = (volatile uint64_t*)args;
	volatile uint32_t *in_args = (volatile uint32_t*)args;

	out_args[3] = *(uint64_t*)&in_args[3];
	out_args[2] = in_args[2];
	out_args[1] = in_args[1];
	out_args[0] = in_args[0];
}

void 
munge_wwwwlw(const void *arg0 __unused, void *args)
{
	volatile uint64_t *out_args = (volatile uint64_t*)args;
	volatile uint32_t *in_args = (volatile uint32_t*)args;

	out_args[5] = in_args[6];
	out_args[4] = *(uint64_t*)&in_args[4];
	out_args[3] = in_args[3];
	out_args[2] = in_args[2];
	out_args[1] = in_args[1];
	out_args[0] = in_args[0];
}

void 
munge_wwwwl(const void *arg0 __unused, void *args)
{
	volatile uint64_t *out_args = (volatile uint64_t*)args;
	volatile uint32_t *in_args = (volatile uint32_t*)args;

	out_args[4] = *(uint64_t*)&in_args[4];
	out_args[3] = in_args[3];
	out_args[2] = in_args[2];
	out_args[1] = in_args[1];
	out_args[0] = in_args[0];
}

void 
munge_wwwwwl(const void *arg0 __unused, void *args)
{
	volatile uint64_t *out_args = (volatile uint64_t*)args;
	volatile uint32_t *in_args = (volatile uint32_t*)args;

	out_args[5] = *(uint64_t*)&in_args[5];
	out_args[4] = in_args[4];
	out_args[3] = in_args[3];
	out_args[2] = in_args[2];
	out_args[1] = in_args[1];
	out_args[0] = in_args[0];
}

void 
munge_wwwwwlww(const void *arg0 __unused, void *args)
{
	volatile uint64_t *out_args = (volatile uint64_t*)args;
	volatile uint32_t *in_args = (volatile uint32_t*)args;

	out_args[7] = in_args[8];
	out_args[6] = in_args[7];
	out_args[5] = *(uint64_t*)&in_args[5];
	out_args[4] = in_args[4];
	out_args[3] = in_args[3];
	out_args[2] = in_args[2];
	out_args[1] = in_args[1];
	out_args[0] = in_args[0];
}

void 
munge_wwwwwllw(const void *arg0 __unused, void *args)
{
	volatile uint64_t *out_args = (volatile uint64_t*)args;
	volatile uint32_t *in_args = (volatile uint32_t*)args;

	out_args[7] = in_args[9];
	out_args[6] = *(uint64_t*)&in_args[7];
	out_args[5] = *(uint64_t*)&in_args[5];
	out_args[4] = in_args[4];
	out_args[3] = in_args[3];
	out_args[2] = in_args[2];
	out_args[1] = in_args[1];
	out_args[0] = in_args[0];
}

void 
munge_wwwwwlll(const void *arg0 __unused, void *args)
{
	volatile uint64_t *out_args = (volatile uint64_t*)args;
	volatile uint32_t *in_args = (volatile uint32_t*)args;

	out_args[7] = *(uint64_t*)&in_args[9];
	out_args[6] = *(uint64_t*)&in_args[7];
	out_args[5] = *(uint64_t*)&in_args[5];
	out_args[4] = in_args[4];
	out_args[3] = in_args[3];
	out_args[2] = in_args[2];
	out_args[1] = in_args[1];
	out_args[0] = in_args[0];
}

void 
munge_wwwwwwl(const void *arg0 __unused, void *args)
{
	volatile uint64_t *out_args = (volatile uint64_t*)args;
	volatile uint32_t *in_args = (volatile uint32_t*)args;

	out_args[6] = *(uint64_t*)&in_args[6];
	out_args[5] = in_args[5];
	out_args[4] = in_args[4];
	out_args[3] = in_args[3];
	out_args[2] = in_args[2];
	out_args[1] = in_args[1];
	out_args[0] = in_args[0];
}
	
void 
munge_wwwwwwlw(const void *arg0 __unused, void *args)
{
	volatile uint64_t *out_args = (volatile uint64_t*)args;
	volatile uint32_t *in_args = (volatile uint32_t*)args;

	out_args[7] = in_args[8];
	out_args[6] = *(uint64_t*)&in_args[6];
	out_args[5] = in_args[5];
	out_args[4] = in_args[4];
	out_args[3] = in_args[3];
	out_args[2] = in_args[2];
	out_args[1] = in_args[1];
	out_args[0] = in_args[0];
}
	
void 
munge_wwwwwwll(const void *arg0 __unused, void *args)
{
	volatile uint64_t *out_args = (volatile uint64_t*)args;
	volatile uint32_t *in_args = (volatile uint32_t*)args;

	out_args[7] = *(uint64_t*)&in_args[8];
	out_args[6] = *(uint64_t*)&in_args[6];
	out_args[5] = in_args[5];
	out_args[4] = in_args[4];
	out_args[3] = in_args[3];
	out_args[2] = in_args[2];
	out_args[1] = in_args[1];
	out_args[0] = in_args[0];
}

void 
munge_wsw(const void *arg0 __unused, void *args)
{
	volatile uint64_t *out_args = (volatile uint64_t*)args;
	volatile uint32_t *in_args = (volatile uint32_t*)args;

	out_args[2] = in_args[2];
	out_args[1] = (int64_t)(int)in_args[1]; /* Sign-extend */
	out_args[0] = in_args[0];
}

void 
munge_wws(const void *arg0 __unused, void *args)
{
	volatile uint64_t *out_args = (volatile uint64_t*)args;
	volatile uint32_t *in_args = (volatile uint32_t*)args;

	out_args[2] = (int64_t)(int)in_args[2]; /* Sign-extend */
	out_args[1] = in_args[1];
	out_args[0] = in_args[0];
}

void 
munge_wwwsw(const void *arg0 __unused, void *args)
{
	volatile uint64_t *out_args = (volatile uint64_t*)args;
	volatile uint32_t *in_args = (volatile uint32_t*)args;

	out_args[4] = in_args[4];
	out_args[3] = (int64_t)(int)in_args[3]; /* Sign-extend */
	out_args[2] = in_args[2];
	out_args[1] = in_args[1];
	out_args[0] = in_args[0];
}

void 
munge_llllll(const void *arg0 __unused, void *args __unused)
{
	/* Nothing to do, already all 64-bit */
}

void 
munge_ll(const void *arg0 __unused, void *args __unused)
{
	/* Nothing to do, already all 64-bit */
}

void 
munge_l(const void *arg0 __unused, void *args __unused)
{
	/* Nothing to do, already all 64-bit */
}

void 
munge_lw(const void *arg0 __unused, void *args)
{
	volatile uint64_t *out_args = (volatile uint64_t*)args;
	volatile uint32_t *in_args = (volatile uint32_t*)args;

	out_args[1] = in_args[2];
	out_args[0] = *(uint64_t*)&in_args[0];
}

void 
munge_lwww(const void *arg0 __unused, void *args)
{
	volatile uint64_t *out_args = (volatile uint64_t*)args;
	volatile uint32_t *in_args = (volatile uint32_t*)args;

	out_args[3] = in_args[4]; 
	out_args[2] = in_args[3];
	out_args[1] = in_args[2];
	out_args[0] = *(uint64_t*)&in_args[0];
}

void
munge_wwlwww(const void *arg0 __unused, void *args)
{
	volatile uint64_t *out_args = (volatile uint64_t*)args;
	volatile uint32_t *in_args = (volatile uint32_t*)args;
	
	out_args[5] = in_args[6];
	out_args[4] = in_args[5];
	out_args[3] = in_args[4];
	out_args[2] = *(uint64_t*)&in_args[2];
	out_args[1] = in_args[1];
	out_args[0] = in_args[0];
}

/*
 * Munge array of 32-bit values into an array of 64-bit values,
 * without sign extension.  Note, src and dest can be the same 
 * (copies from end of array)
 */
static inline __attribute__((always_inline)) void 
munge_32_to_64_unsigned(volatile uint64_t *dest, volatile uint32_t *src, int count)
{
	int i;

	for (i = count - 1; i >= 0; i--) {
		dest[i] = src[i];
	}   
}

