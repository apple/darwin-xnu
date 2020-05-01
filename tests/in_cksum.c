/*
 * Copyright (c) 2000-2018 Apple Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 *
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this
 * file.
 *
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 *
 * @APPLE_LICENSE_HEADER_END@
 */

/*
 * Copyright (c) 1988, 1992, 1993
 *	The Regents of the University of California.  All rights reserved.
 *
 *	@(#)in_cksum.c	8.1 (Berkeley) 6/10/93
 */

#include <sys/param.h>
#include "in_cksum.h"

typedef union {
	char        c[2];
	u_short     s;
} short_union_t;

typedef union {
	u_short     s[2];
	long        l;
} long_union_t;

static __inline__ void
reduce(int * sum)
{
	long_union_t l_util;

	l_util.l = *sum;
	*sum = l_util.s[0] + l_util.s[1];
	if (*sum > 65535) {
		*sum -= 65535;
	}
	return;
}


#include <stdio.h>

unsigned short
in_cksum(void * pkt, int len)
{
	u_short * w;
	int sum = 0;

	w = (u_short *)pkt;
	while ((len -= 32) >= 0) {
		sum += w[0]; sum += w[1];
		sum += w[2]; sum += w[3];
		sum += w[4]; sum += w[5];
		sum += w[6]; sum += w[7];
		sum += w[8]; sum += w[9];
		sum += w[10]; sum += w[11];
		sum += w[12]; sum += w[13];
		sum += w[14]; sum += w[15];
		w += 16;
	}
	len += 32;
	while ((len -= 8) >= 0) {
		sum += w[0]; sum += w[1];
		sum += w[2]; sum += w[3];
		w += 4;
	}
	len += 8;
	if (len) {
		reduce(&sum);
		while ((len -= 2) >= 0) {
			sum += *w++;
		}
	}
	if (len == -1) { /* odd-length packet */
		short_union_t s_util;

		s_util.s = 0;
		s_util.c[0] = *((char *)w);
		s_util.c[1] = 0;
		sum += s_util.s;
	}
	reduce(&sum);
	return ~sum & 0xffff;
}
