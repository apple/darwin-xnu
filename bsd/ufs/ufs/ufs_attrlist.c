/*
 * Copyright (c) 2002-2004 Apple Computer, Inc. All rights reserved.
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
 * ufs_attrlist.c - UFS attribute list processing
 *
 * Copyright (c) 2002, Apple Computer, Inc.  All Rights Reserved.
 */

#include <sys/types.h>
#include <sys/systm.h>
#include <sys/vnode_internal.h>
#include <sys/malloc.h>
#include <sys/attr.h>
#include <sys/kernel.h>
#include <sys/kauth.h>

#include <ufs/ufs/dinode.h>
#include <ufs/ffs/fs.h>
#include <sys/mount_internal.h>
#include "ufsmount.h"

static char ufs_label_magic[4] = UFS_LABEL_MAGIC;

/* Copied from diskdev_cmds/disklib/ufslabel.c */
typedef union {
	char	c[2];
	u_short	s;
} short_union_t;

/* Copied from diskdev_cmds/disklib/ufslabel.c */
typedef union {
	u_short	s[2];
	long	l;
} long_union_t;

/* Copied from diskdev_cmds/disklib/ufslabel.c */
static __inline__ void
reduce(int *sum)
{
	long_union_t l_util;

	l_util.l = *sum;
	*sum = l_util.s[0] + l_util.s[1];
	if (*sum > 65535)
		*sum -= 65535;
	return;
}

/* Copied from diskdev_cmds/disklib/ufslabel.c */
__private_extern__ unsigned short
ul_cksum(void *data, int len)
{
	u_short	*w;
	int	 sum;

	sum = 0;
	w = (u_short *)data;
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
	if (len == -1) { /* odd-length data */
		short_union_t s_util;

		s_util.s = 0;
		s_util.c[0] = *((char *)w);
		s_util.c[1] = 0;
		sum += s_util.s;
	}
	reduce(&sum);
	return (~sum & 0xffff);
}

/* Adapted from diskdev_cmds/disklib/ufslabel.c */
__private_extern__ boolean_t
ufs_label_check(struct ufslabel *ul_p)
{
	u_int16_t	calc;
	u_int16_t 	checksum;

	if (bcmp(&ul_p->ul_magic, ufs_label_magic, 
	    sizeof(ul_p->ul_magic))) {
#ifdef DEBUG
		printf("ufslabel_check: label has bad magic number\n");
#endif
		return (FALSE);
	}
	if (ntohl(ul_p->ul_version) != UFS_LABEL_VERSION) {
#ifdef DEBUG
		printf("ufslabel_check: label has incorect version %d "
		    "(should be %d)\n", ntohl(ul_p->ul_version),
		    UFS_LABEL_VERSION);
#endif
		return (FALSE);
	}
	if (ntohs(ul_p->ul_namelen) > UFS_MAX_LABEL_NAME) {
#ifdef DEBUG
		printf("ufslabel_check: name length %d is too big (> %d)\n",
		    ntohs(ul_p->ul_namelen), UFS_MAX_LABEL_NAME);
#endif
		return (FALSE);
	}

	checksum = ul_p->ul_checksum;	/* Remember previous checksum. */
	ul_p->ul_checksum = 0;
	calc = ul_cksum(ul_p, sizeof(*ul_p));
	if (calc != checksum) {
#ifdef DEBUG
		printf("ufslabel_check: label checksum %x (should be %x)\n",
		    checksum, calc);
#endif
		return (FALSE);
	}
	return (TRUE);
}

__private_extern__ void
ufs_label_init(struct ufslabel *ul_p)
{
	struct timeval tv;

	microtime(&tv);

	bzero(ul_p, sizeof(*ul_p));
	ul_p->ul_version = htonl(UFS_LABEL_VERSION);
	bcopy(ufs_label_magic, &ul_p->ul_magic, sizeof(ul_p->ul_magic));
	ul_p->ul_time = htonl(tv.tv_sec);
}

