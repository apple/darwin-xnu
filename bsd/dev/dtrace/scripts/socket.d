/*
 * Copyright (c) 2013 Apple Computer, Inc.  All Rights Reserved.
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

#pragma D depends_on library darwin.d
#pragma D depends_on module mach_kernel

typedef struct socketbuf {
	uint32_t	cc;
	uint32_t	hiwat;
	uint32_t	lowat;
	uint32_t	mbcnt;
	uint32_t	mbmax;
	uint32_t	flags;
	struct sockbuf	*sockbuf;
} socketbuf_t;

translator socketbuf_t < struct sockbuf *T > {
	cc	= T->sb_cc;
	hiwat	= T->sb_hiwat;
	lowat	= T->sb_lowat;
	mbcnt	= T->sb_mbcnt;
	mbmax	= T->sb_mbmax;
	flags	= T->sb_flags;
	sockbuf = T;
};

typedef struct socketinfo {
	int		zone;
	short		type;
	uint32_t	options;
	short		linger;
	short		state;
	short		qlen;
	short		incqlen;
	short		qlimit;
	short		error;
	uint32_t	flags;
	int		traffic_class;
	struct socket	*socket;
} socketinfo_t;

translator socketinfo_t < struct socket *T > {
	zone		= T->so_zone;
	type		= T->so_type;
	options		= T->so_options;
	linger		= T->so_linger;
	state		= T->so_state;
	qlen		= T->so_qlen;
	incqlen		= T->so_incqlen;
	qlimit		= T->so_qlimit;
	error		= T->so_error;
	flags		= T->so_flags;
	traffic_class	= T->so_traffic_class;
	socket		= T;
};


