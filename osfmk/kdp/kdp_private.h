/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * The contents of this file constitute Original Code as defined in and
 * are subject to the Apple Public Source License Version 1.1 (the
 * "License").  You may not use this file except in compliance with the
 * License.  Please obtain a copy of the License at
 * http://www.apple.com/publicsource and read it before using this file.
 * 
 * This Original Code and all software distributed under the License are
 * distributed on an "AS IS" basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE OR NON-INFRINGEMENT.  Please see the
 * License for the specific language governing rights and limitations
 * under the License.
 * 
 * @APPLE_LICENSE_HEADER_END@
 */

/*
 * Private functions for kdp.c
 */

static boolean_t
kdp_unknown(
    kdp_pkt_t *,
    int *,
    unsigned short *
);

static boolean_t
kdp_connect(
    kdp_pkt_t *,
    int *,
    unsigned short *
);

static boolean_t
kdp_disconnect(
    kdp_pkt_t *,
    int *,
    unsigned short *
);

static boolean_t
kdp_reattach(
    kdp_pkt_t *,
    int *,
    unsigned short *
);

static boolean_t
kdp_hostinfo(
    kdp_pkt_t *,
    int *,
    unsigned short *
);

static boolean_t
kdp_suspend(
    kdp_pkt_t *,
    int *,
    unsigned short *
);

static boolean_t
kdp_readregs(
    kdp_pkt_t *,
    int *,
    unsigned short *
);

static boolean_t
kdp_writeregs(
    kdp_pkt_t *,
    int *,
    unsigned short *
);

static boolean_t
kdp_version(
    kdp_pkt_t *,
    int *,
    unsigned short *
);

static boolean_t
kdp_regions(
    kdp_pkt_t *,
    int *,
    unsigned short *
);

static boolean_t
kdp_maxbytes(
    kdp_pkt_t *,
    int *,
    unsigned short *
);

static boolean_t
kdp_readmem(
    kdp_pkt_t *,
    int *,
    unsigned short *
);

static boolean_t
kdp_writemem(
    kdp_pkt_t *,
    int *,
    unsigned short *
);

static boolean_t
kdp_resumecpus(
    kdp_pkt_t *,
    int *,
    unsigned short *
);

static boolean_t 
kdp_breakpoint_set(
    kdp_pkt_t *,
    int	*,
    unsigned short *t
);

static boolean_t
kdp_breakpoint_remove(
    kdp_pkt_t *,
    int	*,
    unsigned short *
);

