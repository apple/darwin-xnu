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
 * Copyright (c) 1993 NeXT Computer, Inc.  All rights reserved.
 *
 * kdp_internal.h -- internal definitions for kdp module
 *
 */

#include <kdp/kdp.h>
#include <kdp/kdp_protocol.h>

typedef struct {
    unsigned short		reply_port;
    unsigned int		conn_seq;
    boolean_t			is_conn;
    void			*saved_state;
    boolean_t			is_halted;
    unsigned short		exception_port;
    unsigned char		exception_seq;
    boolean_t			exception_ack_needed;
} kdp_glob_t;

extern kdp_glob_t	kdp;
extern int		kdp_flag;

typedef boolean_t
(*kdp_dispatch_t) (
    kdp_pkt_t *,
    int	 *,
    unsigned short *
);

boolean_t
kdp_packet(
    unsigned char *,
    int *,
    unsigned short *
);

void
kdp_exception(
    unsigned char *,
    int *,
    unsigned short *,
    unsigned int,
    unsigned int,
    unsigned int
);

boolean_t
kdp_exception_ack(
    unsigned char *,
    int
);

void
kdp_panic(
    const char		*msg
);

void
kdp_reset(
    void
);

void
kdp_reboot(
    void
);

void
kdp_us_spin(
    int usec
);

int
kdp_intr_disbl(
    void
);

void
kdp_intr_enbl(
    int s
);

kdp_error_t
kdp_machine_read_regs(
    unsigned int cpu,
    unsigned int flavor,
    char *data,
    int *size
);

kdp_error_t
kdp_machine_write_regs(
    unsigned int cpu,
    unsigned int flavor,
    char *data,
    int *size
);

void
kdp_machine_hostinfo(
    kdp_hostinfo_t *hostinfo
);

void
kdp_sync_cache(
    void
);


