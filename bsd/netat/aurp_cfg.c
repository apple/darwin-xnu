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
 *	Copyright (c) 1996 Apple Computer, Inc. 
 *
 *		Created April 8, 1996 by Tuyen Nguyen
 *   Modified, March 17, 1997 by Tuyen Nguyen for MacOSX.
 *
 *	File: cfg.c
 */
 
#ifdef AURP_SUPPORT

#define RESOLVE_DBG
#include <sys/errno.h>
#include <sys/types.h>
#include <sys/param.h>
#include <machine/spl.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/proc.h>
#include <sys/filedesc.h>
#include <sys/fcntl.h>
#include <sys/mbuf.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <net/if.h>

#include <netat/sysglue.h>
#include <netat/appletalk.h>
#include <netat/at_var.h>
#include <netat/routing_tables.h>
#include <netat/at_pcb.h>
#include <netat/aurp.h>

static int aurp_inited = 0;
static char aurp_minor_no[4];

int aurp_open(gref)
	gref_t *gref;
{
	extern void AURPcmdx();
	int i;

	if (!aurp_inited)
		aurp_inited = 1;

	for (i=1; i < sizeof(aurp_minor_no); i++) {
		if (aurp_minor_no[i] == 0) {
			aurp_minor_no[i] = (char )i;
			break;
		}
	}
	if (i == sizeof(aurp_minor_no))
		return EAGAIN;
	if (i == 1) {
		aurp_gref = gref;
		if (ddp_AURPfuncx(AURPCODE_REG, AURPcmdx, 0)) {
			aurp_gref = 0;
			aurp_minor_no[i] = 0;
			return EPROTOTYPE;
		}
	}

	gref->info = (void *)&aurp_minor_no[i];
	return 0;
}

int aurp_close(gref)
	gref_t *gref;
{
	if (*(char *)gref->info == 1) {
		aurp_gref = 0;
		aurp_inited = 0;
		ddp_AURPfuncx(AURPCODE_REG, 0, 0);
	}

	*(char *)gref->info = 0;
	gref->info = 0;
	return 0;
}

