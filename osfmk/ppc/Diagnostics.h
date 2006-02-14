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
 * @OSF_FREE_COPYRIGHT@
 */
/*
 * @APPLE_FREE_COPYRIGHT@
 */

/*
 * Here are the Diagnostic interface interfaces
 * Lovingly crafted by Bill Angell using traditional methods
*/
#ifdef	KERNEL_PRIVATE

#ifndef _DIAGNOSTICS_H_
#define _DIAGNOSTICS_H_

#ifndef __ppc__
#error This file is only useful on PowerPC.
#endif
#include <ppc/savearea.h>

int diagCall(struct savearea *save);

#define diagSCnum 0x00006000

#define dgAdjTB 0
#define dgLRA 1
#define dgpcpy 2
#define dgreset 3
#define dgtest 4
#define dgBMphys 5
#define dgUnMap 6
#define dgBootScreen 7
#define dgFlush 8
#define dgAlign 9
#define dgprw 10
#define dgmck 11
#define dg64 12
#define dgProbeRead 13
#define dgCPNull 14
#define dgPerfMon 15
#define dgMapPage 16
#define dgScom 17
#define dgBind 18
#define dgPproc 19
#define dgAcntg 20
#define dgKlra 21
#define dgKfree 22
#define	dgWar 23


typedef struct diagWork {			/* Diagnostic work area */

	unsigned int dgLock;			/* Lock if needed */
	unsigned int dgFlags;			/* Flags */
#define enaExpTrace 0x00000001
#define enaExpTraceb 31
#define enaUsrFCall 0x00000002
#define enaUsrFCallb 30
#define enaUsrPhyMp 0x00000004
#define enaUsrPhyMpb 29
#define enaDiagSCs  0x00000008
#define enaDiagSCsb  28
#define enaDiagDM  0x00000010
#define enaDiagSDMb  27
#define enaDiagEM  0x00000020
#define enaDiagEMb  26
#define enaDiagTrap  0x00000040
#define enaDiagTrapb  25
#define enaNotifyEM  0x00000080
#define enaNotifyEMb  24
	
	unsigned int dgMisc0;
	unsigned int dgMisc1;
	unsigned int dgMisc2;
	unsigned int dgMisc3;
	unsigned int dgMisc4;
	unsigned int dgMisc5;

} diagWork;

typedef struct scomcomm {
	uint16_t	scomcpu;	/* CPU number */
	uint16_t	scomfunc;	/* 0 = read; 1 = write */
	uint32_t	scomreg;	/* SCOM register */
	uint64_t	scomstat;	/* returned status */
	uint64_t	scomdata;	/* input for write,  output for read */
} scomcomm;

extern diagWork dgWork;
extern int diagTrap(struct savearea *, unsigned int);


#endif /* _DIAGNOSTICS_H_ */

#endif /* KERNEL_PRIVATE */
