/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * Copyright (c) 1999-2003 Apple Computer, Inc.  All Rights Reserved.
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
 * @OSF_COPYRIGHT@
 */

#ifndef _PEXPERT_PPC_DBDMA_H_
#define _PEXPERT_PPC_DBDMA_H_

#ifndef ASSEMBLER

#define	DBDMA_CMD_OUT_MORE	0
#define	DBDMA_CMD_OUT_LAST	1
#define	DBDMA_CMD_IN_MORE	2
#define	DBDMA_CMD_IN_LAST	3
#define	DBDMA_CMD_STORE_QUAD	4
#define	DBDMA_CMD_LOAD_QUAD	5
#define	DBDMA_CMD_NOP		6
#define	DBDMA_CMD_STOP		7

/* Keys */

#define	DBDMA_KEY_STREAM0	0
#define	DBDMA_KEY_STREAM1	1
#define	DBDMA_KEY_STREAM2	2
#define	DBDMA_KEY_STREAM3	3

/* value 4 is reserved */
#define	DBDMA_KEY_REGS		5
#define	DBDMA_KEY_SYSTEM	6
#define	DBDMA_KEY_DEVICE	7

#define	DBDMA_INT_NEVER		0
#define	DBDMA_INT_IF_TRUE	1
#define	DBDMA_INT_IF_FALSE	2
#define	DBDMA_INT_ALWAYS	3

#define	DBDMA_BRANCH_NEVER	0
#define	DBDMA_BRANCH_IF_TRUE	1
#define	DBDMA_BRANCH_IF_FALSE	2
#define	DBDMA_BRANCH_ALWAYS	3

#define	DBDMA_WAIT_NEVER	0
#define	DBDMA_WAIT_IF_TRUE	1
#define DBDMA_WAIT_IF_FALSE	2
#define	DBDMA_WAIT_ALWAYS	3

/* Control register values (in little endian) */

#define	DBDMA_STATUS_MASK	0x000000ff	/* Status Mask */
#define	DBDMA_CNTRL_BRANCH	0x00000100
				/* 0x200 reserved */
#define	DBDMA_CNTRL_ACTIVE	0x00000400
#define	DBDMA_CNTRL_DEAD	0x00000800
#define	DBDMA_CNTRL_WAKE	0x00001000
#define	DBDMA_CNTRL_FLUSH	0x00002000
#define	DBDMA_CNTRL_PAUSE	0x00004000
#define	DBDMA_CNTRL_RUN		0x00008000

#define	DBDMA_SET_CNTRL(x)	( ((x) | (x) << 16) )
#define	DBDMA_CLEAR_CNTRL(x)	( (x) << 16)

#define POWERMAC_IO(a) (a)
#define	DBDMA_REGMAP(channel) \
		(dbdma_regmap_t *)((v_u_char *) POWERMAC_IO(PCI_DMA_BASE_PHYS) \
				+ (channel << 8))


/* powermac_dbdma_channels hold the physical channel numbers for
 * each dbdma device
 */


/* This struct is layout in little endian format */

struct dbdma_command {
	unsigned long	d_cmd_count;
	unsigned long	d_address;
	unsigned long	d_cmddep;
	unsigned long	d_status_resid;
};

typedef struct dbdma_command dbdma_command_t;

#define	DBDMA_BUILD(d, cmd, key, count, address, interrupt, wait, branch) {\
		DBDMA_ST4_ENDIAN(&d->d_address, address); \
		(d)->d_status_resid = 0; \
		(d)->d_cmddep = 0; \
		DBDMA_ST4_ENDIAN(&d->d_cmd_count, \
				((cmd) << 28) | ((key) << 24) |\
				((interrupt) << 20) |\
				((branch) << 18) | ((wait) << 16) | \
				(count)); \
	}

static __inline__ void
dbdma_st4_endian(volatile unsigned long *a, unsigned long x)
{
	__asm__ volatile
		("stwbrx %0,0,%1" : : "r" (x), "r" (a) : "memory");

	return;
}

static __inline__ unsigned long
dbdma_ld4_endian(volatile unsigned long *a)
{
	unsigned long swap;

	__asm__ volatile
		("lwbrx %0,0,%1" :  "=r" (swap) : "r" (a));

	return	swap;
}

#define	DBDMA_LD4_ENDIAN(a) 	dbdma_ld4_endian(a)
#define	DBDMA_ST4_ENDIAN(a, x) 	dbdma_st4_endian(a, x)

/*
 * DBDMA Channel layout
 *
 * NOTE - This structure is in little-endian format. 
 */

struct dbdma_regmap {
	unsigned long	d_control;	/* Control Register */
	unsigned long	d_status;	/* DBDMA Status Register */
	unsigned long	d_cmdptrhi;	/* MSB of command pointer (not used yet) */
	unsigned long	d_cmdptrlo;	/* LSB of command pointer */
	unsigned long	d_intselect;	/* Interrupt Select */
	unsigned long	d_branch;	/* Branch selection */
	unsigned long	d_wait;		/* Wait selection */
	unsigned long	d_transmode;	/* Transfer modes */
	unsigned long	d_dataptrhi;	/* MSB of Data Pointer */
	unsigned long	d_dataptrlo;	/* LSB of Data Pointer */
	unsigned long	d_reserved;	/* Reserved for the moment */
	unsigned long	d_branchptrhi;	/* MSB of Branch Pointer */
	unsigned long	d_branchptrlo;	/* LSB of Branch Pointer */
	/* The remaining fields are undefinied and unimplemented */
};

typedef volatile struct dbdma_regmap dbdma_regmap_t;

/* DBDMA routines */

void	dbdma_start(dbdma_regmap_t *channel, dbdma_command_t *commands);
void	dbdma_stop(dbdma_regmap_t *channel);	
void	dbdma_flush(dbdma_regmap_t *channel);
void	dbdma_reset(dbdma_regmap_t *channel);
void	dbdma_continue(dbdma_regmap_t *channel);
void	dbdma_pause(dbdma_regmap_t *channel);

dbdma_command_t	*dbdma_alloc(int);	/* Allocate command structures */

#endif /* ASSEMBLER */

#endif /* _PEXPERT_PPC_DBDMA_H_ */
