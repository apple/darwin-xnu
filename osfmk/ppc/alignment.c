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
 * Copyright 1996 1995 by Open Software Foundation, Inc. 1997 1996 1995 1994 1993 1992 1991  
 *              All Rights Reserved 
 *  
 * Permission to use, copy, modify, and distribute this software and 
 * its documentation for any purpose and without fee is hereby granted, 
 * provided that the above copyright notice appears in all copies and 
 * that both the copyright notice and this permission notice appear in 
 * supporting documentation. 
 *  
 * OSF DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE 
 * INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS 
 * FOR A PARTICULAR PURPOSE. 
 *  
 * IN NO EVENT SHALL OSF BE LIABLE FOR ANY SPECIAL, INDIRECT, OR 
 * CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM 
 * LOSS OF USE, DATA OR PROFITS, WHETHER IN ACTION OF CONTRACT, 
 * NEGLIGENCE, OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION 
 * WITH THE USE OR PERFORMANCE OF THIS SOFTWARE. 
 * 
 */
/*
 * Copyright 1996 1995 by Apple Computer, Inc. 1997 1996 1995 1994 1993 1992 1991  
 *              All Rights Reserved 
 *  
 * Permission to use, copy, modify, and distribute this software and 
 * its documentation for any purpose and without fee is hereby granted, 
 * provided that the above copyright notice appears in all copies and 
 * that both the copyright notice and this permission notice appear in 
 * supporting documentation. 
 *  
 * APPLE COMPUTER DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE 
 * INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS 
 * FOR A PARTICULAR PURPOSE. 
 *  
 * IN NO EVENT SHALL APPLE COMPUTER BE LIABLE FOR ANY SPECIAL, INDIRECT, OR 
 * CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM 
 * LOSS OF USE, DATA OR PROFITS, WHETHER IN ACTION OF CONTRACT, 
 * NEGLIGENCE, OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION 
 * WITH THE USE OR PERFORMANCE OF THIS SOFTWARE. 
 */

#include <debug.h>
#include <kern/thread_act.h>
#include <mach/thread_status.h>
#include <mach/boolean.h>
#include <kern/misc_protos.h>
#include <kern/simple_lock.h>
#include <ppc/proc_reg.h>
#include <ppc/fpu_protos.h>
#include <ppc/misc_protos.h>
#include <ppc/exception.h>

#if DEBUG
/* These variable may be used to keep track of alignment exceptions */
int alignment_exception_count_user;
int alignment_exception_count_kernel;
#endif

#define	_AINST(x)	boolean_t  align_##x##(unsigned long dsisr,\
					       struct ppc_saved_state *ssp, \
					       struct ppc_float_state *fsp, \
					       unsigned long *align_buffer, \
					       unsigned long dar)


#define	_AFENTRY(name, r, b)	{ #name, align_##name##, r, b, TRUE }
#define	_AENTRY(name, r, b)	{ #name, align_##name##, r, b, FALSE }
#define	_ANIL			{ (void *) 0, (void *) 0, 0, 0 }

_AINST(lwz);
_AINST(stw);
_AINST(lhz);
_AINST(lha);
_AINST(sth);
_AINST(lmw);
_AINST(lfs);
_AINST(lfd);
_AINST(stfs);
_AINST(stfd);
_AINST(lwzu);
_AINST(stwu);
_AINST(lhzu);
_AINST(lhau);
_AINST(sthu);
_AINST(lfsu);
_AINST(lfdu);
_AINST(stfsu);
_AINST(stfdu);
_AINST(lswx);
_AINST(lswi);
_AINST(lwbrx);
_AINST(stwbrx);
_AINST(lhbrx);
_AINST(sthbrx);
_AINST(dcbz);
_AINST(lwzx);
_AINST(stwx);
_AINST(lhzx);
_AINST(lhax);
_AINST(sthx);
_AINST(lfsx);
_AINST(lfdx);
_AINST(stfsx);
_AINST(stfdx);
_AINST(lwzux);
_AINST(stwux);
_AINST(lhzux);
_AINST(lhaux);
_AINST(sthux);
_AINST(stmw);
_AINST(lfsux);
_AINST(lfdux);
_AINST(stfsux);
_AINST(stfdux);

/*
 * Routines to set and get FPU registers.
 */

void GET_FPU_REG(struct ppc_float_state *fsp,
		 unsigned long reg,
		 unsigned long *value);
void SET_FPU_REG(struct ppc_float_state *fsp,
		 unsigned long reg,
		 unsigned long *value);

__inline__ void GET_FPU_REG(struct ppc_float_state *fsp,
			    unsigned long reg,
			    unsigned long *value)
{
	value[0] = ((unsigned long *) &fsp->fpregs[reg])[0];
	value[1] = ((unsigned long *) &fsp->fpregs[reg])[1];
}

__inline__ void SET_FPU_REG(struct ppc_float_state *fsp,
			    unsigned long reg, unsigned long *value)
{
	((unsigned long *) &fsp->fpregs[reg])[0] = value[0]; 
	((unsigned long *) &fsp->fpregs[reg])[1] = value[1];
}


/*
 * Macros to load and set registers according to 
 * a given cast type.
 */

#define	GET_REG(p, reg, value, cast) \
	{ *((cast *) value) = *((cast *) (&p->r0+reg)); }
#define	SET_REG(p, reg, value, cast) \
	{ *((cast *) (&p->r0+reg)) = *((cast *) value); }

/*
 * Macros to help decode the DSISR.
 */

#define	DSISR_BITS_15_16(bits)	((bits>>15) & 0x3)
#define	DSISR_BITS_17_21(bits)	((bits>>10) & 0x1f)	
#define	DSISR_BITS_REG(bits)	((bits>>5) & 0x1f)
#define	DSISR_BITS_RA(bits)	(bits & 0x1f)


struct ppc_align_instruction {
	char		*name;
	boolean_t	(*a_instruct)(unsigned long,
				      struct ppc_saved_state *,
				      struct ppc_float_state *,
				      unsigned long *,
				      unsigned long );
	int		a_readbytes;
	int		a_writebytes;
	boolean_t	a_is_float;
} align_table00[] = {
_AENTRY(lwz, 4, 0),	/* 00 0 0000 */
_ANIL,			/* 00 0 0001 */
_AENTRY(stw, 0, 4),	/* 00 0 0010 */
_ANIL,			/* 00 0 0011 */
_AENTRY(lhz, 2, 0),	/* 00 0 0100 */
_AENTRY(lha, 2, 0),	/* 00 0 0101 */
_AENTRY(sth, 0, 2),	/* 00 0 0110 */
_AENTRY(lmw, 32*4,0),	/* 00 0 0111 */
_AFENTRY(lfs, 4, 0),	/* 00 0 1000 */
_AFENTRY(lfd, 8, 0),	/* 00 0 1001 */
_AFENTRY(stfs, 0, 4),	/* 00 0 1010 */
_AFENTRY(stfd, 0, 8),	/* 00 0 1011 */
_ANIL,			/* 00 0 1100 ?*/
_ANIL,			/* 00 0 1101 - lwa */
_ANIL,			/* 00 0 1110 ?*/
_ANIL,			/* 00 0 1111 - std */
_AENTRY(lwzu, 4, 0),	/* 00 1 0000 */
_ANIL,			/* 00 1 0001 ?*/
_AENTRY(stwu, 0, 4),	/* 00 1 0010 */
_ANIL,			/* 00 1 0011 */
_AENTRY(lhzu, 2, 0),	/* 00 1 0100 */
_AENTRY(lhau, 2, 0),	/* 00 1 0101 */
_AENTRY(sthu, 0, 2),	/* 00 1 0110 */
_AENTRY(stmw, 0, 0),	/* 00 1 0111 */
_AFENTRY(lfsu, 4, 0),	/* 00 1 1000 */
_AFENTRY(lfdu, 8, 0),	/* 00 1 1001 - lfdu */
_AFENTRY(stfsu, 0, 4),	/* 00 1 1010 */
_AFENTRY(stfdu, 0, 8),	/* 00 1 1011 - stfdu */
};

struct ppc_align_instruction align_table01[] = {
_ANIL,			/* 01 0 0000 - ldx */
_ANIL,			/* 01 0 0001 ?*/
_ANIL,			/* 01 0 0010 - stdx */
_ANIL,			/* 01 0 0011 ?*/
_ANIL,			/* 01 0 0100 ?*/
_ANIL,			/* 01 0 0101 - lwax */
_ANIL,			/* 01 0 0110 ?*/
_ANIL,			/* 01 0 0111 ?*/
_AENTRY(lswx,32, 0),	/* 01 0 1000 - lswx */
_AENTRY(lswi,32, 0),	/* 01 0 1001 - lswi */
_ANIL,			/* 01 0 1010 - stswx */
_ANIL,			/* 01 0 1011 - stswi */
_ANIL,			/* 01 0 1100 ?*/
_ANIL,			/* 01 0 1101 ?*/
_ANIL,			/* 01 0 1110 ?*/
_ANIL,			/* 01 0 1111 ?*/
_ANIL,			/* 01 1 0000 - ldux */
_ANIL,			/* 01 1 0001 ?*/
_ANIL,			/* 01 1 0010 - stdux */
_ANIL,			/* 01 1 0011 ?*/
_ANIL,			/* 01 1 0100 ?*/
_ANIL,			/* 01 1 0101 - lwaux */
};

struct ppc_align_instruction align_table10[] = {
_ANIL,			/* 10 0 0000 ?*/
_ANIL,			/* 10 0 0001 ?*/
_ANIL,			/* 10 0 0010 - stwcx. */
_ANIL,			/* 10 0 0011 - stdcx.*/
_ANIL,			/* 10 0 0100 ?*/
_ANIL,			/* 10 0 0101 ?*/
_ANIL,			/* 10 0 0110 ?*/
_ANIL,			/* 10 0 0111 ?*/
_AENTRY(lwbrx, 4, 0),	/* 10 0 1000 */
_ANIL,			/* 10 0 1001 ?*/
_AENTRY(stwbrx, 0, 4),	/* 10 0 1010 */
_ANIL,			/* 10 0 1011 */
_AENTRY(lhbrx, 2, 0),	/* 10 0 1110 */
_ANIL,			/* 10 0 1101 ?*/
_AENTRY(sthbrx, 0, 2),	/* 10 0 1110 */
_ANIL,			/* 10 0 1111 ?*/
_ANIL,			/* 10 1 0000 ?*/
_ANIL,			/* 10 1 0001 ?*/
_ANIL,			/* 10 1 0010 ?*/
_ANIL,			/* 10 1 0011 ?*/
_ANIL,			/* 10 1 0100 - eciwx */
_ANIL,			/* 10 1 0101 ?*/
_ANIL,			/* 10 1 0110 - ecowx */
_ANIL,			/* 10 1 0111 ?*/
_ANIL,			/* 10 1 1000 ?*/
_ANIL,			/* 10 1 1001 ?*/
_ANIL,			/* 10 1 1010 ?*/
_ANIL,			/* 10 1 1011 ?*/
_ANIL,			/* 10 1 1100 ?*/
_ANIL,			/* 10 1 1101 ?*/
_ANIL,			/* 10 1 1110 ?*/
_AENTRY(dcbz, 0, 0),	/* 10 1 1111 */
};

struct ppc_align_instruction align_table11[] = {
_AENTRY(lwzx, 4, 0),	/* 11 0 0000 */
_ANIL,			/* 11 0 0001 ?*/
_AENTRY(stwx, 0, 4),	/* 11 0 0010 */
_ANIL,			/* 11 0 0011 */
_AENTRY(lhzx, 2, 0),	/* 11 0 0100 */
_AENTRY(lhax, 2, 0),	/* 11 0 0101 */
_AENTRY(sthx, 0, 2),	/* 11 0 0110 */
_ANIL,			/* 11 0 0111?*/
_AFENTRY(lfsx, 4, 0),	/* 11 0 1000 */
_AFENTRY(lfdx, 8, 0),	/* 11 0 1001 */
_AFENTRY(stfsx, 0, 4),	/* 11 0 1010 */
_AFENTRY(stfdx, 0, 8),	/* 11 0 1011 */
_ANIL,			/* 11 0 1100 ?*/
_ANIL,			/* 11 0 1101 ?*/
_ANIL,			/* 11 0 1110 ?*/
_ANIL,			/* 11 0 1111 - stfiwx */
_AENTRY(lwzux, 4, 0),	/* 11 1 0000 */
_ANIL,			/* 11 1 0001 ?*/
_AENTRY(stwux, 0, 4),	/* 11 1 0010 */
_ANIL,			/* 11 1 0011 */
_AENTRY(lhzux, 4, 0),	/* 11 1 0100 */
_AENTRY(lhaux, 4, 0),	/* 11 1 0101 */
_AENTRY(sthux, 0, 4),	/* 11 1 0110 */
_ANIL,			/* 11 1 0111 ?*/
_AFENTRY(lfsux, 4, 0),	/* 11 1 1000 */
_AFENTRY(lfdux, 8, 0),	/* 11 1 1001 */
_AFENTRY(stfsux, 0, 4),	/* 11 1 1010 */
_AFENTRY(stfdux, 0, 8),	/* 11 1 1011 */
};


struct ppc_align_instruction_table {
	struct ppc_align_instruction	*table;
	int				size;
} align_tables[4] = {
	align_table00, 	sizeof(align_table00)/
			sizeof(struct ppc_align_instruction),

	align_table01, 	sizeof(align_table01)/
			sizeof(struct ppc_align_instruction),

	align_table10, 	sizeof(align_table10)/
			sizeof(struct ppc_align_instruction),

	align_table11, 	sizeof(align_table11)/
			sizeof(struct ppc_align_instruction)
};

extern int 		real_ncpus;						/* Number of actual CPUs */

/*
 * Alignment Exception Handler
 *
 *
 * This handler is called when the chip attempts
 * to execute an instruction which causes page
 * boundaries to be crossed. Typically, this will
 * happen on stfd* and lfd* instructions.
 * (A request has been made for GNU C compiler
 * NOT to make use of these instructions to 
 * load and store 8 bytes at a time.)
 *
 * This is a *SLOW* handler. There is room for vast
 * improvement. However, it is expected that alignment
 * exceptions will be very infrequent.
 *
 * Not all of the 64 instructions (as listed in 
 * PowerPC Microprocessor Family book under the Alignment
 * Exception section) are handled yet.
 * Only the most common ones which are expected to
 * happen.
 * 
 * -- Michael Burg, Apple Computer, Inc. 1996
 *
 * TODO NMGS finish handler
 */

boolean_t
alignment(unsigned long dsisr, unsigned long dar,
	       struct ppc_saved_state *ssp)
{
	struct ppc_align_instruction_table	*table;
	struct ppc_align_instruction		*entry;
	struct ppc_float_state 				*fpc;
	unsigned long		align_buffer[32];
	boolean_t		success = FALSE;
	thread_act_t act;
	spl_t			s;
	int i;

#if	DEBUG
	if (USER_MODE(ssp->srr1))	(void)hw_atomic_add(&alignment_exception_count_user, 1);
	else 						(void)hw_atomic_add(&alignment_exception_count_kernel, 1);
#endif

	act = current_act();						/* Get the current activation */

	table = &align_tables[DSISR_BITS_15_16(dsisr)];

	if (table == (void *) 0
	|| table->size < DSISR_BITS_17_21(dsisr)) {
#if	DEBUG
		printf("EXCEPTION NOT HANDLED: Out of range.\n");
		printf("dsisr=%X, dar=%X\n",dsisr, dar);
		printf("table=%X\n",DSISR_BITS_15_16(dsisr));
		printf("table->size=%X\n", table->size);
		printf("entry=%X\n",DSISR_BITS_17_21(dsisr));
#endif
		goto out;
	}

	entry = &table->table[DSISR_BITS_17_21(dsisr)];

	if (entry->a_instruct == (void *) 0) {
#if	DEBUG
		printf("EXCEPTION NOT HANDLED: Inst out of table range.\n");
		printf("table=%X\n",DSISR_BITS_15_16(dsisr));
		printf("entry=%X\n",DSISR_BITS_17_21(dsisr));
#endif
		goto out;
	}

	/*
	 * Check to see if the instruction is a 
	 * floating point operation. Save off
	 * the FPU register set ...
	 */

	if (entry->a_is_float)
		fpu_save(act);

	/*
	 * Pull in any bytes which are going to be
	 * read.
	 */

	if (entry->a_readbytes) {
		if (USER_MODE(ssp->srr1)) {
			if (copyin((char *) dar,
				   (char *) align_buffer,
				   entry->a_readbytes)) {
				return	TRUE;
			}
		} else {
			bcopy((char *) dar,
			      (char *) align_buffer,
			      entry->a_readbytes);
		}
	}

#if	0 && DEBUG
	printf("Alignment exception: %s %d,0x%x (r%d/w%d) (tmp %x/%x)\n",
	       entry->name, DSISR_BITS_REG(dsisr),
	       dar, entry->a_readbytes, entry->a_writebytes, 
	       align_buffer[0], align_buffer[1]);
	printf("    pc=(0x%08X), msr=(0x%X)",ssp->srr0, ssp->srr1);
#endif

	
	success = entry->a_instruct(dsisr,
				    ssp,
					(entry->a_is_float ? find_user_fpu(act) : 0),	/* Find this user's FPU state if FP op */
				    align_buffer,
				    dar);

	if (success) {
		if (entry->a_writebytes) {
			if (USER_MODE(ssp->srr1)) {
				if (copyout((char *) align_buffer,
					    (char *) dar,
					    entry->a_writebytes)) {
					return	TRUE;
				}
			} else {
				bcopy((char *) align_buffer,
				      (char *) dar,
				      entry->a_writebytes);
			}
		}
		else {
			if(entry->a_is_float) {				/* If we are an FP op, blow away live context */
				for(i=0; i < real_ncpus; i++) {	/* Cycle through processors */
					(void)hw_compare_and_store((unsigned int)act, 0, &per_proc_info[i].FPU_thread);	/* Clear if ours */
				}
			}

			if (USER_MODE(ssp->srr1)) {
				if (copyout((char *) align_buffer,
					    (char *) dar,
					    entry->a_writebytes)) {
					return	TRUE;
				}
			} else {
				bcopy((char *) align_buffer,
				      (char *) dar,
				      entry->a_writebytes);
			}
		}

		ssp->srr0 += 4;	/* Skip the instruction .. */
	}

	return	!success;

out:
#if	0 && DEBUG
	printf("ALIGNMENT EXCEPTION: (dsisr 0x%x) table %d 0x%x\n",
		dsisr, DSISR_BITS_15_16(dsisr), DSISR_BITS_17_21(dsisr));
#endif

	return	TRUE;
}

_AINST(lwz)
{
	SET_REG(ssp, DSISR_BITS_REG(dsisr), align_buffer, unsigned long);

	return	TRUE;
}

_AINST(stw)
{
	GET_REG(ssp, DSISR_BITS_REG(dsisr), align_buffer, unsigned long);

	return	TRUE;
}

_AINST(lhz)
{
	unsigned long value = *((unsigned short *) align_buffer);

	SET_REG(ssp, DSISR_BITS_REG(dsisr), &value, unsigned long);

	return	TRUE;
}

_AINST(lha)
{
	long value = *((short *) align_buffer);

	SET_REG(ssp, DSISR_BITS_REG(dsisr), &value, unsigned long);

	return	TRUE;
}

_AINST(sth)
{
	GET_REG(ssp, DSISR_BITS_REG(dsisr), align_buffer, unsigned short);

	return	TRUE;
}

_AINST(lmw)
{
    int	i;

    for (i = 0; i < (32-DSISR_BITS_REG(dsisr)); i++)
    {
	SET_REG(ssp, DSISR_BITS_REG(dsisr)+i, &align_buffer[i], unsigned long);
    }
    return TRUE;
}

struct fpsp {
	unsigned long	s	:1;	/* Sign bit */
	unsigned long	exp	:8;	/* exponent + bias */
	unsigned long	fraction:23;	/* fraction */
};
typedef struct fpsp fpsp_t, *fpspPtr;

struct fpdp {
	unsigned long	s	:1;	/* Sign bit */
	unsigned long	exp	:11;	/* exponent + bias */
	unsigned long	fraction:20;	/* fraction */
	unsigned long	fraction1;	/* fraction */
};
typedef struct fpdp fpdp_t, *fpdpPtr;


_AINST(lfs)
{
	unsigned long	lalign_buf[2];


	lfs (align_buffer, lalign_buf);
	SET_FPU_REG(fsp, DSISR_BITS_REG(dsisr), lalign_buf);
	return	TRUE;
}

_AINST(lfd)
{
	SET_FPU_REG(fsp, DSISR_BITS_REG(dsisr), align_buffer);
	return	TRUE;
}

_AINST(stfs)
{
	unsigned long	lalign_buf[2];


	GET_FPU_REG(fsp, DSISR_BITS_REG(dsisr), lalign_buf);
	stfs(lalign_buf, align_buffer);
	return TRUE;
}

_AINST(stfd)
{
	GET_FPU_REG(fsp, DSISR_BITS_REG(dsisr), align_buffer);
	return TRUE;
}

_AINST(lwzu)
{
	SET_REG(ssp, DSISR_BITS_REG(dsisr), align_buffer, unsigned long)
	SET_REG(ssp, DSISR_BITS_RA(dsisr), &dar, unsigned long);
	return TRUE;
}

_AINST(stwu)
{
	GET_REG(ssp, DSISR_BITS_REG(dsisr), align_buffer, unsigned long)
	SET_REG(ssp, DSISR_BITS_RA(dsisr), &dar, unsigned long);
	return TRUE;
}


_AINST(lhzu)
{
	SET_REG(ssp, DSISR_BITS_REG(dsisr), align_buffer, unsigned short)
	SET_REG(ssp, DSISR_BITS_RA(dsisr), &dar, unsigned long);
	return TRUE;
}

_AINST(lhau)
{
	unsigned long	value = *((short *) align_buffer);

	SET_REG(ssp, DSISR_BITS_REG(dsisr), &value, unsigned long);
	SET_REG(ssp, DSISR_BITS_RA(dsisr), &dar, unsigned long);

	return	TRUE;
}

_AINST(sthu)
{
	GET_REG(ssp, DSISR_BITS_REG(dsisr), align_buffer, unsigned short)
	SET_REG(ssp, DSISR_BITS_RA(dsisr), &dar, unsigned long);
	return	TRUE;
}

_AINST(stmw)
{
    int	i, rS = DSISR_BITS_REG(dsisr);
    int numRegs = 32 - rS;
    int numBytes = numRegs * 4;
    int retval;


    for (i = 0; i < numRegs; i++)
    {
#if 0
	printf("    align_buffer[%d] == 0x%x\n",i,align_buffer[i]);
#endif
	GET_REG(ssp, rS+i, &align_buffer[i], unsigned long);
#if 0
	printf("    now align_buffer[%d] == 0x%x\n",i,align_buffer[i]);
#endif
    }
    if (USER_MODE(ssp->srr1)) {
	if ((retval=copyout((char *)align_buffer,(char *)dar,numBytes)) != 0) {
	    return FALSE;
	}
#if 0
	printf("    copyout(%X, %X, %X) succeeded\n",align_buffer,dar,numBytes);
#endif
    }
    else {
	bcopy((char *) align_buffer, (char *) dar, numBytes);
    }
    return TRUE;
}

_AINST(lfsu)
{
	unsigned long	lalign_buf[2];


	lfs (align_buffer, lalign_buf);
	SET_FPU_REG(fsp, DSISR_BITS_REG(dsisr), lalign_buf);
	SET_REG(ssp, DSISR_BITS_RA(dsisr), &dar, unsigned long);
	return	TRUE;
}

_AINST(lfdu)
{
	SET_FPU_REG(fsp, DSISR_BITS_REG(dsisr), align_buffer);
	SET_REG(ssp, DSISR_BITS_RA(dsisr), &dar, unsigned long);

	return	TRUE;
}

_AINST(stfsu)
{
	unsigned long	lalign_buf[2];


	GET_FPU_REG(fsp, DSISR_BITS_REG(dsisr), lalign_buf);
	stfs(lalign_buf, align_buffer);
	SET_REG(ssp, DSISR_BITS_RA(dsisr), &dar, unsigned long);
	return	TRUE;
}


_AINST(stfdu)
{
	GET_FPU_REG(fsp, DSISR_BITS_REG(dsisr), align_buffer);
	SET_REG(ssp, DSISR_BITS_RA(dsisr), &dar, unsigned long);

	return	TRUE;
}

_AINST(lswx)
{
    int	i, nb, nr, inst, zero = 0;


    /* check for invalid form of instruction */
    if (DSISR_BITS_RA(dsisr) >= DSISR_BITS_REG(dsisr) )
	return FALSE;

    if (USER_MODE(ssp->srr1)) {
	if (copyin((char *) ssp->srr0, (char *) &inst, 4 )) {
	return	FALSE;
	}
    } else {
	bcopy((char *) ssp->srr0, (char *) &inst, 4 );
    }
	
    nb = (inst >> 11) & 0x1F;	/* get the number of bytes in the instr */
    nr = (nb + sizeof(long)-1) / sizeof(long);/* get the number of regs to copy */

    if ((nr + DSISR_BITS_REG(dsisr)) > 31)
	return FALSE;		/* not supported yet */

    for (i = 0; i < nr; i++)
    {
	SET_REG(ssp, DSISR_BITS_REG(dsisr)+i, &zero, unsigned long);
    }
    /* copy the string into the save state */
    bcopy((char *) align_buffer, (char *) ssp->r0+DSISR_BITS_REG(dsisr), nb );
    return TRUE;
}

_AINST(lswi)
{
    int	i, nb, nr, inst, zero = 0;


    /* check for invalid form of instruction */
    if (DSISR_BITS_RA(dsisr) >= DSISR_BITS_REG(dsisr) )
	return FALSE;

    if (USER_MODE(ssp->srr1)) {
	if (copyin((char *) ssp->srr0, (char *) &inst, 4 )) {
	return	FALSE;
	}
    } else {
	bcopy((char *) ssp->srr0, (char *) &inst, 4 );
    }
	
    nb = (inst >> 11) & 0x1F;	/* get the number of bytes in the instr */
    nr = (nb + sizeof(long)-1) / sizeof(long);/* get the number of regs to copy */

    if ((nr + DSISR_BITS_REG(dsisr)) > 31)
	return FALSE;		/* not supported yet */

    for (i = 0; i < nr; i++)
    {
	SET_REG(ssp, DSISR_BITS_REG(dsisr)+i, &zero, unsigned long);
    }
    /* copy the string into the save state */
    bcopy((char *) align_buffer, (char *) ssp->r0+DSISR_BITS_REG(dsisr), nb );
    return TRUE;
}

_AINST(stswx)
{
	return	FALSE;
}

_AINST(stswi)
{
	return	FALSE;
}







_AINST(stwcx)
{
	return	FALSE;
}

_AINST(stdcx)
{
	return	FALSE;
}

_AINST(lwbrx)
{
	unsigned long 	new_value;

	__asm__ volatile("lwbrx	%0,0,%1" : : "b" (new_value),
			"b" (&align_buffer[0]));

	SET_REG(ssp, DSISR_BITS_REG(dsisr), &new_value, unsigned long);

	return	TRUE;
}

_AINST(stwbrx)
{
	unsigned long	value;

	GET_REG(ssp, DSISR_BITS_REG(dsisr), &value, unsigned long);
	__asm__ volatile("stwbrx	%0,0,%1" : : "b" (value), "b" (&align_buffer[0]));

	return	TRUE;
}

_AINST(lhbrx)
{
	unsigned short	value;

	__asm__ volatile("lhbrx %0,0,%1" : : "b" (value), "b" (&align_buffer[0]));

	SET_REG(ssp, DSISR_BITS_REG(dsisr), &value, unsigned short);

	return	TRUE;
}

_AINST(sthbrx)
{
	unsigned short value;

	GET_REG(ssp, DSISR_BITS_REG(dsisr), &value, unsigned short);
	__asm__ volatile("sthbrx %0,0,%1" : : "b" (value), "b" (&align_buffer[0]));

	return	TRUE;
}

_AINST(eciwx)
{
	return	FALSE;
}

_AINST(ecowx)
{
	return	FALSE;
}

_AINST(dcbz)
{
    long *alignedDAR = (long *)((long)dar & ~(CACHE_LINE_SIZE-1));


    if (USER_MODE(ssp->srr1)) {

	    align_buffer[0] = 0;
	    align_buffer[1] = 0;
	    align_buffer[2] = 0;
	    align_buffer[3] = 0;
	    align_buffer[4] = 0;
	    align_buffer[5] = 0;
	    align_buffer[6] = 0;
	    align_buffer[7] = 0;

	if (copyout((char *)align_buffer,(char *)alignedDAR,CACHE_LINE_SIZE) != 0)
	    return FALSE;
    } else {
	    /* Cannot use bcopy here just in case it caused the exception */
	    alignedDAR[0] = 0;
	    alignedDAR[1] = 0;
	    alignedDAR[2] = 0;
	    alignedDAR[3] = 0;
	    alignedDAR[4] = 0;
	    alignedDAR[5] = 0;
	    alignedDAR[6] = 0;
	    alignedDAR[7] = 0;
    }
    return	TRUE;
}







_AINST(lwzx)
{
	SET_REG(ssp, DSISR_BITS_REG(dsisr), &align_buffer[0], unsigned long);

	return	TRUE;
}

_AINST(stwx)
{
	GET_REG(ssp, DSISR_BITS_REG(dsisr), &align_buffer[0], unsigned long);

	return	TRUE;
}

_AINST(lhzx)
{
	SET_REG(ssp, DSISR_BITS_REG(dsisr), &align_buffer[0], unsigned short);

	return	TRUE;
}

_AINST(lhax)
{
	unsigned long	value	= *((short *) &align_buffer[0]);

	SET_REG(ssp, DSISR_BITS_REG(dsisr), &value, unsigned long);

	return	TRUE;
}

_AINST(sthx)
{
	GET_REG(ssp, DSISR_BITS_REG(dsisr), &align_buffer[0], unsigned short);

	return	TRUE;
}

_AINST(lfsx)
{
	long	lalign_buf[2];


	lfs (align_buffer, lalign_buf);
	SET_FPU_REG(fsp, DSISR_BITS_REG(dsisr), lalign_buf);
	return	TRUE;
}

_AINST(lfdx)
{
	SET_FPU_REG(fsp, DSISR_BITS_REG(dsisr), align_buffer);

	return	TRUE;
}

_AINST(stfsx)
{
	long	lalign_buf[2];


	GET_FPU_REG(fsp, DSISR_BITS_REG(dsisr), lalign_buf);
	stfs(lalign_buf, align_buffer);
	return	TRUE;
}

_AINST(stfdx)
{
	GET_FPU_REG(fsp, DSISR_BITS_REG(dsisr), align_buffer);

	return	TRUE;
}

_AINST(lwzux)
{
	SET_REG(ssp, DSISR_BITS_REG(dsisr), &align_buffer[0], unsigned long);
	SET_REG(ssp, DSISR_BITS_RA(dsisr), &dar, unsigned long);

	return	TRUE;
}

_AINST(stwux)
{
	GET_REG(ssp, DSISR_BITS_REG(dsisr), &align_buffer[0], unsigned long);
	SET_REG(ssp, DSISR_BITS_RA(dsisr), &dar, unsigned long);

	return	TRUE;
}

_AINST(lhzux)
{
	unsigned long value = *((unsigned short *)&align_buffer[0]);

	SET_REG(ssp, DSISR_BITS_REG(dsisr), &value, unsigned long);
	SET_REG(ssp, DSISR_BITS_RA(dsisr), &dar, unsigned long);

	return	TRUE;
}

_AINST(lhaux)
{
	long value = *((short *) &align_buffer[0]);

	SET_REG(ssp, DSISR_BITS_REG(dsisr), &value, unsigned long);
	SET_REG(ssp, DSISR_BITS_RA(dsisr), &dar, unsigned long);

	return	TRUE;
}

_AINST(sthux)
{
	GET_REG(ssp, DSISR_BITS_REG(dsisr), &align_buffer[0], unsigned short);
	SET_REG(ssp, DSISR_BITS_RA(dsisr), &dar, unsigned long);

	return	TRUE;
}

_AINST(lfsux)
{
	long	lalign_buf[2];


	lfs (align_buffer, lalign_buf);
	SET_FPU_REG(fsp, DSISR_BITS_REG(dsisr), lalign_buf);
	SET_REG(ssp, DSISR_BITS_RA(dsisr), &dar, unsigned long);
	return	TRUE;
}

_AINST(lfdux)
{
	SET_FPU_REG(fsp, DSISR_BITS_REG(dsisr), &align_buffer[0]);
	SET_REG(ssp, DSISR_BITS_RA(dsisr), &dar, unsigned long);

	return	TRUE;
}


_AINST(stfsux)
{
	long	lalign_buf[2];


	GET_FPU_REG(fsp, DSISR_BITS_REG(dsisr), lalign_buf);
	stfs(lalign_buf, align_buffer);
	SET_REG(ssp, DSISR_BITS_RA(dsisr), &dar, unsigned long);
	return	TRUE;
}

_AINST(stfdux)
{
	GET_FPU_REG(fsp, DSISR_BITS_REG(dsisr), &align_buffer[0]);
	SET_REG(ssp, DSISR_BITS_RA(dsisr), &dar, unsigned long);

	return	TRUE;
}
