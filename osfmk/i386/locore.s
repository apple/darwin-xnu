/*
 * Copyright (c) 2000-2009 Apple Inc. All rights reserved.
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
 * @OSF_COPYRIGHT@
 */
/* 
 * Mach Operating System
 * Copyright (c) 1991,1990 Carnegie Mellon University
 * All Rights Reserved.
 * 
 * Permission to use, copy, modify and distribute this software and its
 * documentation is hereby granted, provided that both the copyright
 * notice and this permission notice appear in all copies of the
 * software, derivative works or modified versions, and any portions
 * thereof, and that both notices appear in supporting documentation.
 * 
 * CARNEGIE MELLON ALLOWS FREE USE OF THIS SOFTWARE IN ITS "AS IS"
 * CONDITION.  CARNEGIE MELLON DISCLAIMS ANY LIABILITY OF ANY KIND FOR
 * ANY DAMAGES WHATSOEVER RESULTING FROM THE USE OF THIS SOFTWARE.
 * 
 * Carnegie Mellon requests users of this software to return to
 * 
 *  Software Distribution Coordinator  or  Software.Distribution@CS.CMU.EDU
 *  School of Computer Science
 *  Carnegie Mellon University
 *  Pittsburgh PA 15213-3890
 * 
 * any improvements or extensions that they make and grant Carnegie Mellon
 * the rights to redistribute these changes.
 */

#include <mach_rt.h>
#include <platforms.h>
#include <mach_kdb.h>
#include <mach_kgdb.h>
#include <mach_kdp.h>
#include <stat_time.h>
#include <mach_assert.h>

#include <sys/errno.h>
#include <i386/asm.h>
#include <i386/cpuid.h>
#include <i386/eflags.h>
#include <i386/proc_reg.h>
#include <i386/trap.h>
#include <assym.s>

#include <config_dtrace.h>

/*
 * PTmap is recursive pagemap at top of virtual address space.
 * Within PTmap, the page directory can be found (third indirection).
*/
	.globl	_PTmap,_PTD,_PTDpde
	.set	_PTmap,(PTDPTDI << PDESHIFT)
	.set	_PTD,_PTmap + (PTDPTDI * NBPG)
	.set	_PTDpde,_PTD + (PTDPTDI * PDESIZE)

#if __MACHO__
/* Under Mach-O, etext is a variable which contains
 * the last text address
 */
#define	ETEXT_ADDR	(EXT(etext))
#else
/* Under ELF and other non-Mach-O formats, the address of
 * etext represents the last text address
 */
#define ETEXT_ADDR	$ EXT(etext)
#endif


	.text
locore_start:

/*
 * Fault recovery.
 */

#ifdef	__MACHO__
#define	RECOVERY_SECTION	.section	__VECTORS, __recover 
#else
#define	RECOVERY_SECTION	.text
#define	RECOVERY_SECTION	.text
#endif

#define	RECOVER_TABLE_START	\
	.align 2		; \
	.globl	EXT(recover_table) ;\
LEXT(recover_table)		;\
	.text

#define	RECOVER(addr)		\
	.align	2;		\
	.long	9f		;\
	.long	addr		;\
	.text			;\
9:

#define	RECOVER_TABLE_END		\
	.align	2			;\
	.globl	EXT(recover_table_end)	;\
LEXT(recover_table_end)			;\
	.long 0  /* workaround see comment below */ ;\
	.text ;

/* TODO FIXME
 * the .long 0 is to work around a linker bug (insert radar# here)
 * basically recover_table_end has zero size and bumps up right against saved_esp in acpi_wakeup.s
 * recover_table_end is in __RECOVER,__vectors and saved_esp is in __SLEEP,__data, but they're right next to each
 * other and so the linker combines them and incorrectly relocates everything referencing recover_table_end to point
 * into the SLEEP section
 */

/*
 * Allocate recovery and table.
 */
	RECOVERY_SECTION
	RECOVER_TABLE_START


/*
 *	Called as a function, makes the current thread
 *	return from the kernel as if from an exception.
 *	We will consult with DTrace if this is a 
 *	newly created thread and we need to fire a probe.
 */

	.globl	EXT(thread_exception_return)
	.globl	EXT(thread_bootstrap_return)
LEXT(thread_bootstrap_return)
#if CONFIG_DTRACE
	call EXT(dtrace_thread_bootstrap)
#endif

LEXT(thread_exception_return)
	cli
	xorl	%ecx,%ecx			/* don't check if in the PFZ */
	cmpl    $0, %gs:CPU_IS64BIT
	je	EXT(return_from_trap32)
	jmp	EXT(return_from_trap)


/*
 * Utility routines.
 */

/*
 * Copy from user/kernel address space.
 * arg0:	window offset or kernel address
 * arg1:	kernel address
 * arg2:	byte count
 */
Entry(copyinphys_user)
	movl	$(USER_WINDOW_SEL),%ecx	/* user data segment access through kernel window */
	mov	%cx,%ds

Entry(copyinphys_kern)
	movl	$(PHYS_WINDOW_SEL),%ecx	/* physical access through kernel window */
	mov	%cx,%es
	jmp	copyin_common

Entry(copyin_user)
	movl	$(USER_WINDOW_SEL),%ecx	/* user data segment access through kernel window */
	mov	%cx,%ds

Entry(copyin_kern)

copyin_common:
	pushl	%esi
	pushl	%edi			/* save registers */

	movl	8+S_ARG0,%esi		/* get source - window offset or kernel address */
	movl	8+S_ARG1,%edi		/* get destination - kernel address */
	movl	8+S_ARG2,%edx		/* get count */

	cld				/* count up */
	movl	%edx,%ecx		/* move by longwords first */
	shrl	$2,%ecx
	RECOVERY_SECTION
	RECOVER(copyin_fail)
	rep
	movsl				/* move longwords */
	movl	%edx,%ecx		/* now move remaining bytes */
	andl	$3,%ecx
	RECOVERY_SECTION
	RECOVER(copyin_fail)
	rep
	movsb
	xorl	%eax,%eax		/* return 0 for success */
copyin_ret:
	mov	%ss,%cx			/* restore kernel data and extended segments */
	mov	%cx,%ds
	mov	%cx,%es

	popl	%edi			/* restore registers */
	popl	%esi
	ret				/* and return */

copyin_fail:
	movl	$(EFAULT),%eax		/* return error for failure */
	jmp	copyin_ret		/* pop frame and return */


	
/*
 * Copy string from user/kern address space.
 * arg0:	window offset or kernel address
 * arg1:	kernel address
 * arg2:	max byte count
 * arg3:	actual byte count (OUT)
 */
Entry(copyinstr_kern)
	mov	%ds,%cx
	jmp	copyinstr_common	

Entry(copyinstr_user)
	movl	$(USER_WINDOW_SEL),%ecx	/* user data segment access through kernel window */

copyinstr_common:
	mov	%cx,%fs

	pushl	%esi
	pushl	%edi			/* save registers */

	movl	8+S_ARG0,%esi		/* get source - window offset or kernel address */
	movl	8+S_ARG1,%edi		/* get destination - kernel address */
	movl	8+S_ARG2,%edx		/* get count */

	xorl	%eax,%eax		/* set to 0 here so that the high 24 bits */
					/* are 0 for the cmpl against 0 */
2:
	RECOVERY_SECTION
	RECOVER(copystr_fail)		/* copy bytes... */
	movb	%fs:(%esi),%al
	incl	%esi
	testl	%edi,%edi		/* if kernel address is ... */
	jz	3f			/* not NULL */
	movb	%al,(%edi)		/* copy the byte */
	incl	%edi
3:
	testl	%eax,%eax		/* did we just stuff the 0-byte? */
	jz	4f			/* yes, return 0 status already in %eax */
	decl	%edx			/* decrement #bytes left in buffer */
	jnz	2b			/* buffer not full so copy in another byte */
	movl	$(ENAMETOOLONG),%eax	/* buffer full but no 0-byte: ENAMETOOLONG */
4:
	movl	8+S_ARG3,%edi		/* get OUT len ptr */
	cmpl	$0,%edi
	jz	copystr_ret		/* if null, just return */
	subl	8+S_ARG0,%esi
	movl	%esi,(%edi)		/* else set OUT arg to xfer len */
copystr_ret:
	popl	%edi			/* restore registers */
	popl	%esi
	ret				/* and return */

copystr_fail:
	movl	$(EFAULT),%eax		/* return error for failure */
	jmp	copystr_ret		/* pop frame and return */


/*
 * Copy to user/kern address space.
 * arg0:	kernel address
 * arg1:	window offset or kernel address
 * arg2:	byte count
 */
ENTRY(copyoutphys_user)
	movl	$(USER_WINDOW_SEL),%ecx	/* user data segment access through kernel window */
	mov	%cx,%es

ENTRY(copyoutphys_kern)
	movl	$(PHYS_WINDOW_SEL),%ecx	/* physical access through kernel window */
	mov	%cx,%ds
	jmp	copyout_common

ENTRY(copyout_user)
	movl	$(USER_WINDOW_SEL),%ecx	/* user data segment access through kernel window */
	mov	%cx,%es

ENTRY(copyout_kern)

copyout_common:
	pushl	%esi
	pushl	%edi			/* save registers */

	movl	8+S_ARG0,%esi		/* get source - kernel address */
	movl	8+S_ARG1,%edi		/* get destination - window offset or kernel address */
	movl	8+S_ARG2,%edx		/* get count */

	cld				/* count up */
	movl	%edx,%ecx		/* move by longwords first */
	shrl	$2,%ecx
	RECOVERY_SECTION
	RECOVER(copyout_fail)
	rep
	movsl
	movl	%edx,%ecx		/* now move remaining bytes */
	andl	$3,%ecx
	RECOVERY_SECTION
	RECOVER(copyout_fail)
	rep
	movsb				/* move */
	xorl	%eax,%eax		/* return 0 for success */
copyout_ret:
	mov	%ss,%cx			/* restore kernel segment */
	mov	%cx,%es
	mov	%cx,%ds

	popl	%edi			/* restore registers */
	popl	%esi
	ret				/* and return */

copyout_fail:
	movl	$(EFAULT),%eax		/* return error for failure */
	jmp	copyout_ret		/* pop frame and return */


/*
 * io register must not be used on slaves (no AT bus)
 */
#define	ILL_ON_SLAVE


#if	MACH_ASSERT

#define ARG0		B_ARG0
#define ARG1		B_ARG1
#define ARG2		B_ARG2
#define PUSH_FRAME	FRAME
#define POP_FRAME	EMARF

#else	/* MACH_ASSERT */

#define ARG0		S_ARG0
#define ARG1		S_ARG1
#define ARG2		S_ARG2
#define PUSH_FRAME	
#define POP_FRAME	

#endif	/* MACH_ASSERT */


/*
 * int rdmsr_carefully(uint32_t msr, uint32_t *lo, uint32_t *hi)
 */
ENTRY(rdmsr_carefully)
	movl	S_ARG0, %ecx
	RECOVERY_SECTION
	RECOVER(rdmsr_fail)
	rdmsr
	movl	S_ARG1, %ecx
	movl	%eax, (%ecx)
	movl	S_ARG2, %ecx
	movl	%edx, (%ecx)
	movl	$0, %eax
	ret

rdmsr_fail:
	movl	$1, %eax
	ret

/*
 * Done with recovery table.
 */
	RECOVERY_SECTION
	RECOVER_TABLE_END

	.data
dr_msk:
	.long	~0x000f0003
	.long	~0x00f0000c
	.long	~0x0f000030
	.long	~0xf00000c0
ENTRY(dr_addr)
	.long	0,0,0,0
	.long	0,0,0,0

	.text

/*
 * ffs(mask)
 */
ENTRY(ffs)
	bsfl	S_ARG0, %eax
	jz	0f
	incl	%eax
	ret
0:	xorl	%eax, %eax
	ret

/*
 * cpu_shutdown()
 * Force reboot
 */

null_idtr:
	.word	0
	.long	0

Entry(cpu_shutdown)
        lidt    null_idtr       /* disable the interrupt handler */
        xor     %ecx,%ecx       /* generate a divide by zero */
        div     %ecx,%eax       /* reboot now */
        ret                     /* this will "never" be executed */


/*
 * setbit(int bitno, int *s) - set bit in bit string
 */
ENTRY(setbit)
	movl	S_ARG0, %ecx		/* bit number */
	movl	S_ARG1, %eax		/* address */
	btsl	%ecx, (%eax)		/* set bit */
	ret

/*
 * clrbit(int bitno, int *s) - clear bit in bit string
 */
ENTRY(clrbit)
	movl	S_ARG0, %ecx		/* bit number */
	movl	S_ARG1, %eax		/* address */
	btrl	%ecx, (%eax)		/* clear bit */
	ret

/*
 * ffsbit(int *s) - find first set bit in bit string
 */
ENTRY(ffsbit)
	movl	S_ARG0, %ecx		/* address */
	movl	$0, %edx		/* base offset */
0:
	bsfl	(%ecx), %eax		/* check argument bits */
	jnz	1f			/* found bit, return */
	addl	$4, %ecx		/* increment address */
	addl	$32, %edx		/* increment offset */
	jmp	0b			/* try again */
1:
	addl	%edx, %eax		/* return offset */
	ret

/*
 * testbit(int nr, volatile void *array)
 *
 * Test to see if the bit is set within the bit string
 */

ENTRY(testbit)
	movl	S_ARG0,%eax	/* Get the bit to test */
	movl	S_ARG1,%ecx	/* get the array string */
	btl	%eax,(%ecx)
	sbbl	%eax,%eax
	ret

