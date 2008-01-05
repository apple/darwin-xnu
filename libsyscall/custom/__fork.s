/*
 * Copyright (c) 1999-2007 Apple Inc. All rights reserved.
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
/* Copyright (c) 1992 NeXT Computer, Inc.  All rights reserved.
 *
 *	File:	libc/ppc/sys/fork.s
 *
 * HISTORY
 * 18-Nov-92  Ben Fathi (benf@next.com)
 *	Created from M88K sources
 *
 * 11-Jan-92  Peter King (king@next.com)
 *	Created from M68K sources
 */

#include "SYS.h"

#if defined(__ppc__) || defined(__ppc64__)

/* We use mode-independent "g" opcodes such as "srgi".  These expand
 * into word operations when targeting __ppc__, and into doubleword
 * operations when targeting __ppc64__.
 */
#include <architecture/ppc/mode_independent_asm.h>

MI_ENTRY_POINT(___fork)
    MI_PUSH_STACK_FRAME
    
    MI_CALL_EXTERNAL(__cthread_fork_prepare)
    
	li      r0,SYS_fork
	sc                      // do the fork
	b       Lbotch			// error return

	cmpwi	r4,0            // parent (r4==0) or child (r4==1) ?
	beq     Lparent         // parent, since r4==0

                            
/* Here if we are the child.  */

#if defined(__DYNAMIC__)
    .cstring
LC3:
	.ascii	"__dyld_fork_child\0"
    .text
	.align 2
	mflr	r0
	bcl     20,31,1f
1:	mflr	r3
	mtlr	r0
	addis	r3,r3,ha16(LC3-1b)
	addi	r3,r3,lo16(LC3-1b)
	addi 	r4,r1,SF_LOCAL1
	bl      __dyld_func_lookup
	lg      r3,SF_LOCAL1(r1)
	mtspr 	ctr,r3
	bctrl	
#endif

    li      r9,0
    MI_GET_ADDRESS(r8,__current_pid)
    stw     r9,0(r8)            // clear cached pid in child
    
	MI_CALL_EXTERNAL(__cthread_fork_child)
    
	li	r3,0        // flag for "we are the child"
	b	Lreturn


/* Here if we are the parent, with:
 *  r3 = child's pid
 */
Lparent:
	stg     r3,SF_LOCAL2(r1)	// save child pid in stack
    
    b       Lparent_return      // clean up and return child's pid


/* Here if the fork() syscall failed.  We're still the parent.  */

Lbotch:	

	MI_CALL_EXTERNAL(cerror)
    li      r3,-1               // get an error return code
	stg     r3,SF_LOCAL2(r1)	// save return code in stack
    
	/*
	 * We use cthread_fork_parent() to clean up after a fork error
	 * (unlock cthreads and mailloc packages) so the parent
	 * process can Malloc() after fork() errors without
	 * deadlocking.
	 */
     
Lparent_return:
	MI_CALL_EXTERNAL(__cthread_fork_parent)
	lg      r3,SF_LOCAL2(r1)    // return -1 on error, child's pid on success
    
Lreturn:
    MI_POP_STACK_FRAME_AND_RETURN

#elif defined(__i386__)

LEAF(___fork, 0)
	subl  $28, %esp   // Align the stack, with 16 bytes of extra padding that we'll need
	CALL_EXTERN(__cthread_fork_prepare)

	movl 	$ SYS_fork,%eax; 	// code for fork -> eax
	UNIX_SYSCALL_TRAP		// do the system call
	jnc	L1			// jump if CF==0

	CALL_EXTERN(cerror)
	CALL_EXTERN(__cthread_fork_parent)
	movl	$-1,%eax
	addl	$28, %esp   // restore the stack
	ret
	
L1:
	orl	%edx,%edx	// CF=OF=0,  ZF set if zero result	
	jz	L2		// parent, since r1 == 0 in parent, 1 in child
	
	//child here...
#if defined(__DYNAMIC__)
// Here on the child side of the fork we need to tell the dynamic linker that
// we have forked.  To do this we call __dyld_fork_child in the dyanmic
// linker.  But since we can't dynamically bind anything until this is done we
// do this by using the private extern __dyld_func_lookup() function to get the
// address of __dyld_fork_child (the 'C' code equivlent):
//
//	_dyld_func_lookup("__dyld_fork_child", &address);
//	address();
//
.cstring
LC0:
	.ascii "__dyld_fork_child\0"

.text
	leal	0x8(%esp),%eax		// get the address where we're going to store the pointer
	movl	%eax, 0x4(%esp)		// copy the address of the pointer
	call	1f
1:	popl	%eax
	leal	LC0-1b(%eax),%eax
	movl 	%eax, 0x0(%esp)		// copy the name of the function to look up
	call 	__dyld_func_lookup
	movl	0x8(%esp),%eax		// move the value returned in address parameter
	call	*%eax		// call __dyld_fork_child indirectly
#endif
	xorl	%eax, %eax
	REG_TO_EXTERN(%eax, __current_pid)
	CALL_EXTERN(__cthread_fork_child)

	xorl	%eax,%eax	// zero eax
	addl	$28, %esp   // restore the stack
	ret

	//parent here...
L2:
	movl	%eax, 0xc(%esp)		// save pid

	CALL_EXTERN_AGAIN(__cthread_fork_parent)
	movl	0xc(%esp), %eax		// return pid
	addl	$28, %esp   // restore the stack
	ret		

#elif defined(__x86_64__)

LEAF(___fork, 0)
	subq  $24, %rsp   // Align the stack, plus room for local storage
	CALL_EXTERN(__cthread_fork_prepare)

	movl 	$ SYSCALL_CONSTRUCT_UNIX(SYS_fork),%eax; // code for fork -> rax
	UNIX_SYSCALL_TRAP		// do the system call
	jnc	L1			// jump if CF==0

	CALL_EXTERN(cerror)
	CALL_EXTERN(__cthread_fork_parent)
	movq	$-1, %rax
	addq	$24, %rsp   // restore the stack
	ret
	
L1:
	orl	%edx,%edx	// CF=OF=0,  ZF set if zero result	
	jz	L2		// parent, since r1 == 0 in parent, 1 in child
	
	//child here...
#if defined(__DYNAMIC__)
// Here on the child side of the fork we need to tell the dynamic linker that
// we have forked.  To do this we call __dyld_fork_child in the dyanmic
// linker.  But since we can't dynamically bind anything until this is done we
// do this by using the private extern __dyld_func_lookup() function to get the
// address of __dyld_fork_child (the 'C' code equivlent):
//
//	_dyld_func_lookup("__dyld_fork_child", &address);
//	address();
//
.cstring
LC0:
	.ascii "__dyld_fork_child\0"

.text
	leaq	8(%rsp),%rsi		// get the address where we're going to store the pointer
	leaq 	LC0(%rip), %rdi		// copy the name of the function to look up
	call 	__dyld_func_lookup
	call	*8(%rsp)		// call __dyld_fork_child indirectly
#endif
	xorq	%rax, %rax
	REG_TO_EXTERN(%rax, __current_pid)
	CALL_EXTERN(__cthread_fork_child)

	xorq	%rax,%rax	// zero rax
	addq	$24, %rsp   // restore the stack
	ret

	//parent here...
L2:
	movl	%eax, 16(%rsp)		// save pid

	CALL_EXTERN_AGAIN(__cthread_fork_parent)
	movl	16(%rsp), %eax		// return pid
	addq	$24, %rsp   // restore the stack
	ret		

#else
#error Unsupported architecture
#endif
