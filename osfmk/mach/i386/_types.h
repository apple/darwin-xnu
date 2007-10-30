/*
 * Copyright (c) 2004-2006 Apple Computer, Inc. All rights reserved.
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

#ifndef	_MACH_I386__TYPES_H_
#define	_MACH_I386__TYPES_H_

/*
 * i386_thread_state is the structure that is exported to user threads for 
 * use in status/mutate calls.  This structure should never change.
 *
 */

#if !__DARWIN_UNIX03
struct i386_thread_state
#else /* __DARWIN_UNIX03 */
struct __darwin_i386_thread_state
#endif /* __DARWIN_UNIX03 */
{
    unsigned int	eax;
    unsigned int	ebx;
    unsigned int	ecx;
    unsigned int	edx;
    unsigned int	edi;
    unsigned int	esi;
    unsigned int	ebp;
    unsigned int	esp;
    unsigned int	ss;
    unsigned int	eflags;
    unsigned int	eip;
    unsigned int	cs;
    unsigned int	ds;
    unsigned int	es;
    unsigned int	fs;
    unsigned int	gs;
};

#if !__DARWIN_UNIX03
struct x86_thread_state64
#else /* __DARWIN_UNIX03 */
struct __darwin_x86_thread_state64
#endif /* __DARWIN_UNIX03 */
{
	uint64_t	rax;
	uint64_t	rbx;
	uint64_t	rcx;
	uint64_t	rdx;
	uint64_t	rdi;
	uint64_t	rsi;
	uint64_t	rbp;
	uint64_t	rsp;
	uint64_t	r8;
	uint64_t	r9;
	uint64_t	r10;
	uint64_t	r11;
	uint64_t	r12;
	uint64_t	r13;
	uint64_t	r14;
	uint64_t	r15;
	uint64_t	rip;
	uint64_t	rflags;
	uint64_t	cs;
	uint64_t	fs;
	uint64_t	gs;
};


typedef struct fp_control {
    unsigned short		invalid	:1,
    				denorm	:1,
				zdiv	:1,
				ovrfl	:1,
				undfl	:1,
				precis	:1,
					:2,
				pc	:2,
#define FP_PREC_24B		0
#define	FP_PREC_53B		2
#define FP_PREC_64B		3
				rc	:2,
#define FP_RND_NEAR		0
#define FP_RND_DOWN		1
#define FP_RND_UP		2
#define FP_CHOP			3
				/*inf*/	:1,
					:3;
} fp_control_t;
/*
 * Status word.
 */

typedef struct fp_status {
    unsigned short		invalid	:1,
    				denorm	:1,
				zdiv	:1,
				ovrfl	:1,
				undfl	:1,
				precis	:1,
				stkflt	:1,
				errsumm	:1,
				c0	:1,
				c1	:1,
				c2	:1,
				tos	:3,
				c3	:1,
				busy	:1;
} fp_status_t;
				
/* defn of 80bit x87 FPU or MMX register  */
struct mmst_reg {
	char	mmst_reg[10];
	char	mmst_rsrv[6];
};


/* defn of 128 bit XMM regs */
struct xmm_reg {
	char		xmm_reg[16];
};

/* 
 * Floating point state.
 */

#define FP_STATE_BYTES		512	/* number of chars worth of data from fpu_fcw */
#if !__DARWIN_UNIX03
struct i386_float_state
#else /* __DARWIN_UNIX03 */
struct __darwin_i386_float_state
#endif /* __DARWIN_UNIX03 */
{
	int 			fpu_reserved[2];
	fp_control_t	fpu_fcw;			/* x87 FPU control word */
	fp_status_t		fpu_fsw;			/* x87 FPU status word */
	uint8_t			fpu_ftw;			/* x87 FPU tag word */
	uint8_t			fpu_rsrv1;			/* reserved */ 
	uint16_t		fpu_fop;			/* x87 FPU Opcode */
	uint32_t		fpu_ip;				/* x87 FPU Instruction Pointer offset */
	uint16_t		fpu_cs;				/* x87 FPU Instruction Pointer Selector */
	uint16_t		fpu_rsrv2;			/* reserved */
	uint32_t		fpu_dp;				/* x87 FPU Instruction Operand(Data) Pointer offset */
	uint16_t		fpu_ds;				/* x87 FPU Instruction Operand(Data) Pointer Selector */
	uint16_t		fpu_rsrv3;			/* reserved */
	uint32_t		fpu_mxcsr;			/* MXCSR Register state */
	uint32_t		fpu_mxcsrmask;		/* MXCSR mask */
	struct mmst_reg	fpu_stmm0;		/* ST0/MM0   */
	struct mmst_reg	fpu_stmm1;		/* ST1/MM1  */
	struct mmst_reg	fpu_stmm2;		/* ST2/MM2  */
	struct mmst_reg	fpu_stmm3;		/* ST3/MM3  */
	struct mmst_reg	fpu_stmm4;		/* ST4/MM4  */
	struct mmst_reg	fpu_stmm5;		/* ST5/MM5  */
	struct mmst_reg	fpu_stmm6;		/* ST6/MM6  */
	struct mmst_reg	fpu_stmm7;		/* ST7/MM7  */
	struct xmm_reg	fpu_xmm0;		/* XMM 0  */
	struct xmm_reg	fpu_xmm1;		/* XMM 1  */
	struct xmm_reg	fpu_xmm2;		/* XMM 2  */
	struct xmm_reg	fpu_xmm3;		/* XMM 3  */
	struct xmm_reg	fpu_xmm4;		/* XMM 4  */
	struct xmm_reg	fpu_xmm5;		/* XMM 5  */
	struct xmm_reg	fpu_xmm6;		/* XMM 6  */
	struct xmm_reg	fpu_xmm7;		/* XMM 7  */
	char			fpu_rsrv4[14*16];	/* reserved */
	int 			fpu_reserved1;
};


#if !__DARWIN_UNIX03
struct i386_exception_state
#else /* __DARWIN_UNIX03 */
struct __darwin_i386_exception_state
#endif /* __DARWIN_UNIX03 */
{
    unsigned int	trapno;
    unsigned int	err;
    unsigned int	faultvaddr;
};

#if !__DARWIN_UNIX03
struct x86_debug_state
#else /* __DARWIN_UNIX03 */
struct __darwin_x86_debug_state
#endif /* __DARWIN_UNIX03 */
{
	unsigned int	dr0;
	unsigned int	dr1;
	unsigned int	dr2;
	unsigned int	dr3;
	unsigned int	dr4;
	unsigned int	dr5;
	unsigned int	dr6;
	unsigned int	dr7;
};

#endif /* _MACH_I386__TYPES_H_ */
