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
 * Copyright (c) 1997 Apple Computer, Inc.  All rights reserved.
 * Copyright (c) 1994 NeXT Computer, Inc.  All rights reserved.
 *
 * machdep/ppc/kdp_machdep.c
 *
 * Machine-dependent code for Remote Debugging Protocol
 *
 * March, 1997	Created.	Umesh Vaishampayan [umeshv@NeXT.com]
 *
 */
 
#include <mach/mach_types.h>
#include <mach/exception_types.h>
#include <ppc/exception.h>
#include <ppc/proc_reg.h>
#include <kdp/kdp_internal.h>
#include <ppc/savearea.h>
#include <kern/debug.h>

#define KDP_TEST_HARNESS 0
#if KDP_TEST_HARNESS
#define dprintf(x) kprintf x
#else
#define dprintf(x)
#endif

void print_saved_state(void *);
void kdp_call(void);
void kdp_trap( unsigned int, struct ppc_thread_state *);
int kdp_getc(void);
boolean_t kdp_call_kdb(void);

void
kdp_exception(
    unsigned char	*pkt,
    int	*len,
    unsigned short	*remote_port,
    unsigned int	exception,
    unsigned int	code,
    unsigned int	subcode
)
{
    struct {
    	kdp_exception_t	pkt;
	kdp_exc_info_t	exc;
    }			aligned_pkt;
    kdp_exception_t	*rq = (kdp_exception_t *)&aligned_pkt;

    bcopy((char *)pkt, (char *)rq, sizeof(*rq));
    rq->hdr.request = KDP_EXCEPTION;
    rq->hdr.is_reply = 0;
    rq->hdr.seq = kdp.exception_seq;
    rq->hdr.key = 0;
    rq->hdr.len = sizeof (*rq) + sizeof(kdp_exc_info_t);
    
    rq->n_exc_info = 1;
    rq->exc_info[0].cpu = 0;
    rq->exc_info[0].exception = exception;
    rq->exc_info[0].code = code;
    rq->exc_info[0].subcode = subcode;
    
    rq->hdr.len += rq->n_exc_info * sizeof (kdp_exc_info_t);
    
    bcopy((char *)rq, (char *)pkt, rq->hdr.len);

    kdp.exception_ack_needed = TRUE;
    
    *remote_port = kdp.exception_port;
    *len = rq->hdr.len;
}

boolean_t
kdp_exception_ack(
    unsigned char	*pkt,
    int			len
)
{
    kdp_exception_ack_t	aligned_pkt;
    kdp_exception_ack_t	*rq = (kdp_exception_ack_t *)&aligned_pkt;

    if (len < sizeof (*rq))
	return(FALSE);
	
    bcopy((char *)pkt, (char *)rq, sizeof(*rq));

    if (!rq->hdr.is_reply || rq->hdr.request != KDP_EXCEPTION)
    	return(FALSE);
	
    dprintf(("kdp_exception_ack seq %x %x\n", rq->hdr.seq, kdp.exception_seq));
	
    if (rq->hdr.seq == kdp.exception_seq) {
	kdp.exception_ack_needed = FALSE;
	kdp.exception_seq++;
    }
    return(TRUE);
}

static void
kdp_getintegerstate(
    struct ppc_thread_state		*state
)
{
    struct ppc_thread_state	*saved_state;
   
    saved_state = kdp.saved_state;
   
    bzero((char *)state,sizeof (struct ppc_thread_state)) ;

    state->srr0	= saved_state->srr0;
    state->srr1	= saved_state->srr1;
    state->r0	= saved_state->r0;
    state->r1	= saved_state->r1;
    state->r2	= saved_state->r2;
    state->r3	= saved_state->r3;
    state->r4	= saved_state->r4;
    state->r5	= saved_state->r5;
    state->r6	= saved_state->r6;
    state->r7	= saved_state->r7;
    state->r8	= saved_state->r8;
    state->r9	= saved_state->r9;
    state->r10	= saved_state->r10;
    state->r11	= saved_state->r11;
    state->r12	= saved_state->r12;
    state->r13	= saved_state->r13;
    state->r14	= saved_state->r14;
    state->r15	= saved_state->r15;
    state->r16	= saved_state->r16;
    state->r17	= saved_state->r17;
    state->r18	= saved_state->r18;
    state->r19	= saved_state->r19;
    state->r20	= saved_state->r20;
    state->r21	= saved_state->r21;
    state->r22	= saved_state->r22;
    state->r23	= saved_state->r23;
    state->r24	= saved_state->r24;
    state->r25	= saved_state->r25;
    state->r26	= saved_state->r26;
    state->r27	= saved_state->r27;
    state->r28	= saved_state->r28;
    state->r29	= saved_state->r29;
    state->r30	= saved_state->r30;
    state->r31	= saved_state->r31;
    state->cr	= saved_state->cr;
    state->xer	= saved_state->xer;
    state->lr	= saved_state->lr;
    state->ctr	= saved_state->ctr;
    state->mq	= saved_state->mq; /* This is BOGUS ! (601) ONLY */
}

kdp_error_t
kdp_machine_read_regs(
    unsigned int cpu,
    unsigned int flavor,
    char *data,
    int *size
)
{
    switch (flavor) {

    case PPC_THREAD_STATE:
		dprintf(("kdp_readregs THREAD_STATE\n"));
		kdp_getintegerstate((struct ppc_thread_state *)data);
		*size = PPC_THREAD_STATE_COUNT * sizeof(int);
		return KDPERR_NO_ERROR;
	
    case PPC_FLOAT_STATE:
		dprintf(("kdp_readregs THREAD_FPSTATE\n"));
		bzero((char *)data ,sizeof(struct ppc_float_state));	
		*size = PPC_FLOAT_STATE_COUNT * sizeof(int);
		return KDPERR_NO_ERROR;
	
    default:
		dprintf(("kdp_readregs bad flavor %d\n"));
		return KDPERR_BADFLAVOR;
    }
}

static void
kdp_setintegerstate(
    struct ppc_thread_state		*state
)
{
    struct ppc_thread_state	*saved_state;
   
    saved_state = kdp.saved_state;

    saved_state->srr0	= state->srr0;
    saved_state->srr1	= state->srr1;
    saved_state->r0	= state->r0;
    saved_state->r1	= state->r1;
    saved_state->r2	= state->r2;
    saved_state->r3	= state->r3;
    saved_state->r4	= state->r4;
    saved_state->r5	= state->r5;
    saved_state->r6	= state->r6;
    saved_state->r7	= state->r7;
    saved_state->r8	= state->r8;
    saved_state->r9	= state->r9;
    saved_state->r10	= state->r10;
    saved_state->r11	= state->r11;
    saved_state->r12	= state->r12;
    saved_state->r13	= state->r13;
    saved_state->r14	= state->r14;
    saved_state->r15	= state->r15;
    saved_state->r16	= state->r16;
    saved_state->r17	= state->r17;
    saved_state->r18	= state->r18;
    saved_state->r19	= state->r19;
    saved_state->r20	= state->r20;
    saved_state->r21	= state->r21;
    saved_state->r22	= state->r22;
    saved_state->r23	= state->r23;
    saved_state->r24	= state->r24;
    saved_state->r25	= state->r25;
    saved_state->r26	= state->r26;
    saved_state->r27	= state->r27;
    saved_state->r28	= state->r28;
    saved_state->r29	= state->r29;
    saved_state->r30	= state->r30;
    saved_state->r31	= state->r31;
    saved_state->cr	= state->cr;
    saved_state->xer	= state->xer;
    saved_state->lr	= state->lr;
    saved_state->ctr	= state->ctr;
    saved_state->mq	= state->mq; /* BOGUS! (601)ONLY */
}

kdp_error_t
kdp_machine_write_regs(
    unsigned int cpu,
    unsigned int flavor,
    char *data,
    int *size
)
{
    switch (flavor) {

    case PPC_THREAD_STATE:
		dprintf(("kdp_writeregs THREAD_STATE\n"));
		kdp_setintegerstate((struct ppc_thread_state *)data);

#if KDP_TEST_HARNESS
		DumpTheSave((struct savearea *)data);		/* (TEST/DEBUG) */
#endif
		return KDPERR_NO_ERROR;
	
    case PPC_FLOAT_STATE:
		dprintf(("kdp_writeregs THREAD_FPSTATE\n"));
		return KDPERR_NO_ERROR;
	
    default:
		dprintf(("kdp_writeregs bad flavor %d\n"));
		return KDPERR_BADFLAVOR;
    }
}

void
kdp_machine_hostinfo(
    kdp_hostinfo_t *hostinfo
)
{
    machine_slot_t	m;
    int			i;

    hostinfo->cpus_mask = 0;

    for (i = 0; i < machine_info.max_cpus; i++) {
        m = &machine_slot[i];
        if (!m->is_cpu)
            continue;
	
        hostinfo->cpus_mask |= (1 << i);
        if (hostinfo->cpu_type == 0) {
            hostinfo->cpu_type = m->cpu_type;
            hostinfo->cpu_subtype = m->cpu_subtype;
        }
    }
}

void
kdp_panic(
    const char		*msg
)
{
    printf("kdp panic: %s\n", msg);    
    while(1) {}
}


void
kdp_reboot(void)
{
	halt_all_cpus(TRUE);;
}

int
kdp_intr_disbl(void)
{
    return (splhigh());
}

void
kdp_intr_enbl(int s)
{
    splx(s);
}

void
kdp_us_spin(int usec)
{
    extern void delay(int);

    delay(usec/100);
}

void print_saved_state(void *state)
{
    struct ppc_thread_state	*saved_state;

    saved_state = state;

	printf("pc = 0x%x\n", saved_state->srr0);
	printf("msr = 0x%x\n", saved_state->srr1);
	printf("rp = 0x%x\n", saved_state->lr);
	printf("sp = 0x%x\n", saved_state->r1);

}

void
kdp_call()
{
	Debugger("inline call to debugger(machine_startup)");
}

/*
 * table to convert system specific code to generic codes for kdb
 */
int kdp_trap_codes[] = {
	EXC_BAD_ACCESS,	/* 0x0000  INVALID EXCEPTION */
	EXC_BAD_ACCESS,	/* 0x0100  System reset */
	EXC_BAD_ACCESS,	/* 0x0200  Machine check */
	EXC_BAD_ACCESS,	/* 0x0300  Data access */
	EXC_BAD_ACCESS,	/* 0x0400  Instruction access */
	EXC_BAD_ACCESS,	/* 0x0500  External interrupt */
	EXC_BAD_ACCESS,	/* 0x0600  Alignment */
	EXC_BREAKPOINT,	/* 0x0700  Program - fp exc, ill/priv instr, trap */
	EXC_ARITHMETIC,	/* 0x0800  Floating point disabled */
	EXC_SOFTWARE,	/* 0x0900  Decrementer */
	EXC_BAD_ACCESS,	/* 0x0A00  I/O controller interface */
	EXC_BAD_ACCESS,	/* 0x0B00  INVALID EXCEPTION */
	EXC_SOFTWARE,	/* 0x0C00  System call exception */
	EXC_BREAKPOINT,	/* 0x0D00  Trace */
	EXC_SOFTWARE,	/* 0x0E00  FP assist */
	EXC_SOFTWARE,	/* 0x0F00  Performance monitoring */
	EXC_ARITHMETIC,	/* 0x0F20  Altivec disabled */
	EXC_BAD_ACCESS,	/* 0x1000  Instruction PTE miss */
	EXC_BAD_ACCESS,	/* 0x1100  Data load PTE miss */
	EXC_BAD_ACCESS,	/* 0x1200  Data store PTE miss */
	EXC_BREAKPOINT,	/* 0x1300  Instruction bkpt */
	EXC_SOFTWARE,	/* 0x1400  System management */
	EXC_BAD_ACCESS,	/* 0x1500  INVALID EXCEPTION */
	EXC_ARITHMETIC,	/* 0x1600  Altivec Assist */
	EXC_BAD_ACCESS,	/* 0x1700  INVALID EXCEPTION */
	EXC_BAD_ACCESS,	/* 0x1800  INVALID EXCEPTION */
	EXC_BAD_ACCESS,	/* 0x1900  INVALID EXCEPTION */
	EXC_BAD_ACCESS,	/* 0x1A00  INVALID EXCEPTION */
	EXC_BAD_ACCESS,	/* 0x1B00  INVALID EXCEPTION */
	EXC_BAD_ACCESS,	/* 0x1C00  INVALID EXCEPTION */
	EXC_BAD_ACCESS,	/* 0x1D00  INVALID EXCEPTION */
	EXC_BAD_ACCESS,	/* 0x1E00  INVALID EXCEPTION */
	EXC_BAD_ACCESS,	/* 0x1F00  INVALID EXCEPTION */
	EXC_BREAKPOINT,	/* 0x2000  Run Mode/Trace */
	EXC_BAD_ACCESS,	/* 0x2100  INVALID EXCEPTION */
	EXC_BAD_ACCESS,	/* 0x2200  INVALID EXCEPTION */
	EXC_BAD_ACCESS,	/* 0x2300  INVALID EXCEPTION */
	EXC_BAD_ACCESS,	/* 0x2400  INVALID EXCEPTION */
	EXC_BAD_ACCESS,	/* 0x2500  INVALID EXCEPTION */
	EXC_BAD_ACCESS,	/* 0x2600  INVALID EXCEPTION */
	EXC_BAD_ACCESS,	/* 0x2700  INVALID EXCEPTION */
	EXC_BAD_ACCESS,	/* 0x2800  INVALID EXCEPTION */
	EXC_BAD_ACCESS,	/* 0x2900  INVALID EXCEPTION */
	EXC_BAD_ACCESS,	/* 0x2A00  INVALID EXCEPTION */
	EXC_BAD_ACCESS,	/* 0x2B00  INVALID EXCEPTION */
	EXC_BAD_ACCESS,	/* 0x2C00  INVALID EXCEPTION */
	EXC_BAD_ACCESS,	/* 0x2D00  INVALID EXCEPTION */
	EXC_BAD_ACCESS,	/* 0x2E00  INVALID EXCEPTION */
	EXC_BAD_ACCESS,	/* 0x2F00  INVALID EXCEPTION */
	EXC_SOFTWARE	/* 0x3000  AST trap (software) */
};

int
kdp_getc()
{
	return(cnmaygetc());
}

int kdp_backtrace;
int kdp_sr_dump;
int kdp_dabr;
int kdp_noisy;

#define kdp_code(x) kdp_trap_codes[((x)==T_AST?0x31:(x)/T_VECTOR_SIZE)]

void
kdp_trap(
    unsigned int		exception,
    struct ppc_thread_state	*saved_state
)
{
	unsigned int *fp;
        unsigned int register sp;
	struct ppc_thread_state *state;

	if (kdp_noisy) {
		if (kdp_backtrace) {
			printf("\nvector=%x, \n", exception/4);
#ifdef XXX
			regDump(saved_state);
#endif
			sp = saved_state->r1;
			printf("stack backtrace - sp(%x)  ", sp);
			fp = (unsigned int *) *((unsigned int *)sp);
			while (fp) {
				printf("0x%08x ", fp[2]);
				fp = (unsigned int *)*fp;
			}
			printf("\n");
		}
#ifdef XXX
		if (kdp_sr_dump) {
			dump_segment_registers();
		}
#endif
	
	printf("vector=%d  ", exception/4);
	}

	kdp_raise_exception(kdp_code(exception), 0, 0, saved_state);

	if (kdp_noisy)
		printf("kdp_trap: kdp_raise_exception() ret\n");

	if (*((int *)saved_state->srr0) == 0x7c800008)
		saved_state->srr0 += 4; /* BKPT_SIZE */
		
	if(saved_state->srr1 & (MASK(MSR_SE) | MASK(MSR_BE))) {	/* Are we just stepping or continuing */
		db_run_mode = STEP_ONCE;				/* We are stepping */
	}
	else db_run_mode = STEP_CONTINUE;			/* Otherwise we are continuing */


#ifdef XXX
	mtspr(dabr, kdp_dabr);
#endif
}

boolean_t 
kdp_call_kdb(
	void)
{
	switch_debugger=1;
	return(TRUE);
}

void kdp_print_registers(struct ppc_saved_state *state)
{
	int i;
	for (i=0; i<32; i++) {
		if ((i % 8) == 0)
			printf("\n%4d :",i);
			printf(" %08x",*(&state->r0+i));
	}
	printf("\n");
	printf("cr        = 0x%08x\t\t",state->cr);
	printf("xer       = 0x%08x\n",state->xer);
	printf("lr        = 0x%08x\t\t",state->lr);
	printf("ctr       = 0x%08x\n",state->ctr);
	printf("srr0(iar) = 0x%08x\t\t",state->srr0);
	printf("srr1(msr) = 0x%08B\n",state->srr1,
		"\x10\x11""EE\x12PR\x13""FP\x14ME\x15""FE0\x16SE\x18"
		"FE1\x19""AL\x1a""EP\x1bIT\x1c""DT");
	printf("mq        = 0x%08x\t\t",state->mq);
	printf("sr_copyin = 0x%08x\n",state->sr_copyin);
	printf("\n");
}

void
kdp_print_backtrace(
    unsigned int                exception,
    struct ppc_saved_state     *saved_state)
{
	extern void kdp_print_registers(struct ppc_saved_state *);
	extern void print_backtrace(struct ppc_saved_state *);
	extern unsigned int debug_mode, disableDebugOuput;

	disableDebugOuput = FALSE;
	debug_mode = TRUE;
	printf("re-entering kdp:\n");
	printf("vector=%x, \n", exception/4);
	kdp_print_registers(saved_state);
	print_backtrace(saved_state);
	printf("panic: We are hanging here...\n");
	while(1);
}
