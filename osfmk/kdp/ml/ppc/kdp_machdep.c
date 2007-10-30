/*
 * Copyright (c) 2000-2006 Apple Computer, Inc. All rights reserved.
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
 
#include <mach/mach_types.h>
#include <mach/exception_types.h>
#include <ppc/exception.h>
#include <ppc/proc_reg.h>
#include <kdp/kdp_internal.h>
#include <ppc/savearea.h>
#include <ppc/misc_protos.h>
#include <kern/debug.h>
#include <IOKit/IOPlatformExpert.h>

#include <kern/thread.h>
#include <ppc/thread.h>
#include <vm/vm_map.h>
#include <ppc/pmap.h>

#define KDP_TEST_HARNESS 0
#if KDP_TEST_HARNESS
#define dprintf(x) kprintf x
#else
#define dprintf(x)
#endif

void print_saved_state(void *);
void kdp_call(void);
int kdp_getc(void);
boolean_t kdp_call_kdb(void);

extern pmap_t kdp_pmap;
extern uint32_t kdp_src_high32;


extern unsigned kdp_vm_read(caddr_t src, caddr_t dst, unsigned len);

int
machine_trace_thread(thread_t thread, char *tracepos, char *tracebound, int nframes, boolean_t user_p);

int
machine_trace_thread64(thread_t thread, char *tracepos, char *tracebound, int nframes, boolean_t user_p);

unsigned
machine_read64(addr64_t srcaddr, caddr_t dstaddr, uint32_t len);

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

    if ((size_t)len < sizeof (*rq))
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
    struct savearea	*saved_state;
   
    saved_state = kdp.saved_state;
   
    bzero((char *)state,sizeof (struct ppc_thread_state)) ;

    state->srr0	= (unsigned int)saved_state->save_srr0;
    state->srr1	= (unsigned int)saved_state->save_srr1;
    state->r0	= (unsigned int)saved_state->save_r0;
    state->r1	= (unsigned int)saved_state->save_r1;
    state->r2	= (unsigned int)saved_state->save_r2;
    state->r3	= (unsigned int)saved_state->save_r3;
    state->r4	= (unsigned int)saved_state->save_r4;
    state->r5	= (unsigned int)saved_state->save_r5;
    state->r6	= (unsigned int)saved_state->save_r6;
    state->r7	= (unsigned int)saved_state->save_r7;
    state->r8	= (unsigned int)saved_state->save_r8;
    state->r9	= (unsigned int)saved_state->save_r9;
    state->r10	= (unsigned int)saved_state->save_r10;
    state->r11	= (unsigned int)saved_state->save_r11;
    state->r12	= (unsigned int)saved_state->save_r12;
    state->r13	= (unsigned int)saved_state->save_r13;
    state->r14	= (unsigned int)saved_state->save_r14;
    state->r15	= (unsigned int)saved_state->save_r15;
    state->r16	= (unsigned int)saved_state->save_r16;
    state->r17	= (unsigned int)saved_state->save_r17;
    state->r18	= (unsigned int)saved_state->save_r18;
    state->r19	= (unsigned int)saved_state->save_r19;
    state->r20	= (unsigned int)saved_state->save_r20;
    state->r21	= (unsigned int)saved_state->save_r21;
    state->r22	= (unsigned int)saved_state->save_r22;
    state->r23	= (unsigned int)saved_state->save_r23;
    state->r24	= (unsigned int)saved_state->save_r24;
    state->r25	= (unsigned int)saved_state->save_r25;
    state->r26	= (unsigned int)saved_state->save_r26;
    state->r27	= (unsigned int)saved_state->save_r27;
    state->r28	= (unsigned int)saved_state->save_r28;
    state->r29	= (unsigned int)saved_state->save_r29;
    state->r30	= (unsigned int)saved_state->save_r30;
    state->r31	= (unsigned int)saved_state->save_r31;
    state->cr	= (unsigned int)saved_state->save_cr;
    state->xer	= (unsigned int)saved_state->save_xer;
    state->lr	= (unsigned int)saved_state->save_lr;
    state->ctr	= (unsigned int)saved_state->save_ctr;
}

static void
kdp_getintegerstate64(
    struct ppc_thread_state64	*state
)
{
    struct savearea	*saved_state;
   
    saved_state = kdp.saved_state;
   
    bzero((char *)state,sizeof (struct ppc_thread_state64)) ;

    state->srr0	= saved_state->save_srr0;
    state->srr1	= saved_state->save_srr1;
    state->r0	= saved_state->save_r0;
    state->r1	= saved_state->save_r1;
    state->r2	= saved_state->save_r2;
    state->r3	= saved_state->save_r3;
    state->r4	= saved_state->save_r4;
    state->r5	= saved_state->save_r5;
    state->r6	= saved_state->save_r6;
    state->r7	= saved_state->save_r7;
    state->r8	= saved_state->save_r8;
    state->r9	= saved_state->save_r9;
    state->r10	= saved_state->save_r10;
    state->r11	= saved_state->save_r11;
    state->r12	= saved_state->save_r12;
    state->r13	= saved_state->save_r13;
    state->r14	= saved_state->save_r14;
    state->r15	= saved_state->save_r15;
    state->r16	= saved_state->save_r16;
    state->r17	= saved_state->save_r17;
    state->r18	= saved_state->save_r18;
    state->r19	= saved_state->save_r19;
    state->r20	= saved_state->save_r20;
    state->r21	= saved_state->save_r21;
    state->r22	= saved_state->save_r22;
    state->r23	= saved_state->save_r23;
    state->r24	= saved_state->save_r24;
    state->r25	= saved_state->save_r25;
    state->r26	= saved_state->save_r26;
    state->r27	= saved_state->save_r27;
    state->r28	= saved_state->save_r28;
    state->r29	= saved_state->save_r29;
    state->r30	= saved_state->save_r30;
    state->r31	= saved_state->save_r31;
    state->cr	= saved_state->save_cr;
    state->xer	= saved_state->save_xer;
    state->lr	= saved_state->save_lr;
    state->ctr	= saved_state->save_ctr;
}

kdp_error_t
kdp_machine_read_regs(
    __unused unsigned int cpu,
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

    case PPC_THREAD_STATE64:
		dprintf(("kdp_readregs THREAD_STATE\n"));
		kdp_getintegerstate64((struct ppc_thread_state64 *)data);
		*size = PPC_THREAD_STATE64_COUNT * sizeof(int);
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
    struct savearea	*saved_state;
   
    saved_state = kdp.saved_state;

    saved_state->save_srr0	= state->srr0;
    saved_state->save_srr1	= state->srr1;
    saved_state->save_r0	= state->r0;
    saved_state->save_r1	= state->r1;
    saved_state->save_r2	= state->r2;
    saved_state->save_r3	= state->r3;
    saved_state->save_r4	= state->r4;
    saved_state->save_r5	= state->r5;
    saved_state->save_r6	= state->r6;
    saved_state->save_r7	= state->r7;
    saved_state->save_r8	= state->r8;
    saved_state->save_r9	= state->r9;
    saved_state->save_r10	= state->r10;
    saved_state->save_r11	= state->r11;
    saved_state->save_r12	= state->r12;
    saved_state->save_r13	= state->r13;
    saved_state->save_r14	= state->r14;
    saved_state->save_r15	= state->r15;
    saved_state->save_r16	= state->r16;
    saved_state->save_r17	= state->r17;
    saved_state->save_r18	= state->r18;
    saved_state->save_r19	= state->r19;
    saved_state->save_r20	= state->r20;
    saved_state->save_r21	= state->r21;
    saved_state->save_r22	= state->r22;
    saved_state->save_r23	= state->r23;
    saved_state->save_r24	= state->r24;
    saved_state->save_r25	= state->r25;
    saved_state->save_r26	= state->r26;
    saved_state->save_r27	= state->r27;
    saved_state->save_r28	= state->r28;
    saved_state->save_r29	= state->r29;
    saved_state->save_r30	= state->r30;
    saved_state->save_r31	= state->r31;
    saved_state->save_cr	= state->cr;
    saved_state->save_xer	= state->xer;
    saved_state->save_lr	= state->lr;
    saved_state->save_ctr	= state->ctr;
}

static void
kdp_setintegerstate64(
    struct ppc_thread_state64		*state
)
{
    struct savearea	*saved_state;
   
    saved_state = kdp.saved_state;

    saved_state->save_srr0	= state->srr0;
    saved_state->save_srr1	= state->srr1;
    saved_state->save_r0	= state->r0;
    saved_state->save_r1	= state->r1;
    saved_state->save_r2	= state->r2;
    saved_state->save_r3	= state->r3;
    saved_state->save_r4	= state->r4;
    saved_state->save_r5	= state->r5;
    saved_state->save_r6	= state->r6;
    saved_state->save_r7	= state->r7;
    saved_state->save_r8	= state->r8;
    saved_state->save_r9	= state->r9;
    saved_state->save_r10	= state->r10;
    saved_state->save_r11	= state->r11;
    saved_state->save_r12	= state->r12;
    saved_state->save_r13	= state->r13;
    saved_state->save_r14	= state->r14;
    saved_state->save_r15	= state->r15;
    saved_state->save_r16	= state->r16;
    saved_state->save_r17	= state->r17;
    saved_state->save_r18	= state->r18;
    saved_state->save_r19	= state->r19;
    saved_state->save_r20	= state->r20;
    saved_state->save_r21	= state->r21;
    saved_state->save_r22	= state->r22;
    saved_state->save_r23	= state->r23;
    saved_state->save_r24	= state->r24;
    saved_state->save_r25	= state->r25;
    saved_state->save_r26	= state->r26;
    saved_state->save_r27	= state->r27;
    saved_state->save_r28	= state->r28;
    saved_state->save_r29	= state->r29;
    saved_state->save_r30	= state->r30;
    saved_state->save_r31	= state->r31;
    saved_state->save_cr	= state->cr;
    saved_state->save_xer	= state->xer;
    saved_state->save_lr	= state->lr;
    saved_state->save_ctr	= state->ctr;
}

kdp_error_t
kdp_machine_write_regs(
    __unused unsigned int cpu,
    unsigned int flavor,
    char *data,
    __unused int *size
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

    case PPC_THREAD_STATE64:
		dprintf(("kdp_writeregs THREAD_STATE64\n"));
		kdp_setintegerstate64((struct ppc_thread_state64 *)data);

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
    int			i;

    hostinfo->cpus_mask = 0;
    hostinfo->cpu_type = 0;

    for (i = 0; i < machine_info.max_cpus; i++) {
        if ((PerProcTable[i].ppe_vaddr == (struct per_proc_info *)NULL) || 
	    !(PerProcTable[i].ppe_vaddr->running))
            continue;
	
        hostinfo->cpus_mask |= (1 << i);
        if (hostinfo->cpu_type == 0) {
            hostinfo->cpu_type = slot_type(i);
            hostinfo->cpu_subtype = slot_subtype(i);
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

extern void halt_all_cpus(boolean_t);

void
kdp_reboot(void)
{
	printf("Attempting system restart...");
	/* Call the platform specific restart*/
	if (PE_halt_restart) 
		(*PE_halt_restart)(kPERestartCPU);
	/* If we do reach this, give up */
	halt_all_cpus(TRUE);
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
kdp_call(void)
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
kdp_getc(void)
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
    struct savearea	*saved_state
)
{
	unsigned int *fp;
	unsigned int sp;

	if (kdp_noisy) {
		if (kdp_backtrace) {
			printf("\nvector=%x, \n", exception/4);
			sp = saved_state->save_r1;
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

	if ((unsigned int)(saved_state->save_srr0) == 0x7c800008)
		saved_state->save_srr0 += 4;			/* BKPT_SIZE */

	if(saved_state->save_srr1 & (MASK(MSR_SE) | MASK(MSR_BE))) {	/* Are we just stepping or continuing */
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

static void kdp_print_registers(struct savearea *state)
{
	int i;
	for (i=0; i<32; i++) {
		if ((i % 8) == 0)
			printf("\n%4d :",i);
			printf(" %08llx",*(&state->save_r0+i));
	}
	printf("\n");
	printf("cr        = 0x%08x\t\t",state->save_cr);
	printf("xer       = 0x%08llx\n",state->save_xer);
	printf("lr        = 0x%08llx\t\t",state->save_lr);
	printf("ctr       = 0x%08llx\n",state->save_ctr);
	printf("srr0(iar) = 0x%08llx\t\t",state->save_srr0);
	printf("srr1(msr) = 0x%08B\n",state->save_srr1,
		"\x10\x11""EE\x12PR\x13""FP\x14ME\x15""FE0\x16SE\x18"
		"FE1\x19""AL\x1a""EP\x1bIT\x1c""DT");
	printf("\n");
}

void kdp_print_backtrace(unsigned, struct savearea *);

void
kdp_print_backtrace(
    unsigned int                exception,
    struct savearea     *saved_state)
{
	disable_debug_output = FALSE;
	debug_mode = TRUE;
	printf("re-entering kdp:\n");
	printf("vector=%x, \n", exception/4);
	kdp_print_registers(saved_state);
	print_backtrace(saved_state);
	printf("panic: We are hanging here...\n");
	while(1);
}

unsigned int kdp_ml_get_breakinsn(void)
{
  return 0x7fe00008;
}
#define LR_OFFSET 8
#define LR_OFFSET64 16

int
machine_trace_thread(thread_t thread, char *tracepos, char *tracebound, int nframes, boolean_t user_p)
{
	uint32_t *tracebuf = (uint32_t *)tracepos;
	uint32_t fence = 0;
	uint32_t stackptr = 0;
	uint32_t stacklimit = 0xb0000000;
	int framecount = 0;
	uint32_t init_srr0 = 0;
	uint32_t prevsp = 0;
	uint32_t framesize = 2 * sizeof(vm_offset_t);
	
	if (user_p) {
		/* Examine the user savearea */
		init_srr0 = thread->machine.upcb->save_srr0;
		stackptr = thread->machine.upcb->save_r1;
		/* This bound isn't useful, but it doesn't hinder us */
		stacklimit = 0xffffffff;
		kdp_pmap = thread->task->map->pmap;
	}
	else {
		stackptr = thread->machine.pcb->save_r1;
		init_srr0 = thread->machine.pcb->save_srr0;
	}
	/* Fill in the "current" program counter */
	*tracebuf++ = init_srr0;

	for (framecount = 0; framecount < nframes; framecount++) {
/* Bounds check */
		if ((uint32_t) (tracebound - ((char *)tracebuf)) < (4 * framesize)) {
			tracebuf--;
			break;
		}

		*tracebuf++ = stackptr;
/* Invalid frame, or hit fence */
		if (!stackptr || (stackptr == fence)) {
			break;
		}
/* Stack grows downward */		
		if (stackptr < prevsp) {
			break;
		}
/* Unaligned frame */		
		if (stackptr & 0x000000F) {
			break;
		}
		if (stackptr > stacklimit) {
			break;
		}
/* Assume there's a saved link register, and read it */
		if (kdp_vm_read((caddr_t) (stackptr + LR_OFFSET), (caddr_t) tracebuf, sizeof(caddr_t)) != sizeof(caddr_t)) {
			break;
		}

		tracebuf++;
		prevsp = stackptr;
/* Next frame */
		if (kdp_vm_read((caddr_t) stackptr, (caddr_t) &stackptr, sizeof(caddr_t)) != sizeof(caddr_t)) {
			*tracebuf++ = 0;
			break;
		}
	}
/* Reset the target pmap */
	kdp_pmap = NULL;
	return (uint32_t) (((char *) tracebuf) - tracepos);
}

/* Routine to encapsulate the 64-bit address read hack*/
unsigned
machine_read64(addr64_t srcaddr, caddr_t dstaddr, uint32_t len)
{
	uint32_t kdp_vm_read_low32;
	unsigned retval;
	
	kdp_src_high32 = srcaddr >> 32;
	kdp_vm_read_low32 = srcaddr & 0x00000000FFFFFFFFUL;
	retval = kdp_vm_read((caddr_t)kdp_vm_read_low32, dstaddr, len);
	kdp_src_high32 = 0;
	return retval;
}

int
machine_trace_thread64(thread_t thread, char *tracepos, char *tracebound, int nframes, boolean_t user_p)
{
	uint64_t *tracebuf = (uint64_t *)tracepos;
	uint32_t fence = 0;
	addr64_t stackptr = 0;
	uint64_t stacklimit = 0xb0000000;
	int framecount = 0;
	addr64_t init_srr0 = 0;
	addr64_t prevsp = 0;
	unsigned framesize = 2 * sizeof(addr64_t);
	
	if (user_p) {
		init_srr0 = thread->machine.upcb->save_srr0;
		stackptr = thread->machine.upcb->save_r1;
		stacklimit = 0xffffffffffffffffULL;
		kdp_pmap = thread->task->map->pmap;
	}
	else {
		stackptr = thread->machine.pcb->save_r1;
		init_srr0 = thread->machine.pcb->save_srr0;
	}
	
	*tracebuf++ = init_srr0;

	for (framecount = 0; framecount < nframes; framecount++) {

		if ((uint32_t)(tracebound - ((char *)tracebuf)) < (4 * framesize)) {
			tracebuf--;
			break;
		}

		*tracebuf++ = stackptr;

		if (!stackptr || (stackptr == fence)){
			break;
		}
		if (stackptr < prevsp) {
			break;
		}
		if (stackptr & 0x000000F) {
			break;
		}
		if (stackptr > stacklimit) {
			break;
		}

		if (machine_read64(stackptr+LR_OFFSET64, (caddr_t) tracebuf, sizeof(addr64_t)) != sizeof(addr64_t)) {
			break;
		}
		tracebuf++;
		
		prevsp = stackptr;
		if (machine_read64(stackptr, (caddr_t) &stackptr, sizeof(addr64_t)) != sizeof(addr64_t)) {
			*tracebuf++ = 0;
			break;
		}
	}

	kdp_pmap = NULL;
	return (uint32_t) (((char *) tracebuf) - tracepos);
}


void
kdp_ml_enter_debugger(void)
{
	__asm__ __volatile__("tw 4,r3,r3");
}
