/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_OSREFERENCE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code 
 * as defined in and that are subject to the Apple Public Source License 
 * Version 2.0 (the 'License'). You may not use this file except in 
 * compliance with the License.  The rights granted to you under the 
 * License may not be used to create, or enable the creation or 
 * redistribution of, unlawful or unlicensed copies of an Apple operating 
 * system, or to circumvent, violate, or enable the circumvention or 
 * violation of, any terms of an Apple operating system software license 
 * agreement.
 *
 * Please obtain a copy of the License at 
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
 * @APPLE_LICENSE_OSREFERENCE_HEADER_END@
 */
 
#include <mach_kdp.h>
#include <mach/mach_types.h>
#include <mach/machine.h>
#include <mach/exception_types.h>
#include <kern/cpu_data.h>
#include <i386/trap.h>
#include <i386/mp.h>
#include <kdp/kdp_internal.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <IOKit/IOPlatformExpert.h> /* for PE_halt_restart */
#include <kern/machine.h> /* for halt_all_cpus */

#include <kern/thread.h>
#include <i386/thread.h>
#include <vm/vm_map.h>
#include <i386/pmap.h>

#define KDP_TEST_HARNESS 0
#if KDP_TEST_HARNESS
#define dprintf(x) printf x
#else
#define dprintf(x)
#endif

extern cpu_type_t cpuid_cputype(void);
extern cpu_subtype_t cpuid_cpusubtype(void);

void		print_saved_state(void *);
void		kdp_call(void);
int		kdp_getc(void);
boolean_t	kdp_call_kdb(void);
void		kdp_getstate(i386_thread_state_t *);
void		kdp_setstate(i386_thread_state_t *);
void		kdp_print_phys(int);

int
machine_trace_thread(thread_t thread, uint32_t tracepos, uint32_t tracebound, int nframes, boolean_t user_p);

int
machine_trace_thread64(thread_t thread, uint32_t tracepos, uint32_t tracebound, int nframes, boolean_t user_p);

extern unsigned kdp_vm_read(caddr_t src, caddr_t dst, unsigned len);

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
    kdp_exception_t	*rq = (kdp_exception_t *)pkt;

    rq->hdr.request = KDP_EXCEPTION;
    rq->hdr.is_reply = 0;
    rq->hdr.seq = kdp.exception_seq;
    rq->hdr.key = 0;
    rq->hdr.len = sizeof (*rq);
    
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
    kdp_exception_ack_t	*rq = (kdp_exception_ack_t *)pkt;

    if (((unsigned int) len) < sizeof (*rq))
	return(FALSE);
	
    if (!rq->hdr.is_reply || rq->hdr.request != KDP_EXCEPTION)
    	return(FALSE);
	
    dprintf(("kdp_exception_ack seq %x %x\n", rq->hdr.seq, kdp.exception_seq));
	
    if (rq->hdr.seq == kdp.exception_seq) {
	kdp.exception_ack_needed = FALSE;
	kdp.exception_seq++;
    }
    return(TRUE);
}

void
kdp_getstate(
    x86_thread_state32_t	*state
)
{
    static x86_thread_state32_t	null_state;
    x86_saved_state32_t	*saved_state;
    
    saved_state = (x86_saved_state32_t *)kdp.saved_state;
    
    *state = null_state;	
    state->eax = saved_state->eax;
    state->ebx = saved_state->ebx;
    state->ecx = saved_state->ecx;
    state->edx = saved_state->edx;
    state->edi = saved_state->edi;
    state->esi = saved_state->esi;
    state->ebp = saved_state->ebp;

    if ((saved_state->cs & 0x3) == 0){	/* Kernel State */
    	state->esp = (unsigned int) &saved_state->uesp;
        state->ss = KERNEL_DS;
    } else {
    	state->esp = saved_state->uesp;
    	state->ss = saved_state->ss;
    }

    state->eflags = saved_state->efl;
    state->eip = saved_state->eip;
    state->cs = saved_state->cs;
    state->ds = saved_state->ds;
    state->es = saved_state->es;
    state->fs = saved_state->fs;
    state->gs = saved_state->gs;
}


void
kdp_setstate(
    x86_thread_state32_t	*state
)
{
    x86_saved_state32_t		*saved_state;
    
    saved_state = (x86_saved_state32_t *)kdp.saved_state;

    saved_state->eax = state->eax;
    saved_state->ebx = state->ebx;
    saved_state->ecx = state->ecx;
    saved_state->edx = state->edx;
    saved_state->edi = state->edi;
    saved_state->esi = state->esi;
    saved_state->ebp = state->ebp;
    saved_state->efl = state->eflags;
#if	0
    saved_state->frame.eflags &= ~( EFL_VM | EFL_NT | EFL_IOPL | EFL_CLR );
    saved_state->frame.eflags |=  ( EFL_IF | EFL_SET );
#endif
    saved_state->eip = state->eip;
    saved_state->fs = state->fs;
    saved_state->gs = state->gs;
}


kdp_error_t
kdp_machine_read_regs(
    __unused unsigned int cpu,
    __unused unsigned int flavor,
    char *data,
    __unused int *size
)
{
    static struct i386_float_state  null_fpstate;

    switch (flavor) {

    case OLD_i386_THREAD_STATE:
    case x86_THREAD_STATE32:
	dprintf(("kdp_readregs THREAD_STATE\n"));
	kdp_getstate((x86_thread_state32_t *)data);
	*size = sizeof (x86_thread_state32_t);
	return KDPERR_NO_ERROR;
	
    case x86_FLOAT_STATE32:
	dprintf(("kdp_readregs THREAD_FPSTATE\n"));
	*(x86_float_state32_t *)data = null_fpstate;
	*size = sizeof (x86_float_state32_t);
	return KDPERR_NO_ERROR;
	
    default:
	dprintf(("kdp_readregs bad flavor %d\n", flavor));
	*size = 0;
	return KDPERR_BADFLAVOR;
    }
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

    case OLD_i386_THREAD_STATE:
    case x86_THREAD_STATE32:
	dprintf(("kdp_writeregs THREAD_STATE\n"));
	kdp_setstate((x86_thread_state32_t *)data);
	return KDPERR_NO_ERROR;
	
    case x86_FLOAT_STATE32:
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

    for (i = 0; i < machine_info.max_cpus; i++) {
	if (cpu_data_ptr[i] == NULL)
            continue;
	
        hostinfo->cpus_mask |= (1 << i);
    }

    hostinfo->cpu_type = cpuid_cputype();
    hostinfo->cpu_subtype = cpuid_cpusubtype();
}

void
kdp_panic(
    const char		*msg
)
{
    kprintf("kdp panic: %s\n", msg);    
    __asm__ volatile("hlt");	
}


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
   return splhigh();
}

void
kdp_intr_enbl(int s)
{
	splx(s);
}

int
kdp_getc()
{
	return	cnmaygetc();
}

void
kdp_us_spin(int usec)
{
    delay(usec/100);
}

void print_saved_state(void *state)
{
    x86_saved_state32_t		*saved_state;

    saved_state = state;

	kprintf("pc = 0x%x\n", saved_state->eip);
	kprintf("cr2= 0x%x\n", saved_state->cr2);
	kprintf("rp = TODO FIXME\n");
	kprintf("sp = 0x%x\n", saved_state);

}

void
kdp_sync_cache()
{
	return;	/* No op here. */
}

void
kdp_call()
{
	__asm__ volatile ("int	$3");	/* Let the processor do the work */
}


typedef struct _cframe_t {
    struct _cframe_t	*prev;
    unsigned		caller;
    unsigned		args[0];
} cframe_t;

#include <i386/pmap.h>
extern pt_entry_t *DMAP2;
extern caddr_t DADDR2;

void
kdp_print_phys(int src)
{
	unsigned int   *iptr;
	int             i;

	*(int *) DMAP2 = 0x63 | (src & 0xfffff000);
	invlpg((u_int) DADDR2);
	iptr = (unsigned int *) DADDR2;
	for (i = 0; i < 100; i++) {
		kprintf("0x%x ", *iptr++);
		if ((i % 8) == 0)
			kprintf("\n");
	}
	kprintf("\n");
	*(int *) DMAP2 = 0;

}

boolean_t
kdp_i386_trap(
    unsigned int	trapno,
    x86_saved_state32_t	*saved_state,
    kern_return_t	result,
    vm_offset_t		va
)
{
    unsigned int exception, subcode = 0, code;

    if (trapno != T_INT3 && trapno != T_DEBUG) {
    	kprintf("unexpected kernel trap 0x%x eip 0x%x cr2 0x%x \n",
		trapno, saved_state->eip, saved_state->cr2);
	if (!kdp.is_conn)
	    return FALSE;
    }	

    mp_kdp_enter();

    switch (trapno) {
    
    case T_DIVIDE_ERROR:
	exception = EXC_ARITHMETIC;
	code = EXC_I386_DIVERR;
	break;
    
    case T_OVERFLOW:
	exception = EXC_SOFTWARE;
	code = EXC_I386_INTOFLT;
	break;
    
    case T_OUT_OF_BOUNDS:
	exception = EXC_ARITHMETIC;
	code = EXC_I386_BOUNDFLT;
	break;
    
    case T_INVALID_OPCODE:
	exception = EXC_BAD_INSTRUCTION;
	code = EXC_I386_INVOPFLT;
	break;
    
    case T_SEGMENT_NOT_PRESENT:
	exception = EXC_BAD_INSTRUCTION;
	code = EXC_I386_SEGNPFLT;
	subcode	= saved_state->err;
	break;
    
    case T_STACK_FAULT:
	exception = EXC_BAD_INSTRUCTION;
	code = EXC_I386_STKFLT;
	subcode	= saved_state->err;
	break;
    
    case T_GENERAL_PROTECTION:
	exception = EXC_BAD_INSTRUCTION;
	code = EXC_I386_GPFLT;
	subcode	= saved_state->err;
	break;
	
    case T_PAGE_FAULT:
    	exception = EXC_BAD_ACCESS;
	code = result;
	subcode = va;
	break;
    
    case T_WATCHPOINT:
	exception = EXC_SOFTWARE;
	code = EXC_I386_ALIGNFLT;
	break;
	
    case T_DEBUG:
    case T_INT3:
	exception = EXC_BREAKPOINT;
	code = EXC_I386_BPTFLT;
	break;

    default:
    	exception = EXC_BAD_INSTRUCTION;
	code = trapno;
	break;
    }

    kdp_raise_exception(exception, code, subcode, saved_state);

    mp_kdp_exit();

    return TRUE;
}

boolean_t 
kdp_call_kdb(
        void) 
{       
        return(FALSE);
}

unsigned int
kdp_ml_get_breakinsn(void)
{
  return 0xcc;
}
extern pmap_t kdp_pmap;

#define RETURN_OFFSET 4
int
machine_trace_thread(thread_t thread, uint32_t tracepos, uint32_t tracebound, int nframes, boolean_t user_p)
{
	uint32_t *tracebuf = (uint32_t *)tracepos;
	uint32_t fence = 0;
	uint32_t stackptr = 0;
	uint32_t stacklimit = 0xfc000000;
	int framecount = 0;
	uint32_t init_eip = 0;
	uint32_t prevsp = 0;
	uint32_t framesize = 2 * sizeof(vm_offset_t);
	
	if (user_p) {
	        x86_saved_state32_t	*iss32;
		
		iss32 = USER_REGS32(thread);

		init_eip = iss32->eip;
		stackptr = iss32->ebp;

		/* This bound isn't useful, but it doesn't hinder us*/
		stacklimit = 0xffffffff;
		kdp_pmap = thread->task->map->pmap;
	}
	else {
		/*Examine the i386_saved_state at the base of the kernel stack*/
		stackptr = STACK_IKS(thread->kernel_stack)->k_ebp;
		init_eip = STACK_IKS(thread->kernel_stack)->k_eip;
	}

	*tracebuf++ = init_eip;

	for (framecount = 0; framecount < nframes; framecount++) {

		if ((tracebound - ((uint32_t) tracebuf)) < (4 * framesize)) {
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
		if (stackptr & 0x0000003) {
			break;
		}
		if (stackptr > stacklimit) {
			break;
		}

		if (kdp_vm_read((caddr_t) (stackptr + RETURN_OFFSET), (caddr_t) tracebuf, sizeof(caddr_t)) != sizeof(caddr_t)) {
			break;
		}
		tracebuf++;
		
		prevsp = stackptr;
		if (kdp_vm_read((caddr_t) stackptr, (caddr_t) &stackptr, sizeof(caddr_t)) != sizeof(caddr_t)) {
			*tracebuf++ = 0;
			break;
		}
	}

	kdp_pmap = 0;

	return ((uint32_t) tracebuf - tracepos);
}

/* This is a stub until the x86 64-bit model becomes clear */
int
machine_trace_thread64(__unused thread_t thread, __unused uint32_t tracepos, __unused uint32_t tracebound, __unused int nframes, __unused boolean_t user_p) {
	return 0;
}
