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
 
#include <mach_kdp.h>
#include <mach/mach_types.h>
#include <mach/machine.h>
#include <mach/exception_types.h>
#include <kern/cpu_data.h>
#include <i386/trap.h>
#include <i386/mp.h>
#include <kdp/kdp_internal.h>
#include <kdp/kdp_callout.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <IOKit/IOPlatformExpert.h> /* for PE_halt_restart */
#include <kern/machine.h> /* for halt_all_cpus */
#include <libkern/OSAtomic.h>

#include <kern/thread.h>
#include <i386/thread.h>
#include <vm/vm_map.h>
#include <i386/pmap.h>
#include <kern/kalloc.h>

#define KDP_TEST_HARNESS 0
#if KDP_TEST_HARNESS
#define dprintf(x) printf x
#else
#define dprintf(x)
#endif

extern cpu_type_t cpuid_cputype(void);
extern cpu_subtype_t cpuid_cpusubtype(void);

extern vm_offset_t machine_trace_thread_get_kva(vm_offset_t cur_target_addr);
extern void machine_trace_thread_clear_validation_cache(void);

void		print_saved_state(void *);
void		kdp_call(void);
int		kdp_getc(void);
boolean_t	kdp_call_kdb(void);
void		kdp_getstate(x86_thread_state64_t *);
void		kdp_setstate(x86_thread_state64_t *);
void		kdp_print_phys(int);

int
machine_trace_thread(thread_t thread, char *tracepos, char *tracebound, int nframes, boolean_t user_p);

int
machine_trace_thread64(thread_t thread, char *tracepos, char *tracebound, int nframes, boolean_t user_p);

unsigned
machine_read64(addr64_t srcaddr, caddr_t dstaddr, uint32_t len);

static void	kdp_callouts(kdp_event_t event);

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
    x86_thread_state64_t	*state
)
{
    x86_saved_state64_t	*saved_state;
    
    saved_state = (x86_saved_state64_t *)kdp.saved_state;
    
    state->rax = saved_state->rax;
    state->rbx = saved_state->rbx;
    state->rcx = saved_state->rcx;
    state->rdx = saved_state->rdx;
    state->rdi = saved_state->rdi;
    state->rsi = saved_state->rsi;
    state->rbp = saved_state->rbp;

    state->r8  = saved_state->r8;
    state->r9  = saved_state->r9;
    state->r10 = saved_state->r10;
    state->r11 = saved_state->r11;
    state->r12 = saved_state->r12;
    state->r13 = saved_state->r13;
    state->r14 = saved_state->r14;
    state->r15 = saved_state->r15;
    
    state->rsp = saved_state->isf.rsp;
    state->rflags = saved_state->isf.rflags;
    state->rip = saved_state->isf.rip;

    state->cs = saved_state->isf.cs;
    state->fs = saved_state->fs;
    state->gs = saved_state->gs;
}


void
kdp_setstate(
    x86_thread_state64_t	*state
)
{
    x86_saved_state64_t		*saved_state;
    
    saved_state = (x86_saved_state64_t *)kdp.saved_state;
    saved_state->rax = state->rax;
    saved_state->rbx = state->rbx;
    saved_state->rcx = state->rcx;
    saved_state->rdx = state->rdx;
    saved_state->rdi = state->rdi;
    saved_state->rsi = state->rsi;
    saved_state->rbp = state->rbp;
    saved_state->r8  = state->r8;
    saved_state->r9  = state->r9;
    saved_state->r10 = state->r10;
    saved_state->r11 = state->r11;
    saved_state->r12 = state->r12;
    saved_state->r13 = state->r13;
    saved_state->r14 = state->r14;
    saved_state->r15 = state->r15;

    saved_state->isf.rflags = state->rflags;
    saved_state->isf.rsp = state->rsp;
    saved_state->isf.rip = state->rip;

    saved_state->fs = (uint32_t)state->fs;
    saved_state->gs = (uint32_t)state->gs;
}


kdp_error_t
kdp_machine_read_regs(
    __unused unsigned int cpu,
    unsigned int flavor,
    char *data,
    int *size
)
{
    static x86_float_state64_t  null_fpstate;

    switch (flavor) {

    case x86_THREAD_STATE64:
	dprintf(("kdp_readregs THREAD_STATE64\n"));
	kdp_getstate((x86_thread_state64_t *)data);
	*size = sizeof (x86_thread_state64_t);
	return KDPERR_NO_ERROR;
	
    case x86_FLOAT_STATE64:
	dprintf(("kdp_readregs THREAD_FPSTATE64\n"));
	*(x86_float_state64_t *)data = null_fpstate;
	*size = sizeof (x86_float_state64_t);
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

    case x86_THREAD_STATE64:
	dprintf(("kdp_writeregs THREAD_STATE64\n"));
	kdp_setstate((x86_thread_state64_t *)data);
	return KDPERR_NO_ERROR;
	
    case x86_FLOAT_STATE64:
	dprintf(("kdp_writeregs THREAD_FPSTATE64\n"));
	return KDPERR_NO_ERROR;
	
    default:
	dprintf(("kdp_writeregs bad flavor %d\n", flavor));
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

    hostinfo->cpu_type = cpuid_cputype() | CPU_ARCH_ABI64;
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
kdp_machine_reboot(void)
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
kdp_getc(void)
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
    x86_saved_state64_t		*saved_state;

    saved_state = state;

	kprintf("pc = 0x%llx\n", saved_state->isf.rip);
	kprintf("cr2= 0x%llx\n", saved_state->cr2);
	kprintf("rp = TODO FIXME\n");
	kprintf("sp = %p\n", saved_state);

}

void
kdp_sync_cache(void)
{
	return;	/* No op here. */
}

void
kdp_call(void)
{
	__asm__ volatile ("int	$3");	/* Let the processor do the work */
}


typedef struct _cframe_t {
    struct _cframe_t	*prev;
    unsigned		caller;
    unsigned		args[0];
} cframe_t;

extern pt_entry_t *DMAP2;
extern caddr_t DADDR2;

void
kdp_print_phys(int src)
{
	unsigned int   *iptr;
	int             i;

	*(int *) DMAP2 = 0x63 | (src & 0xfffff000);
	invlpg((uintptr_t) DADDR2);
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
    unsigned int		trapno,
    x86_saved_state64_t	*saved_state,
    kern_return_t	result,
    vm_offset_t		va
)
{
    unsigned int exception, subcode = 0, code;

    if (trapno != T_INT3 && trapno != T_DEBUG) {
    	kprintf("Debugger: Unexpected kernel trap number: "
		"0x%x, RIP: 0x%llx, CR2: 0x%llx\n",
		trapno, saved_state->isf.rip, saved_state->cr2);
	if (!kdp.is_conn)
	    return FALSE;
    }	

    mp_kdp_enter();
    kdp_callouts(KDP_EVENT_ENTER);

    if (saved_state->isf.rflags & EFL_TF) {
	    enable_preemption_no_check();
    }

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
	subcode	= (unsigned int)saved_state->isf.err;
	break;
    
    case T_STACK_FAULT:
	exception = EXC_BAD_INSTRUCTION;
	code = EXC_I386_STKFLT;
	subcode	= (unsigned int)saved_state->isf.err;
	break;
    
    case T_GENERAL_PROTECTION:
	exception = EXC_BAD_INSTRUCTION;
	code = EXC_I386_GPFLT;
	subcode	= (unsigned int)saved_state->isf.err;
	break;
	
    case T_PAGE_FAULT:
    	exception = EXC_BAD_ACCESS;
	code = result;
	subcode = (unsigned int)va;
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

    if (current_cpu_datap()->cpu_fatal_trap_state) {
	    current_cpu_datap()->cpu_post_fatal_trap_state = saved_state;
	    saved_state = current_cpu_datap()->cpu_fatal_trap_state;
    }

    kdp_raise_exception(exception, code, subcode, saved_state);
    /* If the instruction single step bit is set, disable kernel preemption
     */
    if (saved_state->isf.rflags & EFL_TF) {
	    disable_preemption();
    }

    kdp_callouts(KDP_EVENT_EXIT);
    mp_kdp_exit();

    return TRUE;
}

boolean_t 
kdp_call_kdb(
        void) 
{       
        return(FALSE);
}

void
kdp_machine_get_breakinsn(
						  uint8_t *bytes,
						  uint32_t *size
)
{
	bytes[0] = 0xcc;
	*size = 1;
}

extern pmap_t kdp_pmap;

#define RETURN_OFFSET 4

int
machine_trace_thread(thread_t thread, char *tracepos, char *tracebound, int nframes, boolean_t user_p)
{
	uint32_t *tracebuf = (uint32_t *)tracepos;
	uint32_t fence = 0;
	uint32_t stackptr = 0;
	uint32_t stacklimit = 0xfc000000;
	int framecount = 0;
	uint32_t init_eip = 0;
	uint32_t prevsp = 0;
	uint32_t framesize = 2 * sizeof(vm_offset_t);
	vm_offset_t kern_virt_addr = 0;

	if (user_p) {
	        x86_saved_state32_t	*iss32;
		
		iss32 = USER_REGS32(thread);
		init_eip = iss32->eip;
		stackptr = iss32->ebp;

		stacklimit = 0xffffffff;
		kdp_pmap = thread->task->map->pmap;
	}
	else
		panic("32-bit trace attempted on 64-bit kernel");

	*tracebuf++ = init_eip;

	for (framecount = 0; framecount < nframes; framecount++) {

		if ((tracebound - ((char *)tracebuf)) < (4 * framesize)) {
			tracebuf--;
			break;
		}

		*tracebuf++ = stackptr;
/* Invalid frame, or hit fence */
		if (!stackptr || (stackptr == fence)) {
			break;
		}

		/* Unaligned frame */
		if (stackptr & 0x0000003) {
			break;
		}
		
		if (stackptr <= prevsp) {
			break;
		}

		if (stackptr > stacklimit) {
			break;
		}

		kern_virt_addr = machine_trace_thread_get_kva(stackptr + RETURN_OFFSET);

		if (!kern_virt_addr) {
			break;
		}

		*tracebuf = *(uint32_t *)kern_virt_addr;
		tracebuf++;
		
		prevsp = stackptr;
		kern_virt_addr = machine_trace_thread_get_kva(stackptr);

		if (!kern_virt_addr) {
			*tracebuf++ = 0;
			break;
		}

		stackptr = *(uint32_t *)kern_virt_addr;
	}

	machine_trace_thread_clear_validation_cache();
	kdp_pmap = 0;

	return (uint32_t) (((char *) tracebuf) - tracepos);
}


#define RETURN_OFFSET64	8
/* Routine to encapsulate the 64-bit address read hack*/
unsigned
machine_read64(addr64_t srcaddr, caddr_t dstaddr, uint32_t len)
{
	return (unsigned)kdp_machine_vm_read(srcaddr, dstaddr, len);
}

int
machine_trace_thread64(thread_t thread, char *tracepos, char *tracebound, int nframes, boolean_t user_p)
{
	uint64_t *tracebuf = (uint64_t *)tracepos;
	uint32_t fence = 0;
	addr64_t stackptr = 0;
	int	 framecount = 0;
	addr64_t init_rip = 0;
	addr64_t prevsp = 0;
	unsigned framesize = 2 * sizeof(addr64_t);
	vm_offset_t kern_virt_addr = 0;

	if (user_p) {
		x86_saved_state64_t	*iss64;
		iss64 = USER_REGS64(thread);
		init_rip = iss64->isf.rip;
		stackptr = iss64->rbp;
		kdp_pmap = thread->task->map->pmap;
	}
	else {
		stackptr = STACK_IKS(thread->kernel_stack)->k_rbp;
		init_rip = STACK_IKS(thread->kernel_stack)->k_rip;
		init_rip = VM_KERNEL_UNSLIDE(init_rip);
		kdp_pmap = 0;
	}

	*tracebuf++ = init_rip;

	for (framecount = 0; framecount < nframes; framecount++) {

		if ((uint32_t)(tracebound - ((char *)tracebuf)) < (4 * framesize)) {
			tracebuf--;
			break;
		}

		*tracebuf++ = stackptr;

		if (!stackptr || (stackptr == fence)){
			break;
		}

		if (stackptr & 0x0000007) {
			break;
		}

		if (stackptr <= prevsp) {
			break;
		}

		kern_virt_addr = machine_trace_thread_get_kva(stackptr + RETURN_OFFSET64);

		if (!kern_virt_addr) {
			break;
		}

		*tracebuf = *(uint64_t *)kern_virt_addr;
		if (!user_p)
			*tracebuf = VM_KERNEL_UNSLIDE(*tracebuf);

		tracebuf++;

		prevsp = stackptr;
		kern_virt_addr = machine_trace_thread_get_kva(stackptr);

		if (!kern_virt_addr) {
			*tracebuf++ = 0;
			break;
		}

		stackptr = *(uint64_t *)kern_virt_addr;
	}

	machine_trace_thread_clear_validation_cache();
	kdp_pmap = NULL;

	return (uint32_t) (((char *) tracebuf) - tracepos);
}

static struct kdp_callout {
	struct kdp_callout	*callout_next;
	kdp_callout_fn_t	callout_fn;
	void			*callout_arg;
} *kdp_callout_list = NULL;


/*
 * Called from kernel context to register a kdp event callout.
 */
void
kdp_register_callout(
	kdp_callout_fn_t	fn,
	void			*arg)
{
	struct kdp_callout	*kcp;
	struct kdp_callout	*list_head;

	kcp = kalloc(sizeof(*kcp));
	if (kcp == NULL)
		panic("kdp_register_callout() kalloc failed");

	kcp->callout_fn  = fn;
	kcp->callout_arg = arg;

	/* Lock-less list insertion using compare and exchange. */
	do {
		list_head = kdp_callout_list;
		kcp->callout_next = list_head;
	} while (!OSCompareAndSwapPtr(list_head, kcp, (void * volatile *)&kdp_callout_list));
}

/*
 * Called at exception/panic time when extering or exiting kdp.  
 * We are single-threaded at this time and so we don't use locks.
 */
static void
kdp_callouts(kdp_event_t event)
{
	struct kdp_callout	*kcp = kdp_callout_list;

	while (kcp) {
		kcp->callout_fn(kcp->callout_arg, event); 
		kcp = kcp->callout_next;
	}	
}

void
kdp_ml_enter_debugger(void)
{
	__asm__ __volatile__("int3");
}
