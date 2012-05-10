/*
 * Copyright (c) 2000-2007 Apple Inc. All rights reserved.
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
 * Copyright (c) 1991,1990,1989 Carnegie Mellon University
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

#include <mach_assert.h>
#include <mach_kdb.h>
#include <mach_kgdb.h>
#include <mach_kdp.h>

#include <kern/cpu_number.h>
#include <kern/kalloc.h>
#include <kern/lock.h>
#include <kern/spl.h>
#include <kern/thread.h>
#include <kern/assert.h>
#include <kern/sched_prim.h>
#include <kern/misc_protos.h>
#include <kern/clock.h>
#include <vm/vm_kern.h>
#include <vm/pmap.h>
#include <stdarg.h>
#if !MACH_KDP
#include <kdp/kdp_udp.h>
#endif

#if defined(__i386__) || defined(__x86_64__)
#include <i386/cpu_threads.h>
#include <i386/pmCPU.h>
#endif

#include <IOKit/IOPlatformExpert.h>
#include <machine/pal_routines.h>

#include <sys/kdebug.h>
#include <libkern/OSKextLibPrivate.h>
#include <libkern/OSAtomic.h>
#include <libkern/kernel_mach_header.h>
#include <uuid/uuid.h>

unsigned int	halt_in_debugger = 0;
unsigned int	switch_debugger = 0;
unsigned int	current_debugger = 0;
unsigned int	active_debugger = 0;
unsigned int	debug_mode=0;
unsigned int 	disable_debug_output = TRUE;
unsigned int 	systemLogDiags = FALSE;
unsigned int 	panicDebugging = FALSE;
unsigned int	logPanicDataToScreen = FALSE;

int mach_assert = 1;

const char		*panicstr = (char *) 0;
decl_simple_lock_data(,panic_lock)
int			paniccpu;
volatile int		panicwait;
volatile unsigned int	nestedpanic= 0;
unsigned int		panic_is_inited = 0;
unsigned int		return_on_panic = 0;
unsigned long		panic_caller;

#if CONFIG_EMBEDDED
#define DEBUG_BUF_SIZE (PAGE_SIZE)
#else
#define DEBUG_BUF_SIZE (3 * PAGE_SIZE)
#endif

char debug_buf[DEBUG_BUF_SIZE];
char *debug_buf_ptr = debug_buf;
unsigned int debug_buf_size = sizeof(debug_buf);

static char model_name[64];
/* uuid_string_t */ char kernel_uuid[37]; 

struct pasc {
  unsigned a: 7;
  unsigned b: 7;
  unsigned c: 7;
  unsigned d: 7;
  unsigned e: 7;
  unsigned f: 7;
  unsigned g: 7;
  unsigned h: 7;
}  __attribute__((packed));

typedef struct pasc pasc_t;

/* Prevent CPP from breaking the definition below */
#if CONFIG_NO_PANIC_STRINGS
#undef Assert
#endif

void
Assert(
	const char	*file,
	int		line,
	const char	*expression
      )
{
	int saved_return_on_panic;

	if (!mach_assert) {
		return;
	}

	saved_return_on_panic = return_on_panic;
	return_on_panic = 1;

	panic_plain("%s:%d Assertion failed: %s", file, line, expression);

	return_on_panic = saved_return_on_panic;
}

/*
 *	Carefully use the panic_lock.  There's always a chance that
 *	somehow we'll call panic before getting to initialize the
 *	panic_lock -- in this case, we'll assume that the world is
 *	in uniprocessor mode and just avoid using the panic lock.
 */
#define	PANIC_LOCK()							\
MACRO_BEGIN								\
	if (panic_is_inited)						\
		simple_lock(&panic_lock);				\
MACRO_END

#define	PANIC_UNLOCK()							\
MACRO_BEGIN								\
	if (panic_is_inited)						\
		simple_unlock(&panic_lock);				\
MACRO_END


void
panic_init(void)
{
	unsigned long uuidlen = 0;
	void *uuid;

	uuid = getuuidfromheader(&_mh_execute_header, &uuidlen);
	if ((uuid != NULL) && (uuidlen == sizeof(uuid_t))) {
		uuid_unparse_upper(*(uuid_t *)uuid, kernel_uuid);
	}

	simple_lock_init(&panic_lock, 0);
	panic_is_inited = 1;
	panic_caller = 0;
}

void
debug_log_init(void)
{
	if (debug_buf_size != 0)
		return;
	debug_buf_ptr = debug_buf;
	debug_buf_size = sizeof(debug_buf);
}

#if defined(__i386__) || defined(__x86_64__)
#define panic_stop()	pmCPUHalt(PM_HALT_PANIC)
#define panic_safe()	pmSafeMode(x86_lcpu(), PM_SAFE_FL_SAFE)
#define panic_normal()	pmSafeMode(x86_lcpu(), PM_SAFE_FL_NORMAL)
#else
#define panic_stop()	{ while (1) ; }
#define panic_safe()
#define panic_normal()
#endif

/*
 * Prevent CPP from breaking the definition below,
 * since all clients get a #define to prepend line numbers
 */
#undef panic

void _consume_panic_args(int a __unused, ...)
{
    panic("panic");
}

void
panic(const char *str, ...)
{
	va_list	listp;
	spl_t	s;
	thread_t thread;
	wait_queue_t wq;

	if (kdebug_enable) {
		ml_set_interrupts_enabled(TRUE);
		kdbg_dump_trace_to_file("/var/tmp/panic.trace");
	}

	s = splhigh();
	disable_preemption();

#if	defined(__i386__) || defined(__x86_64__)
	/* Attempt to display the unparsed panic string */
	const char *tstr = str;

	kprintf("Panic initiated, string: ");
	while (tstr && *tstr)
		kprintf("%c", *tstr++);
	kprintf("\n");
#endif

	panic_safe();

	thread = current_thread();		/* Get failing thread */
	wq = thread->wait_queue;		/* Save the old value */
	thread->wait_queue = NULL;		/* Clear the wait so we do not get double panics when we try locks */

	if( logPanicDataToScreen )
		disable_debug_output = FALSE;
		
	debug_mode = TRUE;

	/* panic_caller is initialized to 0.  If set, don't change it */
	if ( ! panic_caller )
		panic_caller = (unsigned long)(char *)__builtin_return_address(0);
	
restart:
	PANIC_LOCK();
	if (panicstr) {
		if (cpu_number() != paniccpu) {
			PANIC_UNLOCK();
			/*
			 * Wait until message has been printed to identify correct
			 * cpu that made the first panic.
			 */
			while (panicwait)
				continue;
			goto restart;
	    } else {
			nestedpanic +=1;
			PANIC_UNLOCK();
			Debugger("double panic");
			printf("double panic:  We are hanging here...\n");
			panic_stop();
			/* NOTREACHED */
		}
	}
	panicstr = str;
	paniccpu = cpu_number();
	panicwait = 1;

	PANIC_UNLOCK();
	kdb_printf("panic(cpu %d caller 0x%lx): ", (unsigned) paniccpu, panic_caller);
	if (str) {
		va_start(listp, str);
		_doprnt(str, &listp, consdebug_putc, 0);
		va_end(listp);
	}
	kdb_printf("\n");

	/*
	 * Release panicwait indicator so that other cpus may call Debugger().
	 */
	panicwait = 0;
	Debugger("panic");
	/*
	 * Release panicstr so that we can handle normally other panics.
	 */
	PANIC_LOCK();
	panicstr = (char *)0;
	PANIC_UNLOCK();
	thread->wait_queue = wq; 	/* Restore the wait queue */

	if (return_on_panic) {
		panic_normal();
		enable_preemption();
		splx(s);
		return;
	}

	kdb_printf("panic: We are hanging here...\n");
	panic_stop();
	/* NOTREACHED */
}

void
log(__unused int level, char *fmt, ...)
{
	va_list	listp;

#ifdef lint
	level++;
#endif /* lint */
#ifdef	MACH_BSD
	disable_preemption();
	va_start(listp, fmt);
	_doprnt(fmt, &listp, conslog_putc, 0);
	va_end(listp);
	enable_preemption();
#endif
}

void
debug_putc(char c)
{
	if ((debug_buf_size != 0) &&
		((debug_buf_ptr-debug_buf) < (int)debug_buf_size)) {
		*debug_buf_ptr=c;
		debug_buf_ptr++;
	}
}

/* In-place packing routines -- inefficient, but they're called at most once.
 * Assumes "buflen" is a multiple of 8.
 */

int packA(char *inbuf, uint32_t length, uint32_t buflen)
{
  unsigned int i, j = 0;
  pasc_t pack;
  
  length = MIN(((length + 7) & ~7), buflen);

  for (i = 0; i < length; i+=8)
    {
      pack.a = inbuf[i];
      pack.b = inbuf[i+1];
      pack.c = inbuf[i+2];
      pack.d = inbuf[i+3];
      pack.e = inbuf[i+4];
      pack.f = inbuf[i+5];
      pack.g = inbuf[i+6];
      pack.h = inbuf[i+7];
      bcopy ((char *) &pack, inbuf + j, 7);
      j += 7;
    }
  return j;
}

void unpackA(char *inbuf, uint32_t length)
{
	pasc_t packs;
	unsigned i = 0;
	length = (length * 8)/7;

	while (i < length) {
	  packs = *(pasc_t *)&inbuf[i];
	  bcopy(&inbuf[i+7], &inbuf[i+8], MAX(0, (int) (length - i - 8)));
	  inbuf[i++] = packs.a;
	  inbuf[i++] = packs.b;
	  inbuf[i++] = packs.c;
	  inbuf[i++] = packs.d;
	  inbuf[i++] = packs.e;
	  inbuf[i++] = packs.f;
	  inbuf[i++] = packs.g;
	  inbuf[i++] = packs.h;
	}
}

extern void *proc_name_address(void *p);

static void
panic_display_process_name(void) {
	char proc_name[32] = "Unknown";
	task_t ctask = 0;
	void *cbsd_info = 0;

	if (ml_nofault_copy((vm_offset_t)&current_thread()->task, (vm_offset_t) &ctask, sizeof(task_t)) == sizeof(task_t))
		if(ml_nofault_copy((vm_offset_t)&ctask->bsd_info, (vm_offset_t)&cbsd_info, sizeof(&ctask->bsd_info)) == sizeof(&ctask->bsd_info))
			if (cbsd_info && (ml_nofault_copy((vm_offset_t) proc_name_address(cbsd_info), (vm_offset_t) &proc_name, sizeof(proc_name)) > 0))
				proc_name[sizeof(proc_name) - 1] = '\0';
	kdb_printf("\nBSD process name corresponding to current thread: %s\n", proc_name);
}

unsigned	panic_active(void) {
	return ((panicstr != (char *) 0));
}

void populate_model_name(char *model_string) {
	strlcpy(model_name, model_string, sizeof(model_name));
}

static void panic_display_model_name(void) {
	char tmp_model_name[sizeof(model_name)];

	if (ml_nofault_copy((vm_offset_t) &model_name, (vm_offset_t) &tmp_model_name, sizeof(model_name)) != sizeof(model_name))
		return;

	tmp_model_name[sizeof(tmp_model_name) - 1] = '\0';

	if (tmp_model_name[0] != 0)
		kdb_printf("System model name: %s\n", tmp_model_name);
}

static void panic_display_kernel_uuid(void) {
	char tmp_kernel_uuid[sizeof(kernel_uuid)];

	if (ml_nofault_copy((vm_offset_t) &kernel_uuid, (vm_offset_t) &tmp_kernel_uuid, sizeof(kernel_uuid)) != sizeof(kernel_uuid))
		return;

	if (tmp_kernel_uuid[0] != '\0')
		kdb_printf("Kernel UUID: %s\n", tmp_kernel_uuid);
}

static void panic_display_uptime(void) {
	uint64_t	uptime;
	absolutetime_to_nanoseconds(mach_absolute_time(), &uptime);

	kdb_printf("\nSystem uptime in nanoseconds: %llu\n", uptime);
}

extern const char version[];
extern char osversion[];

static volatile uint32_t config_displayed = 0;

__private_extern__ void panic_display_system_configuration(void) {

	panic_display_process_name();
	if (OSCompareAndSwap(0, 1, &config_displayed)) {
		char buf[256];
		if (strlcpy(buf, PE_boot_args(), sizeof(buf)))
			kdb_printf("Boot args: %s\n", buf);
		kdb_printf("\nMac OS version:\n%s\n",
		    (osversion[0] != 0) ? osversion : "Not yet set");
		kdb_printf("\nKernel version:\n%s\n",version);
		panic_display_kernel_uuid();
		panic_display_pal_info();
		panic_display_model_name();
		panic_display_uptime();
		panic_display_zprint();
#if CONFIG_ZLEAKS
		panic_display_ztrace();
#endif /* CONFIG_ZLEAKS */
		kext_dump_panic_lists(&kdb_log);
	}
}

extern zone_t		first_zone;
extern unsigned int	num_zones, stack_total;
extern unsigned long long stack_allocs;

#if defined(__i386__) || defined (__x86_64__)
extern unsigned int	inuse_ptepages_count;
extern long long alloc_ptepages_count;
#endif

extern boolean_t	panic_include_zprint;

__private_extern__ void panic_display_zprint()
{
	if(panic_include_zprint == TRUE) {

		unsigned int	i;
		struct zone	zone_copy;

		if(first_zone!=NULL) {
			if(ml_nofault_copy((vm_offset_t)first_zone, (vm_offset_t)&zone_copy, sizeof(struct zone)) == sizeof(struct zone)) {
				for (i = 0; i < num_zones; i++) {
					if(zone_copy.cur_size > (1024*1024)) {
						kdb_printf("%.20s:%lu\n",zone_copy.zone_name,(uintptr_t)zone_copy.cur_size);
					}	
					
					if(zone_copy.next_zone == NULL) {
						break;
					}

					if(ml_nofault_copy((vm_offset_t)zone_copy.next_zone, (vm_offset_t)&zone_copy, sizeof(struct zone)) != sizeof(struct zone)) {
						break;
					}
				}
			}
		}

		kdb_printf("Kernel Stacks:%lu\n",(uintptr_t)(kernel_stack_size * stack_total));

#if defined(__i386__) || defined (__x86_64__)
		kdb_printf("PageTables:%lu\n",(uintptr_t)(PAGE_SIZE * inuse_ptepages_count));
#endif

		kdb_printf("Kalloc.Large:%lu\n",(uintptr_t)kalloc_large_total);
	}
}

#if CONFIG_ZLEAKS
extern boolean_t	panic_include_ztrace;
extern struct ztrace* top_ztrace;
/*
 * Prints the backtrace most suspected of being a leaker, if we paniced in the zone allocator.
 * top_ztrace and panic_include_ztrace comes from osfmk/kern/zalloc.c
 */
__private_extern__ void panic_display_ztrace(void)
{
	if(panic_include_ztrace == TRUE) {
		unsigned int i = 0;
		struct ztrace top_ztrace_copy;
		
		/* Make sure not to trip another panic if there's something wrong with memory */
		if(ml_nofault_copy((vm_offset_t)top_ztrace, (vm_offset_t)&top_ztrace_copy, sizeof(struct ztrace)) == sizeof(struct ztrace)) {
			kdb_printf("\nBacktrace suspected of leaking: (outstanding bytes: %lu)\n", (uintptr_t)top_ztrace_copy.zt_size);
			/* Print the backtrace addresses */
			for (i = 0; (i < top_ztrace_copy.zt_depth && i < MAX_ZTRACE_DEPTH) ; i++) {
				kdb_printf("%p\n", top_ztrace_copy.zt_stack[i]);
			}
			/* Print any kexts in that backtrace, along with their link addresses so we can properly blame them */
			kmod_panic_dump((vm_offset_t *)&top_ztrace_copy.zt_stack[0], top_ztrace_copy.zt_depth);
		}
		else {
			kdb_printf("\nCan't access top_ztrace...\n");
		}
		kdb_printf("\n");
	}
}
#endif /* CONFIG_ZLEAKS */

#if !MACH_KDP
static struct ether_addr kdp_current_mac_address = {{0, 0, 0, 0, 0, 0}};

/* XXX ugly forward declares to stop warnings */
void *kdp_get_interface(void);
void kdp_set_ip_and_mac_addresses(struct in_addr *, struct ether_addr *);
void kdp_set_gateway_mac(void *);
void kdp_set_interface(void *);
void kdp_register_send_receive(void *, void *);
void kdp_unregister_send_receive(void *, void *);
void kdp_snapshot_preflight(int, void *, uint32_t, uint32_t);
int kdp_stack_snapshot_geterror(void);
int kdp_stack_snapshot_bytes_traced(void);

void *
kdp_get_interface( void)
{
        return(void *)0;
}

unsigned int
kdp_get_ip_address(void )
{ return 0; }

struct ether_addr
kdp_get_mac_addr(void)
{       
        return kdp_current_mac_address;
}

void
kdp_set_ip_and_mac_addresses(   
        __unused struct in_addr          *ipaddr,
        __unused struct ether_addr       *macaddr)
{}

void
kdp_set_gateway_mac(__unused void *gatewaymac)
{}

void
kdp_set_interface(__unused void *ifp)
{}

void
kdp_register_send_receive(__unused void *send, __unused void *receive)
{}

void
kdp_unregister_send_receive(__unused void *send, __unused void *receive)
{}

void
kdp_snapshot_preflight(__unused int pid, __unused void * tracebuf,
		__unused uint32_t tracebuf_size, __unused uint32_t options)
{}

int
kdp_stack_snapshot_geterror(void)
{       
        return -1;
}

int
kdp_stack_snapshot_bytes_traced(void)
{       
        return 0;
}

#endif
