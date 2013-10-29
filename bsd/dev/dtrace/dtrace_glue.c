/*
 * Copyright (c) 2005-2006 Apple Computer, Inc. All rights reserved.
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
 * APPLE NOTE: This file is compiled even if dtrace is unconfig'd. A symbol
 * from this file (_dtrace_register_anon_DOF) always needs to be exported for
 * an external kext to link against.
 */

#if CONFIG_DTRACE

#define MACH__POSIX_C_SOURCE_PRIVATE 1 /* pulls in suitable savearea from mach/ppc/thread_status.h */
#include <kern/thread.h>
#include <mach/thread_status.h>

#include <stdarg.h>
#include <string.h>
#include <sys/malloc.h>
#include <sys/time.h>
#include <sys/proc.h>
#include <sys/proc_internal.h>
#include <sys/kauth.h>
#include <sys/user.h>
#include <sys/systm.h>
#include <sys/dtrace.h>
#include <sys/dtrace_impl.h>
#include <libkern/OSAtomic.h>
#include <kern/kern_types.h>
#include <kern/timer_call.h>
#include <kern/thread_call.h>
#include <kern/task.h>
#include <kern/sched_prim.h>
#include <kern/queue.h>
#include <miscfs/devfs/devfs.h>
#include <kern/kalloc.h>

#include <mach/vm_param.h>
#include <mach/mach_vm.h>
#include <mach/task.h>
#include <vm/pmap.h>
#include <vm/vm_map.h> /* All the bits we care about are guarded by MACH_KERNEL_PRIVATE :-( */


/*
 * pid/proc
 */
/* Solaris proc_t is the struct. Darwin's proc_t is a pointer to it. */
#define proc_t struct proc /* Steer clear of the Darwin typedef for proc_t */

/* Not called from probe context */
proc_t * 
sprlock(pid_t pid)
{
	proc_t* p;

	if ((p = proc_find(pid)) == PROC_NULL) {
		return PROC_NULL;
	}

	task_suspend(p->task);

	proc_lock(p);

	lck_mtx_lock(&p->p_dtrace_sprlock);

	return p;
}

/* Not called from probe context */
void
sprunlock(proc_t *p)
{
	if (p != PROC_NULL) {
		lck_mtx_unlock(&p->p_dtrace_sprlock);

		proc_unlock(p);

		task_resume(p->task);

		proc_rele(p);
	}
}

/*
 * uread/uwrite
 */

// These are not exported from vm_map.h.
extern kern_return_t vm_map_read_user(vm_map_t map, vm_map_address_t src_addr, void *dst_p, vm_size_t size);
extern kern_return_t vm_map_write_user(vm_map_t map, void *src_p, vm_map_address_t dst_addr, vm_size_t size);

/* Not called from probe context */
int
uread(proc_t *p, void *buf, user_size_t len, user_addr_t a)
{
	kern_return_t ret;

	ASSERT(p != PROC_NULL);
	ASSERT(p->task != NULL);

	task_t task = p->task;

	/*
	 * Grab a reference to the task vm_map_t to make sure
	 * the map isn't pulled out from under us.
	 *
	 * Because the proc_lock is not held at all times on all code
	 * paths leading here, it is possible for the proc to have
	 * exited. If the map is null, fail.
	 */
	vm_map_t map = get_task_map_reference(task);
	if (map) {
		ret = vm_map_read_user( map, (vm_map_address_t)a, buf, (vm_size_t)len);
		vm_map_deallocate(map);
	} else
		ret = KERN_TERMINATED;
	
	return (int)ret;
}


/* Not called from probe context */
int
uwrite(proc_t *p, void *buf, user_size_t len, user_addr_t a)
{
	kern_return_t ret;

	ASSERT(p != NULL);
	ASSERT(p->task != NULL);

	task_t task = p->task;

	/*
	 * Grab a reference to the task vm_map_t to make sure
	 * the map isn't pulled out from under us.
	 *
	 * Because the proc_lock is not held at all times on all code
	 * paths leading here, it is possible for the proc to have
	 * exited. If the map is null, fail.
	 */
	vm_map_t map = get_task_map_reference(task);
	if (map) {
		/* Find the memory permissions. */
		uint32_t nestingDepth=999999;
		vm_region_submap_short_info_data_64_t info;
		mach_msg_type_number_t count = VM_REGION_SUBMAP_SHORT_INFO_COUNT_64;
		mach_vm_address_t address = (mach_vm_address_t)a;
		mach_vm_size_t sizeOfRegion = (mach_vm_size_t)len;
	
		ret = mach_vm_region_recurse(map, &address, &sizeOfRegion, &nestingDepth, (vm_region_recurse_info_t)&info, &count);
		if (ret != KERN_SUCCESS)
			goto done;

		vm_prot_t reprotect;

		if (!(info.protection & VM_PROT_WRITE)) {
			/* Save the original protection values for restoration later */
			reprotect = info.protection;

			if (info.max_protection & VM_PROT_WRITE) {
				/* The memory is not currently writable, but can be made writable. */
				ret = mach_vm_protect (map, (mach_vm_offset_t)a, (mach_vm_size_t)len, 0, reprotect | VM_PROT_WRITE);
			} else {
				/*
				 * The memory is not currently writable, and cannot be made writable. We need to COW this memory.
				 *
				 * Strange, we can't just say "reprotect | VM_PROT_COPY", that fails.
				 */
				ret = mach_vm_protect (map, (mach_vm_offset_t)a, (mach_vm_size_t)len, 0, VM_PROT_COPY | VM_PROT_READ | VM_PROT_WRITE);
			}

			if (ret != KERN_SUCCESS)
				goto done;

		} else {
			/* The memory was already writable. */
			reprotect = VM_PROT_NONE;
		}

		ret = vm_map_write_user( map,
					 buf,
					 (vm_map_address_t)a,
					 (vm_size_t)len);

		if (ret != KERN_SUCCESS)
			goto done;

		if (reprotect != VM_PROT_NONE) {
			ASSERT(reprotect & VM_PROT_EXECUTE);
			ret = mach_vm_protect (map, (mach_vm_offset_t)a, (mach_vm_size_t)len, 0, reprotect);
		}

done:
		vm_map_deallocate(map);
	} else 
		ret = KERN_TERMINATED;

	return (int)ret;
}

/*
 * cpuvar
 */
lck_mtx_t cpu_lock;
lck_mtx_t mod_lock;

dtrace_cpu_t *cpu_list;
cpu_core_t *cpu_core; /* XXX TLB lockdown? */

/*
 * cred_t
 */

/*
 * dtrace_CRED() can be called from probe context. We cannot simply call kauth_cred_get() since
 * that function may try to resolve a lazy credential binding, which entails taking the proc_lock.
 */ 
cred_t *
dtrace_CRED(void)
{
	struct uthread *uthread = get_bsdthread_info(current_thread());

	if (uthread == NULL)
		return NULL;
	else
		return uthread->uu_ucred; /* May return NOCRED which is defined to be 0 */
}

#define	HAS_ALLPRIVS(cr)	priv_isfullset(&CR_OEPRIV(cr))
#define	HAS_PRIVILEGE(cr, pr)	((pr) == PRIV_ALL ? \
					HAS_ALLPRIVS(cr) : \
					PRIV_ISASSERT(&CR_OEPRIV(cr), pr))

int PRIV_POLICY_CHOICE(void* cred, int priv, int all)
{
#pragma unused(priv, all)
	return kauth_cred_issuser(cred); /* XXX TODO: How is this different from PRIV_POLICY_ONLY? */
}

int 
PRIV_POLICY_ONLY(void *cr, int priv, int boolean)
{
#pragma unused(priv, boolean)
	return kauth_cred_issuser(cr); /* XXX TODO: HAS_PRIVILEGE(cr, priv); */
}

/* XXX Get around const poisoning using structure assigns */
gid_t
crgetgid(const cred_t *cr) { cred_t copy_cr = *cr; return kauth_cred_getgid(&copy_cr); }

uid_t
crgetuid(const cred_t *cr) { cred_t copy_cr = *cr; return kauth_cred_getuid(&copy_cr); }

/*
 * "cyclic"
 */

typedef struct wrap_timer_call {
	cyc_handler_t hdlr;
	cyc_time_t when;
	uint64_t deadline;
	struct timer_call call;
} wrap_timer_call_t;

#define WAKEUP_REAPER 0x7FFFFFFFFFFFFFFFLL
#define NEARLY_FOREVER 0x7FFFFFFFFFFFFFFELL

static void
_timer_call_apply_cyclic( void *ignore, void *vTChdl )
{
#pragma unused(ignore)
	wrap_timer_call_t *wrapTC = (wrap_timer_call_t *)vTChdl;

	(*(wrapTC->hdlr.cyh_func))( wrapTC->hdlr.cyh_arg );

	clock_deadline_for_periodic_event( wrapTC->when.cyt_interval, mach_absolute_time(), &(wrapTC->deadline) );
	timer_call_enter1( &(wrapTC->call), (void *)wrapTC, wrapTC->deadline, TIMER_CALL_SYS_CRITICAL | TIMER_CALL_LOCAL );

	/* Did timer_call_remove_cyclic request a wakeup call when this timer call was re-armed? */
	if (wrapTC->when.cyt_interval == WAKEUP_REAPER)
		thread_wakeup((event_t)wrapTC);
}

static cyclic_id_t
timer_call_add_cyclic(wrap_timer_call_t *wrapTC, cyc_handler_t *handler, cyc_time_t *when)
{
	uint64_t now;

	timer_call_setup( &(wrapTC->call),  _timer_call_apply_cyclic, NULL );
	wrapTC->hdlr = *handler;
	wrapTC->when = *when;

	nanoseconds_to_absolutetime( wrapTC->when.cyt_interval, (uint64_t *)&wrapTC->when.cyt_interval );

	now = mach_absolute_time();
	wrapTC->deadline = now;

	clock_deadline_for_periodic_event( wrapTC->when.cyt_interval, now, &(wrapTC->deadline) );
	timer_call_enter1( &(wrapTC->call), (void *)wrapTC, wrapTC->deadline, TIMER_CALL_SYS_CRITICAL | TIMER_CALL_LOCAL );

	return (cyclic_id_t)wrapTC;
}

static void
timer_call_remove_cyclic(cyclic_id_t cyclic)
{
	wrap_timer_call_t *wrapTC = (wrap_timer_call_t *)cyclic;

	while (!timer_call_cancel(&(wrapTC->call))) {
		int ret = assert_wait(wrapTC, THREAD_UNINT);
		ASSERT(ret == THREAD_WAITING);

		wrapTC->when.cyt_interval = WAKEUP_REAPER;

		ret = thread_block(THREAD_CONTINUE_NULL);
		ASSERT(ret == THREAD_AWAKENED);
	}
}

static void *
timer_call_get_cyclic_arg(cyclic_id_t cyclic)
{       
	wrap_timer_call_t *wrapTC = (wrap_timer_call_t *)cyclic;
 	
	return (wrapTC ? wrapTC->hdlr.cyh_arg : NULL);
}   

cyclic_id_t
cyclic_timer_add(cyc_handler_t *handler, cyc_time_t *when)
{
	wrap_timer_call_t *wrapTC = _MALLOC(sizeof(wrap_timer_call_t), M_TEMP, M_ZERO | M_WAITOK);
	if (NULL == wrapTC)
		return CYCLIC_NONE;
	else
		return timer_call_add_cyclic( wrapTC, handler, when );
}

void 
cyclic_timer_remove(cyclic_id_t cyclic)
{
	ASSERT( cyclic != CYCLIC_NONE );

	timer_call_remove_cyclic( cyclic );
	_FREE((void *)cyclic, M_TEMP);
}

static void
_cyclic_add_omni(cyclic_id_list_t cyc_list)
{
	cyc_time_t cT;
	cyc_handler_t cH;
	wrap_timer_call_t *wrapTC;
	cyc_omni_handler_t *omni = (cyc_omni_handler_t *)cyc_list;
	char *t;

	(omni->cyo_online)(omni->cyo_arg, CPU, &cH, &cT); 

	t = (char *)cyc_list;
	t += sizeof(cyc_omni_handler_t);
	cyc_list = (cyclic_id_list_t)(uintptr_t)t;

	t += sizeof(cyclic_id_t)*NCPU;
	t += (sizeof(wrap_timer_call_t))*cpu_number();
	wrapTC = (wrap_timer_call_t *)(uintptr_t)t;

	cyc_list[cpu_number()] = timer_call_add_cyclic(wrapTC, &cH, &cT);
}

cyclic_id_list_t
cyclic_add_omni(cyc_omni_handler_t *omni)
{
	cyclic_id_list_t cyc_list = 
		_MALLOC( (sizeof(wrap_timer_call_t))*NCPU + 
				 sizeof(cyclic_id_t)*NCPU + 
				 sizeof(cyc_omni_handler_t), M_TEMP, M_ZERO | M_WAITOK);
	if (NULL == cyc_list)
		return (cyclic_id_list_t)CYCLIC_NONE;

	*(cyc_omni_handler_t *)cyc_list = *omni;
	dtrace_xcall(DTRACE_CPUALL, (dtrace_xcall_t)_cyclic_add_omni, (void *)cyc_list);

	return cyc_list;
}

static void
_cyclic_remove_omni(cyclic_id_list_t cyc_list)
{
	cyc_omni_handler_t *omni = (cyc_omni_handler_t *)cyc_list;
	void *oarg;
	cyclic_id_t cid;
	char *t;

	t = (char *)cyc_list;
	t += sizeof(cyc_omni_handler_t);
	cyc_list = (cyclic_id_list_t)(uintptr_t)t;

	cid = cyc_list[cpu_number()];
	oarg = timer_call_get_cyclic_arg(cid);

	timer_call_remove_cyclic( cid );
	(omni->cyo_offline)(omni->cyo_arg, CPU, oarg);
}

void
cyclic_remove_omni(cyclic_id_list_t cyc_list)
{
	ASSERT( cyc_list != (cyclic_id_list_t)CYCLIC_NONE );

	dtrace_xcall(DTRACE_CPUALL, (dtrace_xcall_t)_cyclic_remove_omni, (void *)cyc_list);
	_FREE(cyc_list, M_TEMP);
}

typedef struct wrap_thread_call {
	thread_call_t TChdl;
	cyc_handler_t hdlr;
	cyc_time_t when;
	uint64_t deadline;
} wrap_thread_call_t;

/*
 * _cyclic_apply will run on some thread under kernel_task. That's OK for the 
 * cleaner and the deadman, but too distant in time and place for the profile provider.
 */
static void
_cyclic_apply( void *ignore, void *vTChdl )
{
#pragma unused(ignore)
	wrap_thread_call_t *wrapTC = (wrap_thread_call_t *)vTChdl;

	(*(wrapTC->hdlr.cyh_func))( wrapTC->hdlr.cyh_arg );

	clock_deadline_for_periodic_event( wrapTC->when.cyt_interval, mach_absolute_time(), &(wrapTC->deadline) );
	(void)thread_call_enter1_delayed( wrapTC->TChdl, (void *)wrapTC, wrapTC->deadline );

	/* Did cyclic_remove request a wakeup call when this thread call was re-armed? */
	if (wrapTC->when.cyt_interval == WAKEUP_REAPER)
		thread_wakeup((event_t)wrapTC);
}

cyclic_id_t
cyclic_add(cyc_handler_t *handler, cyc_time_t *when)
{
	uint64_t now;

	wrap_thread_call_t *wrapTC = _MALLOC(sizeof(wrap_thread_call_t), M_TEMP, M_ZERO | M_WAITOK);
	if (NULL == wrapTC)
		return CYCLIC_NONE;

	wrapTC->TChdl = thread_call_allocate( _cyclic_apply, NULL );
	wrapTC->hdlr = *handler;
	wrapTC->when = *when;

	ASSERT(when->cyt_when == 0);
	ASSERT(when->cyt_interval < WAKEUP_REAPER);

	nanoseconds_to_absolutetime(wrapTC->when.cyt_interval, (uint64_t *)&wrapTC->when.cyt_interval);

	now = mach_absolute_time();
	wrapTC->deadline = now;

	clock_deadline_for_periodic_event( wrapTC->when.cyt_interval, now, &(wrapTC->deadline) );
	(void)thread_call_enter1_delayed( wrapTC->TChdl, (void *)wrapTC, wrapTC->deadline );

	return (cyclic_id_t)wrapTC;
}

static void
noop_cyh_func(void * ignore)
{
#pragma unused(ignore)
}

void
cyclic_remove(cyclic_id_t cyclic)
{
	wrap_thread_call_t *wrapTC = (wrap_thread_call_t *)cyclic;

	ASSERT(cyclic != CYCLIC_NONE);

	while (!thread_call_cancel(wrapTC->TChdl)) {
		int ret = assert_wait(wrapTC, THREAD_UNINT);
		ASSERT(ret == THREAD_WAITING);

		wrapTC->when.cyt_interval = WAKEUP_REAPER;

		ret = thread_block(THREAD_CONTINUE_NULL);
		ASSERT(ret == THREAD_AWAKENED);
	}

	if (thread_call_free(wrapTC->TChdl))
		_FREE(wrapTC, M_TEMP);
	else {
		/* Gut this cyclic and move on ... */
		wrapTC->hdlr.cyh_func = noop_cyh_func;
		wrapTC->when.cyt_interval = NEARLY_FOREVER;
	}
}

/*
 * timeout / untimeout (converted to dtrace_timeout / dtrace_untimeout due to name collision)
 */ 

thread_call_t
dtrace_timeout(void (*func)(void *, void *), void* arg, uint64_t nanos)
{
#pragma unused(arg)
	thread_call_t call = thread_call_allocate(func, NULL);

	nanoseconds_to_absolutetime(nanos, &nanos);

	/*
	 * This method does not use clock_deadline_for_periodic_event() because it is a one-shot,
	 * and clock drift on later invocations is not a worry.
	 */
	uint64_t deadline = mach_absolute_time() + nanos;
	/* DRK: consider using a lower priority callout here */
	thread_call_enter_delayed(call, deadline);

	return call;
}

/*
 * ddi
 */
void
ddi_report_dev(dev_info_t *devi)
{
#pragma unused(devi)
}

#define NSOFT_STATES 32 /* XXX No more than 32 clients at a time, please. */
static void *soft[NSOFT_STATES];

int
ddi_soft_state_init(void **state_p, size_t size, size_t n_items)
{
#pragma unused(n_items)
	int i;
	
	for (i = 0; i < NSOFT_STATES; ++i) soft[i] = _MALLOC(size, M_TEMP, M_ZERO | M_WAITOK);
	*(size_t *)state_p = size;
	return 0;
}

int
ddi_soft_state_zalloc(void *state, int item)
{
#pragma unused(state)
	if (item < NSOFT_STATES)
		return DDI_SUCCESS;
	else
		return DDI_FAILURE;
}

void *
ddi_get_soft_state(void *state, int item)
{
#pragma unused(state)
	ASSERT(item < NSOFT_STATES);
	return soft[item];
}

int
ddi_soft_state_free(void *state, int item)
{
	ASSERT(item < NSOFT_STATES);
	bzero( soft[item], (size_t)state );
	return DDI_SUCCESS;
}

void
ddi_soft_state_fini(void **state_p)
{
#pragma unused(state_p)
	int i;
	
	for (i = 0; i < NSOFT_STATES; ++i) _FREE( soft[i], M_TEMP );
}

static unsigned int gRegisteredProps = 0;
static struct {
	char name[32];		/* enough for "dof-data-" + digits */
	int *data;
	uint_t nelements;
} gPropTable[16];

kern_return_t _dtrace_register_anon_DOF(char *, uchar_t *, uint_t);

kern_return_t
_dtrace_register_anon_DOF(char *name, uchar_t *data, uint_t nelements)
{
	if (gRegisteredProps < sizeof(gPropTable)/sizeof(gPropTable[0])) {
		int *p = (int *)_MALLOC(nelements*sizeof(int), M_TEMP, M_WAITOK);
		
		if (NULL == p)
			return KERN_FAILURE;
			
		strlcpy(gPropTable[gRegisteredProps].name, name, sizeof(gPropTable[0].name));
		gPropTable[gRegisteredProps].nelements = nelements;
		gPropTable[gRegisteredProps].data = p;
			
		while (nelements-- > 0) {
			*p++ = (int)(*data++);
		}
		
		gRegisteredProps++;
		return KERN_SUCCESS;
	}
	else
		return KERN_FAILURE;
}

int
ddi_prop_lookup_int_array(dev_t match_dev, dev_info_t *dip, uint_t flags,
    const char *name, int **data, uint_t *nelements)
{
#pragma unused(match_dev,dip,flags)
	unsigned int i;
	for (i = 0; i < gRegisteredProps; ++i)
	{
		if (0 == strncmp(name, gPropTable[i].name,
					sizeof(gPropTable[i].name))) {
			*data = gPropTable[i].data;
			*nelements = gPropTable[i].nelements;
			return DDI_SUCCESS;
		}
	}
	return DDI_FAILURE;
}
	
int
ddi_prop_free(void *buf)
{
	_FREE(buf, M_TEMP);
	return DDI_SUCCESS;
}

int
ddi_driver_major(dev_info_t	*devi) { return (int)major(CAST_DOWN_EXPLICIT(int,devi)); }

int
ddi_create_minor_node(dev_info_t *dip, const char *name, int spec_type,
    minor_t minor_num, const char *node_type, int flag)
{
#pragma unused(spec_type,node_type,flag)
	dev_t dev = makedev( ddi_driver_major(dip), minor_num );

	if (NULL == devfs_make_node( dev, DEVFS_CHAR, UID_ROOT, GID_WHEEL, 0666, name, 0 ))
		return DDI_FAILURE;
	else
		return DDI_SUCCESS;
} 

void
ddi_remove_minor_node(dev_info_t *dip, char *name)
{
#pragma unused(dip,name)
/* XXX called from dtrace_detach, so NOTREACHED for now. */
}

major_t
getemajor( dev_t d )
{
	return (major_t) major(d);
}

minor_t
getminor ( dev_t d )
{
	return (minor_t) minor(d);
}

dev_t 
makedevice(major_t major, minor_t minor)
{
	return makedev( major, minor );
}

int ddi_getprop(dev_t dev, dev_info_t *dip, int flags, const char *name, int defvalue)
{
#pragma unused(dev, dip, flags, name)

	return defvalue;
}

/*
 * Kernel Debug Interface
 */
int
kdi_dtrace_set(kdi_dtrace_set_t ignore)
{
#pragma unused(ignore)
	return 0; /* Success */
}

extern void Debugger(const char*);

void
debug_enter(char *c) { Debugger(c); }

/*
 * kmem
 */

void *
dt_kmem_alloc(size_t size, int kmflag)
{
#pragma unused(kmflag)

/*
 * We ignore the M_NOWAIT bit in kmflag (all of kmflag, in fact).
 * Requests larger than 8K with M_NOWAIT fail in kalloc_canblock.
 */
#if defined(DTRACE_MEMORY_ZONES)
	return dtrace_alloc(size);
#else
	return kalloc(size);
#endif
}

void *
dt_kmem_zalloc(size_t size, int kmflag)
{
#pragma unused(kmflag)

/*
 * We ignore the M_NOWAIT bit in kmflag (all of kmflag, in fact).
 * Requests larger than 8K with M_NOWAIT fail in kalloc_canblock.
 */
#if defined(DTRACE_MEMORY_ZONES)
	void* buf = dtrace_alloc(size);
#else
	void* buf = kalloc(size);
#endif

	if(!buf)
		return NULL;

	bzero(buf, size);

	return buf;
}

void
dt_kmem_free(void *buf, size_t size)
{
#pragma unused(size)
	/*
	 * DTrace relies on this, its doing a lot of NULL frees.
	 * A null free causes the debug builds to panic.
	 */
	if (buf == NULL) return;

	ASSERT(size > 0);

#if defined(DTRACE_MEMORY_ZONES)
	dtrace_free(buf, size);
#else
	kfree(buf, size);
#endif
}



/*
 * aligned kmem allocator
 * align should be a power of two
 */

void* dt_kmem_alloc_aligned(size_t size, size_t align, int kmflag)
{
	void* buf;
	intptr_t p;
	void** buf_backup;

	buf = dt_kmem_alloc(align + sizeof(void*) + size, kmflag);

	if(!buf)
		return NULL;

	p = (intptr_t)buf;
	p += sizeof(void*);				/* now we have enough room to store the backup */
	p = P2ROUNDUP(p, align);			/* and now we're aligned */

	buf_backup = (void**)(p - sizeof(void*));
	*buf_backup = buf;				/* back up the address we need to free */

	return (void*)p;
}

void* dt_kmem_zalloc_aligned(size_t size, size_t align, int kmflag)
{
	void* buf;

	buf = dt_kmem_alloc_aligned(size, align, kmflag);

	if(!buf)
		return NULL;

	bzero(buf, size);

	return buf;
}

void dt_kmem_free_aligned(void* buf, size_t size)
{
#pragma unused(size)
	intptr_t p;
	void** buf_backup;

	p = (intptr_t)buf;
	p -= sizeof(void*);
	buf_backup = (void**)(p);

	dt_kmem_free(*buf_backup, size + ((char*)buf - (char*)*buf_backup));
}

/*
 * dtrace wants to manage just a single block: dtrace_state_percpu_t * NCPU, and
 * doesn't specify constructor, destructor, or reclaim methods.
 * At present, it always zeroes the block it obtains from kmem_cache_alloc().
 * We'll manage this constricted use of kmem_cache with ordinary _MALLOC and _FREE.
 */
kmem_cache_t *
kmem_cache_create(
    const char *name,		/* descriptive name for this cache */
    size_t bufsize,		/* size of the objects it manages */
    size_t align,		/* required object alignment */
    int (*constructor)(void *, void *, int), /* object constructor */
    void (*destructor)(void *, void *),	/* object destructor */
    void (*reclaim)(void *), /* memory reclaim callback */
    void *private,		/* pass-thru arg for constr/destr/reclaim */
    vmem_t *vmp,		/* vmem source for slab allocation */
    int cflags)		/* cache creation flags */
{
#pragma unused(name,align,constructor,destructor,reclaim,private,vmp,cflags)
	return (kmem_cache_t *)bufsize; /* A cookie that tracks the single object size. */
}
	
void *
kmem_cache_alloc(kmem_cache_t *cp, int kmflag)
{
#pragma unused(kmflag)
	size_t bufsize = (size_t)cp;
	return (void *)_MALLOC(bufsize, M_TEMP, M_WAITOK);
}

void
kmem_cache_free(kmem_cache_t *cp, void *buf)
{
#pragma unused(cp)
	_FREE(buf, M_TEMP);
}

void
kmem_cache_destroy(kmem_cache_t *cp)
{
#pragma unused(cp)
}

/*
 * taskq
 */
extern void thread_call_setup(thread_call_t, thread_call_func_t, thread_call_param_t); /* XXX MACH_KERNEL_PRIVATE */

static void
_taskq_apply( task_func_t func, thread_call_param_t arg )
{
	func( (void *)arg );
}

taskq_t *
taskq_create(const char *name, int nthreads, pri_t pri, int minalloc,
    int maxalloc, uint_t flags)
{
#pragma unused(name,nthreads,pri,minalloc,maxalloc,flags)

	return (taskq_t *)thread_call_allocate( (thread_call_func_t)_taskq_apply, NULL );
}

taskqid_t
taskq_dispatch(taskq_t *tq, task_func_t func, void *arg, uint_t flags)
{
#pragma unused(flags)
	thread_call_setup( (thread_call_t) tq, (thread_call_func_t)_taskq_apply, (thread_call_param_t)func );
	thread_call_enter1( (thread_call_t) tq, (thread_call_param_t)arg );
	return (taskqid_t) tq /* for lack of anything better */;
}

void	
taskq_destroy(taskq_t *tq)
{
	thread_call_cancel( (thread_call_t) tq );
	thread_call_free( (thread_call_t) tq );
}

pri_t maxclsyspri;

/*
 * vmem (Solaris "slab" allocator) used by DTrace solely to hand out resource ids
 */
typedef unsigned int u_daddr_t;
#include "blist.h"

/* By passing around blist *handles*, the underlying blist can be resized as needed. */
struct blist_hdl {
	blist_t blist; 
};

vmem_t * 
vmem_create(const char *name, void *base, size_t size, size_t quantum, void *ignore5,
					void *ignore6, vmem_t *source, size_t qcache_max, int vmflag)
{
#pragma unused(name,quantum,ignore5,ignore6,source,qcache_max,vmflag)
	blist_t bl;
	struct blist_hdl *p = _MALLOC(sizeof(struct blist_hdl), M_TEMP, M_WAITOK);
	
	ASSERT(quantum == 1);
	ASSERT(NULL == ignore5);
	ASSERT(NULL == ignore6);
	ASSERT(NULL == source);
	ASSERT(0 == qcache_max);
	ASSERT(vmflag & VMC_IDENTIFIER);
	
	size = MIN(128, size); /* Clamp to 128 initially, since the underlying data structure is pre-allocated */
	
	p->blist = bl = blist_create( size );
	blist_free(bl, 0, size);
	if (base) blist_alloc( bl, (daddr_t)(uintptr_t)base ); /* Chomp off initial ID(s) */
	
	return (vmem_t *)p;
}
 
void *
vmem_alloc(vmem_t *vmp, size_t size, int vmflag)
{
#pragma unused(vmflag)
	struct blist_hdl *q = (struct blist_hdl *)vmp;
	blist_t bl = q->blist;
	daddr_t p;
	
	p = blist_alloc(bl, (daddr_t)size);
	
	if ((daddr_t)-1 == p) {
		blist_resize(&bl, (bl->bl_blocks) << 1, 1);
		q->blist = bl;
		p = blist_alloc(bl, (daddr_t)size);
		if ((daddr_t)-1 == p) 
			panic("vmem_alloc: failure after blist_resize!");
	}
	
	return (void *)(uintptr_t)p;
}

void
vmem_free(vmem_t *vmp, void *vaddr, size_t size)
{
	struct blist_hdl *p = (struct blist_hdl *)vmp;
	
	blist_free( p->blist, (daddr_t)(uintptr_t)vaddr, (daddr_t)size );
}

void
vmem_destroy(vmem_t *vmp)
{
	struct blist_hdl *p = (struct blist_hdl *)vmp;
	
	blist_destroy( p->blist );
	_FREE( p, sizeof(struct blist_hdl) );
}

/*
 * Timing
 */

/*
 * dtrace_gethrestime() provides the "walltimestamp", a value that is anchored at 
 * January 1, 1970. Because it can be called from probe context, it must take no locks.
 */

hrtime_t
dtrace_gethrestime(void)
{
	clock_sec_t		secs;
	clock_nsec_t	nanosecs;
	uint64_t		secs64, ns64;
    
	clock_get_calendar_nanotime_nowait(&secs, &nanosecs);
	secs64 = (uint64_t)secs;
	ns64 = (uint64_t)nanosecs;

	ns64 = ns64 + (secs64 * 1000000000LL);
	return ns64;
}

/*
 * dtrace_gethrtime() provides high-resolution timestamps with machine-dependent origin.
 * Hence its primary use is to specify intervals.
 */

hrtime_t
dtrace_abs_to_nano(uint64_t elapsed)
{
	static mach_timebase_info_data_t    sTimebaseInfo = { 0, 0 };

	/*
	 * If this is the first time we've run, get the timebase.
	 * We can use denom == 0 to indicate that sTimebaseInfo is
	 * uninitialised because it makes no sense to have a zero
	 * denominator in a fraction.
	 */

	if ( sTimebaseInfo.denom == 0 ) {
		(void) clock_timebase_info(&sTimebaseInfo);
	}

	/*
	 * Convert to nanoseconds.
	 * return (elapsed * (uint64_t)sTimebaseInfo.numer)/(uint64_t)sTimebaseInfo.denom;
	 *
	 * Provided the final result is representable in 64 bits the following maneuver will
	 * deliver that result without intermediate overflow.
	 */
	if (sTimebaseInfo.denom == sTimebaseInfo.numer)
		return elapsed;
	else if (sTimebaseInfo.denom == 1)
		return elapsed * (uint64_t)sTimebaseInfo.numer;
	else {
		/* Decompose elapsed = eta32 * 2^32 + eps32: */
		uint64_t eta32 = elapsed >> 32;
		uint64_t eps32 = elapsed & 0x00000000ffffffffLL;

		uint32_t numer = sTimebaseInfo.numer, denom = sTimebaseInfo.denom;

		/* Form product of elapsed64 (decomposed) and numer: */
		uint64_t mu64 = numer * eta32;
		uint64_t lambda64 = numer * eps32;

		/* Divide the constituents by denom: */
		uint64_t q32 = mu64/denom;
		uint64_t r32 = mu64 - (q32 * denom); /* mu64 % denom */

		return (q32 << 32) + ((r32 << 32) + lambda64)/denom;
	}
}

hrtime_t
dtrace_gethrtime(void)
{
    static uint64_t        start = 0;
    
	if (start == 0)
		start = mach_absolute_time();
		
    return dtrace_abs_to_nano(mach_absolute_time() - start);
}

/*
 * Atomicity and synchronization
 */
uint32_t
dtrace_cas32(uint32_t *target, uint32_t cmp, uint32_t new)
{
    if (OSCompareAndSwap( (UInt32)cmp, (UInt32)new, (volatile UInt32 *)target ))
		return cmp;
	else
		return ~cmp; /* Must return something *other* than cmp */
}

void *
dtrace_casptr(void *target, void *cmp, void *new)
{
	if (OSCompareAndSwapPtr( cmp, new, (void**)target ))
		return cmp;
	else
		return (void *)(~(uintptr_t)cmp); /* Must return something *other* than cmp */
}

/*
 * Interrupt manipulation
 */
dtrace_icookie_t
dtrace_interrupt_disable(void)
{
	return (dtrace_icookie_t)ml_set_interrupts_enabled(FALSE);
}

void
dtrace_interrupt_enable(dtrace_icookie_t reenable)
{
	(void)ml_set_interrupts_enabled((boolean_t)reenable);
}

/*
 * MP coordination
 */
static void
dtrace_sync_func(void) {}

/*
 * dtrace_sync() is not called from probe context.
 */
void
dtrace_sync(void)
{
	dtrace_xcall(DTRACE_CPUALL, (dtrace_xcall_t)dtrace_sync_func, NULL);
}

/*
 * The dtrace_copyin/out/instr and dtrace_fuword* routines can be called from probe context.
 */

extern kern_return_t dtrace_copyio_preflight(addr64_t);
extern kern_return_t dtrace_copyio_postflight(addr64_t);
 
static int
dtrace_copycheck(user_addr_t uaddr, uintptr_t kaddr, size_t size)
{
#pragma unused(kaddr)

	vm_offset_t recover = dtrace_set_thread_recover( current_thread(), 0 ); /* Snare any extant recovery point. */
	dtrace_set_thread_recover( current_thread(), recover ); /* Put it back. We *must not* re-enter and overwrite. */

	ASSERT(kaddr + size >= kaddr);

	if (	uaddr + size < uaddr ||		/* Avoid address wrap. */
		KERN_FAILURE == dtrace_copyio_preflight(uaddr)) /* Machine specific setup/constraints. */
	{
		DTRACE_CPUFLAG_SET(CPU_DTRACE_BADADDR);
		cpu_core[CPU->cpu_id].cpuc_dtrace_illval = uaddr;
		return (0);
	}
	return (1);
}

void
dtrace_copyin(user_addr_t src, uintptr_t dst, size_t len, volatile uint16_t *flags)
{
#pragma unused(flags)
    
	if (dtrace_copycheck( src, dst, len )) {
		if (copyin((const user_addr_t)src, (char *)dst, (vm_size_t)len)) {
			DTRACE_CPUFLAG_SET(CPU_DTRACE_BADADDR);
			cpu_core[CPU->cpu_id].cpuc_dtrace_illval = src;
		}
		dtrace_copyio_postflight(src);
	}
}

void
dtrace_copyinstr(user_addr_t src, uintptr_t dst, size_t len, volatile uint16_t *flags)
{
#pragma unused(flags)
    
	size_t actual;
	
	if (dtrace_copycheck( src, dst, len )) {
		/*  copyin as many as 'len' bytes. */
		int error = copyinstr((const user_addr_t)src, (char *)dst, (vm_size_t)len, &actual);

		/*
		 * ENAMETOOLONG is returned when 'len' bytes have been copied in but the NUL terminator was
		 * not encountered. That does not require raising CPU_DTRACE_BADADDR, and we press on.
		 * Note that we do *not* stuff a NUL terminator when returning ENAMETOOLONG, that's left
		 * to the caller.
		 */
		if (error && error != ENAMETOOLONG) {
			DTRACE_CPUFLAG_SET(CPU_DTRACE_BADADDR);
			cpu_core[CPU->cpu_id].cpuc_dtrace_illval = src;
		}
		dtrace_copyio_postflight(src);
	}
}

void
dtrace_copyout(uintptr_t src, user_addr_t dst, size_t len, volatile uint16_t *flags)
{
#pragma unused(flags)
    
	if (dtrace_copycheck( dst, src, len )) {
		if (copyout((const void *)src, dst, (vm_size_t)len)) {
			DTRACE_CPUFLAG_SET(CPU_DTRACE_BADADDR);
			cpu_core[CPU->cpu_id].cpuc_dtrace_illval = dst;
		}
		dtrace_copyio_postflight(dst);
	}
}

void
dtrace_copyoutstr(uintptr_t src, user_addr_t dst, size_t len, volatile uint16_t *flags)
{
#pragma unused(flags)
    
	size_t actual;

	if (dtrace_copycheck( dst, src, len )) {

		/*
		 * ENAMETOOLONG is returned when 'len' bytes have been copied out but the NUL terminator was
		 * not encountered. We raise CPU_DTRACE_BADADDR in that case.
		 * Note that we do *not* stuff a NUL terminator when returning ENAMETOOLONG, that's left
		 * to the caller.
		 */
		if (copyoutstr((const void *)src, dst, (size_t)len, &actual)) {
			DTRACE_CPUFLAG_SET(CPU_DTRACE_BADADDR);
			cpu_core[CPU->cpu_id].cpuc_dtrace_illval = dst;
		}
		dtrace_copyio_postflight(dst);
	}
}

uint8_t
dtrace_fuword8(user_addr_t uaddr)
{
	uint8_t ret = 0;

	DTRACE_CPUFLAG_SET(CPU_DTRACE_NOFAULT);
	if (dtrace_copycheck( uaddr, (uintptr_t)&ret, sizeof(ret))) {
		if (copyin((const user_addr_t)uaddr, (char *)&ret, sizeof(ret))) {
			DTRACE_CPUFLAG_SET(CPU_DTRACE_BADADDR);
			cpu_core[CPU->cpu_id].cpuc_dtrace_illval = uaddr;
		}
		dtrace_copyio_postflight(uaddr);
	}
	DTRACE_CPUFLAG_CLEAR(CPU_DTRACE_NOFAULT);

	return(ret);
}

uint16_t
dtrace_fuword16(user_addr_t uaddr)
{
	uint16_t ret = 0;

	DTRACE_CPUFLAG_SET(CPU_DTRACE_NOFAULT);
	if (dtrace_copycheck( uaddr, (uintptr_t)&ret, sizeof(ret))) {
		if (copyin((const user_addr_t)uaddr, (char *)&ret, sizeof(ret))) {
			DTRACE_CPUFLAG_SET(CPU_DTRACE_BADADDR);
			cpu_core[CPU->cpu_id].cpuc_dtrace_illval = uaddr;
		}
		dtrace_copyio_postflight(uaddr);
	}
	DTRACE_CPUFLAG_CLEAR(CPU_DTRACE_NOFAULT);

	return(ret);
}

uint32_t
dtrace_fuword32(user_addr_t uaddr)
{
	uint32_t ret = 0;

	DTRACE_CPUFLAG_SET(CPU_DTRACE_NOFAULT);
	if (dtrace_copycheck( uaddr, (uintptr_t)&ret, sizeof(ret))) {
		if (copyin((const user_addr_t)uaddr, (char *)&ret, sizeof(ret))) {
			DTRACE_CPUFLAG_SET(CPU_DTRACE_BADADDR);
			cpu_core[CPU->cpu_id].cpuc_dtrace_illval = uaddr;
		}
		dtrace_copyio_postflight(uaddr);
	}
	DTRACE_CPUFLAG_CLEAR(CPU_DTRACE_NOFAULT);

	return(ret);
}

uint64_t
dtrace_fuword64(user_addr_t uaddr)
{
	uint64_t ret = 0;

	DTRACE_CPUFLAG_SET(CPU_DTRACE_NOFAULT);
	if (dtrace_copycheck( uaddr, (uintptr_t)&ret, sizeof(ret))) {
		if (copyin((const user_addr_t)uaddr, (char *)&ret, sizeof(ret))) {
			DTRACE_CPUFLAG_SET(CPU_DTRACE_BADADDR);
			cpu_core[CPU->cpu_id].cpuc_dtrace_illval = uaddr;
		}
		dtrace_copyio_postflight(uaddr);
	}
	DTRACE_CPUFLAG_CLEAR(CPU_DTRACE_NOFAULT);

	return(ret);
}

/*
 * Emulation of Solaris fuword / suword
 * Called from the fasttrap provider, so the use of copyin/out requires fewer safegaurds.
 */

int
fuword8(user_addr_t uaddr, uint8_t *value)
{
	if (copyin((const user_addr_t)uaddr, (char *)value, sizeof(uint8_t)) != 0) {
		return -1;
	}

	return 0;
}

int
fuword16(user_addr_t uaddr, uint16_t *value)
{
	if (copyin((const user_addr_t)uaddr, (char *)value, sizeof(uint16_t)) != 0) {
		return -1;
	}

	return 0;
}

int
fuword32(user_addr_t uaddr, uint32_t *value)
{
	if (copyin((const user_addr_t)uaddr, (char *)value, sizeof(uint32_t)) != 0) {
		return -1;
	}

	return 0;
}

int
fuword64(user_addr_t uaddr, uint64_t *value)
{
	if (copyin((const user_addr_t)uaddr, (char *)value, sizeof(uint64_t)) != 0) {
		return -1;
	}

	return 0;
}

void
fuword8_noerr(user_addr_t uaddr, uint8_t *value)
{
	if (copyin((const user_addr_t)uaddr, (char *)value, sizeof(uint8_t))) {
		*value = 0;
	}
}

void
fuword16_noerr(user_addr_t uaddr, uint16_t *value)
{
	if (copyin((const user_addr_t)uaddr, (char *)value, sizeof(uint16_t))) {
		*value = 0;
	}
}

void
fuword32_noerr(user_addr_t uaddr, uint32_t *value)
{
	if (copyin((const user_addr_t)uaddr, (char *)value, sizeof(uint32_t))) {
		*value = 0;
	}
}

void
fuword64_noerr(user_addr_t uaddr, uint64_t *value)
{
	if (copyin((const user_addr_t)uaddr, (char *)value, sizeof(uint64_t))) {
		*value = 0;
	}
}

int
suword64(user_addr_t addr, uint64_t value)
{
	if (copyout((const void *)&value, addr, sizeof(value)) != 0) {
		return -1;
	}

	return 0;
}

int
suword32(user_addr_t addr, uint32_t value)
{
	if (copyout((const void *)&value, addr, sizeof(value)) != 0) {
		return -1;
	}

	return 0;
}

int
suword16(user_addr_t addr, uint16_t value)
{
	if (copyout((const void *)&value, addr, sizeof(value)) != 0) {
		return -1;
	}

	return 0;
}

int
suword8(user_addr_t addr, uint8_t value)
{
	if (copyout((const void *)&value, addr, sizeof(value)) != 0) {
		return -1;
	}

	return 0;
}


/*
 * Miscellaneous
 */
extern boolean_t dtrace_tally_fault(user_addr_t);

boolean_t
dtrace_tally_fault(user_addr_t uaddr)
{
	DTRACE_CPUFLAG_SET(CPU_DTRACE_BADADDR);
	cpu_core[CPU->cpu_id].cpuc_dtrace_illval = uaddr;
	return( DTRACE_CPUFLAG_ISSET(CPU_DTRACE_NOFAULT) ? TRUE : FALSE );
}

#define TOTTY   0x02
extern int prf(const char *, va_list, int, struct tty *); /* bsd/kern/subr_prf.h */

int
vuprintf(const char *format, va_list ap)
{
	return prf(format, ap, TOTTY, NULL);
}

/* Not called from probe context */
void cmn_err( int level, const char *format, ... )
{
#pragma unused(level)
	va_list alist;

	va_start(alist, format);
	vuprintf(format, alist);
	va_end(alist);
	uprintf("\n");
}

/*
 * History:
 *  2002-01-24 	gvdl	Initial implementation of strstr
 */

__private_extern__ const char *
strstr(const char *in, const char *str)
{
    char c;
    size_t len;

    c = *str++;
    if (!c)
        return (const char *) in;	// Trivial empty string case

    len = strlen(str);
    do {
        char sc;

        do {
            sc = *in++;
            if (!sc)
                return (char *) 0;
        } while (sc != c);
    } while (strncmp(in, str, len) != 0);

    return (const char *) (in - 1);
}

/*
 * Runtime and ABI
 */
uintptr_t
dtrace_caller(int ignore)
{
#pragma unused(ignore)
	return -1; /* Just as in Solaris dtrace_asm.s */
}

int
dtrace_getstackdepth(int aframes)
{
	struct frame *fp = (struct frame *)__builtin_frame_address(0);
	struct frame *nextfp, *minfp, *stacktop;
	int depth = 0;
	int on_intr;

	if ((on_intr = CPU_ON_INTR(CPU)) != 0)
		stacktop = (struct frame *)dtrace_get_cpu_int_stack_top();
	else
		stacktop = (struct frame *)(dtrace_get_kernel_stack(current_thread()) + kernel_stack_size);

	minfp = fp;

	aframes++;

	for (;;) {
		depth++;

		nextfp = *(struct frame **)fp;

		if (nextfp <= minfp || nextfp >= stacktop) {
			if (on_intr) {
				/*
				 * Hop from interrupt stack to thread stack.
				 */
                                vm_offset_t kstack_base = dtrace_get_kernel_stack(current_thread());

                                minfp = (struct frame *)kstack_base;
                                stacktop = (struct frame *)(kstack_base + kernel_stack_size);

				on_intr = 0;
				continue;
			}
			break;
		}

		fp = nextfp;
		minfp = fp;
	}

	if (depth <= aframes)
		return (0);

	return (depth - aframes);
}

/*
 * Unconsidered
 */
void
dtrace_vtime_enable(void) {}

void
dtrace_vtime_disable(void) {}

#else /* else ! CONFIG_DTRACE */

#include <sys/types.h>
#include <mach/vm_types.h>
#include <mach/kmod.h>

/*
 * This exists to prevent build errors when dtrace is unconfigured.
 */

kern_return_t _dtrace_register_anon_DOF(char *, unsigned char *, uint32_t);

kern_return_t _dtrace_register_anon_DOF(char *arg1, unsigned char *arg2, uint32_t arg3) {
#pragma unused(arg1, arg2, arg3)

        return KERN_FAILURE;
}

#endif /* CONFIG_DTRACE */
