/*
 * Copyright (c) 2000-2006 Apple Computer, Inc. All rights reserved.
 *
 * @Apple_LICENSE_HEADER_START@
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
 * @APPLE_OSREFERENCE_LICENSE_HEADER_END@
 */

#include <machine/spl.h>

#include <sys/errno.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/proc_internal.h>
#include <sys/vm.h>
#include <sys/sysctl.h>
#include <sys/kdebug.h>
#include <sys/sysproto.h>

#define HZ      100
#include <mach/clock_types.h>
#include <mach/mach_types.h>
#include <mach/mach_time.h>
#include <machine/machine_routines.h>

#if defined(__i386__) || defined(__x86_64__)
#include <i386/rtclock.h>
#endif
#include <kern/thread.h>
#include <kern/task.h>
#include <kern/debug.h>
#include <vm/vm_kern.h>
#include <sys/lock.h>

#include <sys/malloc.h>
#include <sys/mcache.h>
#include <sys/kauth.h>

#include <sys/vnode.h>
#include <sys/vnode_internal.h>
#include <sys/fcntl.h>

#include <mach/mach_host.h>		/* for host_info() */
#include <libkern/OSAtomic.h>

/* XXX should have prototypes, but Mach does not provide one */
void task_act_iterate_wth_args(task_t, void(*)(thread_t, void *), void *);
int cpu_number(void);	/* XXX <machine/...> include path broken */

/* XXX should probably be static, but it's debugging code... */
int kdbg_read(user_addr_t, size_t *, vnode_t, vfs_context_t);
void kdbg_control_chud(int, void *);
int kdbg_control(int *, u_int, user_addr_t, size_t *);
int kdbg_getentropy (user_addr_t, size_t *, int);
int kdbg_readmap(user_addr_t, size_t *, vnode_t, vfs_context_t);
int kdbg_getreg(kd_regtype *);
int kdbg_setreg(kd_regtype *);
int kdbg_setrtcdec(kd_regtype *);
int kdbg_setpidex(kd_regtype *);
int kdbg_setpid(kd_regtype *);
void kdbg_mapinit(void);
int kdbg_reinit(void);
int kdbg_bootstrap(void);

static int create_buffers(void);
static void delete_buffers(void);

extern void IOSleep(int);

#ifdef ppc
extern uint32_t maxDec;
#endif

/* trace enable status */
unsigned int kdebug_enable = 0;

/* track timestamps for security server's entropy needs */
uint64_t * 		  kd_entropy_buffer = 0;
unsigned int      kd_entropy_bufsize = 0;
unsigned int      kd_entropy_count  = 0;
unsigned int      kd_entropy_indx   = 0;
vm_offset_t       kd_entropy_buftomem = 0;


#define SLOW_NOLOG	0x01
#define SLOW_CHECKS	0x02
#define SLOW_ENTROPY	0x04

unsigned int kdebug_slowcheck = SLOW_NOLOG;

unsigned int kd_cpus;

#define EVENTS_PER_STORAGE_UNIT		2048
#define MIN_STORAGE_UNITS_PER_CPU	4

struct kd_storage {
	struct	kd_storage *kds_next;
	kd_buf	*kds_bufptr;
	kd_buf	*kds_buflast;
	kd_buf	*kds_readlast;

	kd_buf	kds_records[EVENTS_PER_STORAGE_UNIT];
};

#define MAX_BUFFER_SIZE			(1024 * 1024 * 128)
#define N_STORAGE_UNITS_PER_BUFFER	(MAX_BUFFER_SIZE / sizeof(struct kd_storage))


struct kd_storage_buffers {
	struct	kd_storage	*kdsb_addr;
	uint32_t		kdsb_size;
};


struct kd_storage *kds_free_list = NULL;
struct kd_storage_buffers *kd_bufs = NULL;
int	n_storage_units = 0;
int	n_storage_buffers = 0;

struct kd_bufinfo {
	struct  kd_storage *kd_list_head;
	struct  kd_storage *kd_list_tail;
	struct	kd_storage *kd_active;
        uint64_t kd_prev_timebase;
} __attribute__(( aligned(CPU_CACHE_SIZE) ));

struct kd_bufinfo *kdbip = NULL;

#define KDCOPYBUF_COUNT	2048
#define KDCOPYBUF_SIZE	(KDCOPYBUF_COUNT * sizeof(kd_buf))
kd_buf *kdcopybuf = NULL;


unsigned int nkdbufs = 8192;
unsigned int kdebug_flags = 0;
unsigned int kdlog_beg=0;
unsigned int kdlog_end=0;
unsigned int kdlog_value1=0;
unsigned int kdlog_value2=0;
unsigned int kdlog_value3=0;
unsigned int kdlog_value4=0;

static lck_spin_t * kds_spin_lock;
static lck_mtx_t  * kd_trace_mtx_sysctl;
static lck_grp_t  * kd_trace_mtx_sysctl_grp;
static lck_attr_t * kd_trace_mtx_sysctl_attr;
static lck_grp_attr_t   *kd_trace_mtx_sysctl_grp_attr;

static lck_grp_t       *stackshot_subsys_lck_grp;
static lck_grp_attr_t  *stackshot_subsys_lck_grp_attr;
static lck_attr_t      *stackshot_subsys_lck_attr;
static lck_mtx_t        stackshot_subsys_mutex;

void *stackshot_snapbuf = NULL;

int
stack_snapshot2(pid_t pid, user_addr_t tracebuf, uint32_t tracebuf_size, uint32_t flags, uint32_t dispatch_offset, int32_t *retval);

extern void
kdp_snapshot_preflight(int pid, void  *tracebuf, uint32_t tracebuf_size, uint32_t flags, uint32_t dispatch_offset);

extern int
kdp_stack_snapshot_geterror(void);
extern unsigned int
kdp_stack_snapshot_bytes_traced(void);

kd_threadmap *kd_mapptr = 0;
unsigned int kd_mapsize = 0;
unsigned int kd_mapcount = 0;
vm_offset_t kd_maptomem = 0;

off_t	RAW_file_offset = 0;

pid_t global_state_pid = -1;       /* Used to control exclusive use of kd_buffer */

#define DBG_FUNC_MASK 0xfffffffc

/* task to string structure */
struct tts
{
  task_t    task;            /* from procs task */
  pid_t     pid;             /* from procs p_pid  */
  char      task_comm[20];   /* from procs p_comm */
};

typedef struct tts tts_t;

struct krt
{
  kd_threadmap *map;    /* pointer to the map buffer */
  int count;
  int maxcount;
  struct tts *atts;
};

typedef struct krt krt_t;

/* This is for the CHUD toolkit call */
typedef void (*kd_chudhook_fn) (uint32_t debugid, uintptr_t arg1,
				uintptr_t arg2, uintptr_t arg3,
				uintptr_t arg4, uintptr_t arg5);

kd_chudhook_fn kdebug_chudhook = 0;   /* pointer to CHUD toolkit function */

__private_extern__ void stackshot_lock_init( void ) __attribute__((section("__TEXT, initcode")));

/* Support syscall SYS_kdebug_trace */
int
kdebug_trace(__unused struct proc *p, struct kdebug_trace_args *uap, __unused int32_t *retval)
{
    if ( (kdebug_enable == 0) )
        return(EINVAL);
  
    kernel_debug(uap->code, uap->arg1, uap->arg2, uap->arg3, uap->arg4, 0);
    return(0);
}


static int
create_buffers(void)
{
        int	i;
	int	p_buffer_size;
	int	f_buffer_size;
	int	f_buffers;
	int	error = 0;

	if (nkdbufs < (kd_cpus * EVENTS_PER_STORAGE_UNIT * MIN_STORAGE_UNITS_PER_CPU))
		n_storage_units = kd_cpus * MIN_STORAGE_UNITS_PER_CPU;
	else
		n_storage_units = nkdbufs / EVENTS_PER_STORAGE_UNIT;

	nkdbufs = n_storage_units * EVENTS_PER_STORAGE_UNIT;

	f_buffers = n_storage_units / N_STORAGE_UNITS_PER_BUFFER;
	n_storage_buffers = f_buffers;

	f_buffer_size = N_STORAGE_UNITS_PER_BUFFER * sizeof(struct kd_storage);
	p_buffer_size = (n_storage_units % N_STORAGE_UNITS_PER_BUFFER) * sizeof(struct kd_storage);

	if (p_buffer_size)
		n_storage_buffers++;

	kd_bufs = NULL;

	if (kdcopybuf == 0) {
	        if (kmem_alloc(kernel_map, (vm_offset_t *)&kdcopybuf, (vm_size_t)KDCOPYBUF_SIZE) != KERN_SUCCESS) {
			error = ENOSPC;
			goto out;
		}
	}
	if (kmem_alloc(kernel_map, (vm_offset_t *)&kd_bufs, (vm_size_t)(n_storage_buffers * sizeof(struct kd_storage_buffers))) != KERN_SUCCESS) {
		error = ENOSPC;
		goto out;
	}
	bzero(kd_bufs, n_storage_buffers * sizeof(struct kd_storage_buffers));

	for (i = 0; i < f_buffers; i++) {
		if (kmem_alloc(kernel_map, (vm_offset_t *)&kd_bufs[i].kdsb_addr, (vm_size_t)f_buffer_size) != KERN_SUCCESS) {
			error = ENOSPC;
			goto out;
		}
		kd_bufs[i].kdsb_size = f_buffer_size;
	}
	if (p_buffer_size) {
		if (kmem_alloc(kernel_map, (vm_offset_t *)&kd_bufs[i].kdsb_addr, (vm_size_t)p_buffer_size) != KERN_SUCCESS) {
			error = ENOSPC;
			goto out;
		}
		kd_bufs[i].kdsb_size = p_buffer_size;
	}

	for (i = 0; i < n_storage_buffers; i++) {
		struct kd_storage *kds;
		int	n_elements;
		int	n;

		n_elements = kd_bufs[i].kdsb_size / sizeof(struct kd_storage);
		kds = kd_bufs[i].kdsb_addr;

		for (n = 0; n < n_elements; n++) {
			kds[n].kds_next = kds_free_list;
			kds_free_list = &kds[n];

			kds[n].kds_buflast = &kds[n].kds_records[EVENTS_PER_STORAGE_UNIT];
		}
	}
	bzero((char *)kdbip, sizeof(struct kd_bufinfo) * kd_cpus);

	kdebug_flags |= KDBG_BUFINIT;
out:
	if (error)
		delete_buffers();

	return(error);
}


static void
delete_buffers(void)
{
	int 	i;
	
	if (kd_bufs) {
		for (i = 0; i < n_storage_buffers; i++) {
			if (kd_bufs[i].kdsb_addr)
				kmem_free(kernel_map, (vm_offset_t)kd_bufs[i].kdsb_addr, (vm_size_t)kd_bufs[i].kdsb_size);
		}
		kmem_free(kernel_map, (vm_offset_t)kd_bufs, (vm_size_t)(n_storage_buffers * sizeof(struct kd_storage_buffers)));

		kd_bufs = NULL;
		n_storage_buffers = 0;
	}
	if (kdcopybuf) {
		kmem_free(kernel_map, (vm_offset_t)kdcopybuf, KDCOPYBUF_SIZE);

		kdcopybuf = NULL;
	}
	kds_free_list = NULL;

	kdebug_flags &= ~KDBG_BUFINIT;
}


static void
release_storage_unit(struct kd_bufinfo *kdbp, struct kd_storage *kdsp)
{

	int s = 0;
	s = ml_set_interrupts_enabled(FALSE);
	lck_spin_lock(kds_spin_lock);

	if (kdsp == kdbp->kd_list_head) {
		/*
		 * its possible for the storage unit pointed to
		 * by kdsp to have already been stolen... so
		 * check to see if its still the head of the list
		 * now that we're behind the lock that protects 
		 * adding and removing from the queue...
		 * since we only ever release and steal units from
		 * that position, if its no longer the head
		 * we having nothing to do in this context
		 */
		kdbp->kd_list_head = kdsp->kds_next;
	
		kdsp->kds_next = kds_free_list;
		kds_free_list = kdsp;
	}
	lck_spin_unlock(kds_spin_lock);
	ml_set_interrupts_enabled(s);
}


/*
 * Interrupts are disabled when we enter this routine.
 */
static struct kd_storage *
allocate_storage_unit(struct kd_bufinfo *kdbp)
{
	struct	kd_storage *kdsp;
	struct  kd_bufinfo *kdbp_vict, *kdbp_try;
	uint64_t	oldest_ts, ts;
		
	lck_spin_lock(kds_spin_lock);

	if ((kdsp = kds_free_list))
		kds_free_list = kdsp->kds_next;
	else {
		if (kdebug_flags & KDBG_NOWRAP) {
                        kdebug_slowcheck |= SLOW_NOLOG;
			goto out;
		}
		kdbp_vict = NULL;
		oldest_ts = (uint64_t)-1;

		for (kdbp_try = &kdbip[0]; kdbp_try < &kdbip[kd_cpus]; kdbp_try++) {

			if ((kdsp = kdbp_try->kd_list_head) == NULL) {
				/*
				 * no storage unit to steal
				 */
				continue;
			}
			if (kdsp == kdbp_try->kd_active) {
				/*
				 * make sure we don't steal the storage unit
				 * being actively recorded to...  this state
				 * also implies that this is the only unit assigned
				 * to this CPU, so we can immediately move on 
				 */
				continue;
			}
			ts = kdbg_get_timestamp(&(kdbp_try->kd_list_head->kds_records[0]));

			if (ts < oldest_ts) {
				/*
				 * when 'wrapping', we want to steal the
				 * storage unit that has the 'earliest' time
				 * associated with it (first event time)
				 */
				oldest_ts = ts;
				kdbp_vict = kdbp_try;
			}
		}
#if 1
		if (kdbp_vict == NULL) {
			kdebug_enable = 0;

			panic("allocate_storage_unit: no storage units available\n");
		}
#endif
		kdsp = kdbp_vict->kd_list_head;

		kdbp_vict->kd_list_head = kdsp->kds_next;

		kdebug_flags |= KDBG_WRAPPED;
	}
	kdsp->kds_next     = NULL;
	kdsp->kds_bufptr   = &kdsp->kds_records[0];
	kdsp->kds_readlast = kdsp->kds_bufptr;

	if (kdbp->kd_list_head == NULL)
		kdbp->kd_list_head = kdsp;
	else
		kdbp->kd_list_tail->kds_next = kdsp;
	kdbp->kd_list_tail = kdsp;
out:
	lck_spin_unlock(kds_spin_lock);

	return (kdsp);
}



static void
kernel_debug_internal(
	uint32_t	debugid,
	uintptr_t	arg1,
	uintptr_t	arg2,
	uintptr_t	arg3,
	uintptr_t	arg4,
	uintptr_t	arg5,
	int		entropy_flag)
{
	struct proc 	*curproc;
	uint64_t 	now;
	int		s;
	kd_buf		*kd;
	int		cpu;
	struct kd_bufinfo *kdbp;
	struct kd_storage *kdsp;

	s = ml_set_interrupts_enabled(FALSE);

	now = mach_absolute_time() & KDBG_TIMESTAMP_MASK;
	cpu = cpu_number();

	if (kdebug_enable & KDEBUG_ENABLE_CHUD) {
		if (kdebug_chudhook)
			kdebug_chudhook(debugid, arg1, arg2, arg3, arg4, arg5);

		if ( !(kdebug_enable & (KDEBUG_ENABLE_ENTROPY | KDEBUG_ENABLE_TRACE)))
			goto out;
	}
	if (kdebug_slowcheck == 0)
		goto record_trace;

	if (entropy_flag && (kdebug_enable & KDEBUG_ENABLE_ENTROPY)) {
		if (kd_entropy_indx < kd_entropy_count)	{
			kd_entropy_buffer [ kd_entropy_indx] = mach_absolute_time();
			kd_entropy_indx++;
		}
	    
		if (kd_entropy_indx == kd_entropy_count) {
			/*
			 * Disable entropy collection
			 */
			kdebug_enable &= ~KDEBUG_ENABLE_ENTROPY;
			kdebug_slowcheck &= ~SLOW_ENTROPY;
		}
	}
	if ( (kdebug_slowcheck & SLOW_NOLOG) )
		goto out;
	
	if (kdebug_flags & KDBG_PIDCHECK) {
		/*
		 * If kdebug flag is not set for current proc, return
		 */
		curproc = current_proc();

		if ((curproc && !(curproc->p_kdebug)) &&
		    ((debugid & 0xffff0000) != (MACHDBG_CODE(DBG_MACH_SCHED, 0) | DBG_FUNC_NONE)))
			goto out;
	}
	else if (kdebug_flags & KDBG_PIDEXCLUDE) {
		/*
		 * If kdebug flag is set for current proc, return
		 */
		curproc = current_proc();

		if ((curproc && curproc->p_kdebug) &&
		    ((debugid & 0xffff0000) != (MACHDBG_CODE(DBG_MACH_SCHED, 0) | DBG_FUNC_NONE)))
			goto out;
	}
	if (kdebug_flags & KDBG_RANGECHECK) {
		if ((debugid < kdlog_beg)
		    || ((debugid >= kdlog_end) && (debugid >> 24 != DBG_TRACE)))
			goto out;
	}
	else if (kdebug_flags & KDBG_VALCHECK) {
		if ((debugid & DBG_FUNC_MASK) != kdlog_value1 &&
		    (debugid & DBG_FUNC_MASK) != kdlog_value2 &&
		    (debugid & DBG_FUNC_MASK) != kdlog_value3 &&
		    (debugid & DBG_FUNC_MASK) != kdlog_value4 &&
		    (debugid >> 24 != DBG_TRACE))
			goto out;
	}

record_trace:
	kdbp = &kdbip[cpu];

	if ((kdsp = kdbp->kd_active) == NULL) {
		if ((kdsp = allocate_storage_unit(kdbp)) == NULL) {
			/*
			 * this can only happen if wrapping
			 * has been disabled
			 */
			goto out;
		}
		kdbp->kd_active = kdsp;
	}
	kd = kdsp->kds_bufptr;

	kd->debugid = debugid;
	kd->arg1 = arg1;
	kd->arg2 = arg2;
	kd->arg3 = arg3;
	kd->arg4 = arg4;
	kd->arg5 = arg5;
	          
	kdbg_set_timestamp_and_cpu(kd, now, cpu);

	kdsp->kds_bufptr++;

	if (kdsp->kds_bufptr >= kdsp->kds_buflast)
	  	kdbp->kd_active = NULL;
out:
	ml_set_interrupts_enabled(s);
}

void
kernel_debug(
	uint32_t	debugid,
	uintptr_t	arg1,
	uintptr_t	arg2,
	uintptr_t	arg3,
	uintptr_t	arg4,
	__unused uintptr_t arg5)
{
	kernel_debug_internal(debugid, arg1, arg2, arg3, arg4, (uintptr_t)thread_tid(current_thread()), 1);
}

void
kernel_debug1(
	uint32_t	debugid,
	uintptr_t	arg1,
	uintptr_t	arg2,
	uintptr_t	arg3,
	uintptr_t	arg4,
	uintptr_t	arg5)
{
	kernel_debug_internal(debugid, arg1, arg2, arg3, arg4, arg5, 0);
}

static void
kdbg_lock_init(void)
{
	host_basic_info_data_t hinfo;
	mach_msg_type_number_t count = HOST_BASIC_INFO_COUNT;

	if (kdebug_flags & KDBG_LOCKINIT)
		return;

	/* get the number of cpus and cache it */
#define BSD_HOST 1
	host_info((host_t)BSD_HOST, HOST_BASIC_INFO, (host_info_t)&hinfo, &count);
	kd_cpus = hinfo.logical_cpu_max;

	if (kmem_alloc(kernel_map, (vm_offset_t *)&kdbip,
		       sizeof(struct kd_bufinfo) * kd_cpus) != KERN_SUCCESS)
	        return;

	/*
	 * allocate lock group attribute and group
	 */
	kd_trace_mtx_sysctl_grp_attr = lck_grp_attr_alloc_init();
	kd_trace_mtx_sysctl_grp = lck_grp_alloc_init("kdebug", kd_trace_mtx_sysctl_grp_attr);
		
	/*
	 * allocate the lock attribute
	 */
	kd_trace_mtx_sysctl_attr = lck_attr_alloc_init();


	/*
	 * allocate and initialize spin lock and mutex
	 */
	kd_trace_mtx_sysctl = lck_mtx_alloc_init(kd_trace_mtx_sysctl_grp, kd_trace_mtx_sysctl_attr);
	kds_spin_lock = lck_spin_alloc_init(kd_trace_mtx_sysctl_grp, kd_trace_mtx_sysctl_attr);

	kdebug_flags |= KDBG_LOCKINIT;
}


int
kdbg_bootstrap(void)
{
        kdebug_flags &= ~KDBG_WRAPPED;

	return (create_buffers());
}

int
kdbg_reinit(void)
{
	int ret = 0;

	/*
	 * Disable trace collecting
	 * First make sure we're not in
	 * the middle of cutting a trace
	 */
	kdebug_enable &= ~KDEBUG_ENABLE_TRACE;
	kdebug_slowcheck |= SLOW_NOLOG;

	/*
	 * make sure the SLOW_NOLOG is seen
	 * by everyone that might be trying
	 * to cut a trace..
	 */
	IOSleep(100);

	delete_buffers();

	if ((kdebug_flags & KDBG_MAPINIT) && kd_mapsize && kd_mapptr) {
		kmem_free(kernel_map, (vm_offset_t)kd_mapptr, kd_mapsize);
		kdebug_flags &= ~KDBG_MAPINIT;
		kd_mapsize = 0;
		kd_mapptr = (kd_threadmap *) 0;
		kd_mapcount = 0;
	}  
	ret = kdbg_bootstrap();

	return(ret);
}

void
kdbg_trace_data(struct proc *proc, long *arg_pid)
{
	if (!proc)
		*arg_pid = 0;
	else
		*arg_pid = proc->p_pid;
}


void
kdbg_trace_string(struct proc *proc, long *arg1, long *arg2, long *arg3, long *arg4)
{
	char *dbg_nameptr; 
	int dbg_namelen;
	long dbg_parms[4];

	if (!proc) {
		*arg1 = 0;
		*arg2 = 0;
		*arg3 = 0;
		*arg4 = 0;
		return;
	}
	/*
	 * Collect the pathname for tracing
	 */
	dbg_nameptr = proc->p_comm;
	dbg_namelen = (int)strlen(proc->p_comm);
	dbg_parms[0]=0L;
	dbg_parms[1]=0L;
	dbg_parms[2]=0L;
	dbg_parms[3]=0L;
  
	if(dbg_namelen > (int)sizeof(dbg_parms))
		dbg_namelen = (int)sizeof(dbg_parms);
    
	strncpy((char *)dbg_parms, dbg_nameptr, dbg_namelen);

	*arg1=dbg_parms[0];
	*arg2=dbg_parms[1];
	*arg3=dbg_parms[2];
	*arg4=dbg_parms[3];
}

static void
kdbg_resolve_map(thread_t th_act, void *opaque)
{
	kd_threadmap *mapptr;
	krt_t *t = (krt_t *)opaque;

	if (t->count < t->maxcount) {
		mapptr = &t->map[t->count];
		mapptr->thread  = (uintptr_t)thread_tid(th_act);

		(void) strlcpy (mapptr->command, t->atts->task_comm,
				sizeof(t->atts->task_comm));
		/*
		 * Some kernel threads have no associated pid.
		 * We still need to mark the entry as valid.
		 */
		if (t->atts->pid)
			mapptr->valid = t->atts->pid;
		else
			mapptr->valid = 1;

		t->count++;
	}
}

void
kdbg_mapinit(void)
{
	struct proc	*p;
	struct krt	akrt;
	int		tts_count;    /* number of task-to-string structures */
	struct tts	*tts_mapptr;
	unsigned int	tts_mapsize = 0;
	vm_offset_t	tts_maptomem=0;
	int		i;

        if (kdebug_flags & KDBG_MAPINIT)
		return;

	/*
	 * need to use PROC_SCANPROCLIST with proc_iterate
	 */
	proc_list_lock();

	/*
	 * Calculate the sizes of map buffers
	 */
	for (p = allproc.lh_first, kd_mapcount=0, tts_count=0; p; p = p->p_list.le_next) {
		kd_mapcount += get_task_numacts((task_t)p->task);
		tts_count++;
	}
	proc_list_unlock();

	/*
	 * The proc count could change during buffer allocation,
	 * so introduce a small fudge factor to bump up the
	 * buffer sizes. This gives new tasks some chance of 
	 * making into the tables.  Bump up by 10%.
	 */
	kd_mapcount += kd_mapcount/10;
	tts_count += tts_count/10;

	kd_mapsize = kd_mapcount * sizeof(kd_threadmap);

	if ((kmem_alloc(kernel_map, & kd_maptomem, (vm_size_t)kd_mapsize) == KERN_SUCCESS)) {
		kd_mapptr = (kd_threadmap *) kd_maptomem;
		bzero(kd_mapptr, kd_mapsize);
	} else
		kd_mapptr = (kd_threadmap *) 0;

	tts_mapsize = tts_count * sizeof(struct tts);

	if ((kmem_alloc(kernel_map, & tts_maptomem, (vm_size_t)tts_mapsize) == KERN_SUCCESS)) {
		tts_mapptr = (struct tts *) tts_maptomem;
		bzero(tts_mapptr, tts_mapsize);
	} else
		tts_mapptr = (struct tts *) 0;

	/* 
	 * We need to save the procs command string
	 * and take a reference for each task associated
	 * with a valid process
	 */
	if (tts_mapptr) {
		/*
		 * should use proc_iterate
		 */
		proc_list_lock();

	        for (p = allproc.lh_first, i=0; p && i < tts_count; p = p->p_list.le_next) {
	                if (p->p_lflag & P_LEXIT)
		                continue;

			if (p->task) {
				task_reference(p->task);
				tts_mapptr[i].task = p->task;
				tts_mapptr[i].pid  = p->p_pid;
				(void)strlcpy(tts_mapptr[i].task_comm, p->p_comm, sizeof(tts_mapptr[i].task_comm));
				i++;
			}
		}
		tts_count = i;

		proc_list_unlock();
	}

	if (kd_mapptr && tts_mapptr) {
		kdebug_flags |= KDBG_MAPINIT;

		/*
		 * Initialize thread map data
		 */
		akrt.map = kd_mapptr;
		akrt.count = 0;
		akrt.maxcount = kd_mapcount;
	    
		for (i = 0; i < tts_count; i++) {
			akrt.atts = &tts_mapptr[i];
			task_act_iterate_wth_args(tts_mapptr[i].task, kdbg_resolve_map, &akrt);
			task_deallocate((task_t) tts_mapptr[i].task);
		}
		kmem_free(kernel_map, (vm_offset_t)tts_mapptr, tts_mapsize);
	}
}

static void
kdbg_clear(void)
{
        /*
	 * Clean up the trace buffer
	 * First make sure we're not in
	 * the middle of cutting a trace
	 */

	kdebug_enable &= ~KDEBUG_ENABLE_TRACE;
	kdebug_slowcheck = SLOW_NOLOG;

	/*
	 * make sure the SLOW_NOLOG is seen
	 * by everyone that might be trying
	 * to cut a trace..
	 */
	IOSleep(100);

	if (kdebug_enable & KDEBUG_ENABLE_ENTROPY)
		kdebug_slowcheck |= SLOW_ENTROPY;

        global_state_pid = -1;
	kdebug_flags &= (unsigned int)~KDBG_CKTYPES;
	kdebug_flags &= ~(KDBG_NOWRAP | KDBG_RANGECHECK | KDBG_VALCHECK);
	kdebug_flags &= ~(KDBG_PIDCHECK | KDBG_PIDEXCLUDE);

	delete_buffers();

	/* Clean up the thread map buffer */
	kdebug_flags &= ~KDBG_MAPINIT;
	if (kd_mapptr) {
		kmem_free(kernel_map, (vm_offset_t)kd_mapptr, kd_mapsize);
		kd_mapptr = (kd_threadmap *) 0;
	}
	kd_mapsize = 0;
	kd_mapcount = 0;
}

int
kdbg_setpid(kd_regtype *kdr)
{
	pid_t pid;
	int flag, ret=0;
	struct proc *p;

	pid = (pid_t)kdr->value1;
	flag = (int)kdr->value2;

	if (pid > 0) {
		if ((p = proc_find(pid)) == NULL)
			ret = ESRCH;
		else {
			if (flag == 1) {
				/*
				 * turn on pid check for this and all pids
				 */
				kdebug_flags |= KDBG_PIDCHECK;
				kdebug_flags &= ~KDBG_PIDEXCLUDE;
				kdebug_slowcheck |= SLOW_CHECKS;
				
				p->p_kdebug = 1;
			} else {
				/*
				 * turn off pid check for this pid value
				 * Don't turn off all pid checking though
				 *
				 * kdebug_flags &= ~KDBG_PIDCHECK;
				 */   
				p->p_kdebug = 0;
			}
			proc_rele(p);
		}
	}
	else
		ret = EINVAL;

	return(ret);
}

/* This is for pid exclusion in the trace buffer */
int
kdbg_setpidex(kd_regtype *kdr)
{
	pid_t pid;
	int flag, ret=0;
	struct proc *p;

	pid = (pid_t)kdr->value1;
	flag = (int)kdr->value2;

	if (pid > 0) {
		if ((p = proc_find(pid)) == NULL)
			ret = ESRCH;
		else {
			if (flag == 1) {
				/*
				 * turn on pid exclusion
				 */
				kdebug_flags |= KDBG_PIDEXCLUDE;
				kdebug_flags &= ~KDBG_PIDCHECK;
				kdebug_slowcheck |= SLOW_CHECKS;

				p->p_kdebug = 1;
			}
			else {
				/*
				 * turn off pid exclusion for this pid value
				 * Don't turn off all pid exclusion though
				 *
				 * kdebug_flags &= ~KDBG_PIDEXCLUDE;
				 */   
				p->p_kdebug = 0;
			}
			proc_rele(p);
		}
	} else
		ret = EINVAL;

	return(ret);
}


/*
 * This is for setting a maximum decrementer value
 */
int
kdbg_setrtcdec(kd_regtype *kdr)
{
	int ret = 0;
	natural_t decval;

	decval = (natural_t)kdr->value1;

	if (decval && decval < KDBG_MINRTCDEC)
		ret = EINVAL;
#ifdef ppc
	else {
		maxDec = decval ? decval : 0x7FFFFFFF;	/* Set or reset the max decrementer */
	}
#else
	else
		ret = ENOTSUP;
#endif /* ppc */

	return(ret);
}

int
kdbg_setreg(kd_regtype * kdr)
{
	int ret=0;
	unsigned int val_1, val_2, val;
	switch (kdr->type) {
	
	case KDBG_CLASSTYPE :
		val_1 = (kdr->value1 & 0xff);
		val_2 = (kdr->value2 & 0xff);
		kdlog_beg = (val_1<<24);
		kdlog_end = (val_2<<24);
		kdebug_flags &= (unsigned int)~KDBG_CKTYPES;
		kdebug_flags &= ~KDBG_VALCHECK;       /* Turn off specific value check  */
		kdebug_flags |= (KDBG_RANGECHECK | KDBG_CLASSTYPE);
		kdebug_slowcheck |= SLOW_CHECKS;
		break;
	case KDBG_SUBCLSTYPE :
		val_1 = (kdr->value1 & 0xff);
		val_2 = (kdr->value2 & 0xff);
		val = val_2 + 1;
		kdlog_beg = ((val_1<<24) | (val_2 << 16));
		kdlog_end = ((val_1<<24) | (val << 16));
		kdebug_flags &= (unsigned int)~KDBG_CKTYPES;
		kdebug_flags &= ~KDBG_VALCHECK;       /* Turn off specific value check  */
		kdebug_flags |= (KDBG_RANGECHECK | KDBG_SUBCLSTYPE);
		kdebug_slowcheck |= SLOW_CHECKS;
		break;
	case KDBG_RANGETYPE :
		kdlog_beg = (kdr->value1);
		kdlog_end = (kdr->value2);
		kdebug_flags &= (unsigned int)~KDBG_CKTYPES;
		kdebug_flags &= ~KDBG_VALCHECK;       /* Turn off specific value check  */
		kdebug_flags |= (KDBG_RANGECHECK | KDBG_RANGETYPE);
		kdebug_slowcheck |= SLOW_CHECKS;
		break;
	case KDBG_VALCHECK:
		kdlog_value1 = (kdr->value1);
		kdlog_value2 = (kdr->value2);
		kdlog_value3 = (kdr->value3);
		kdlog_value4 = (kdr->value4);
		kdebug_flags &= (unsigned int)~KDBG_CKTYPES;
		kdebug_flags &= ~KDBG_RANGECHECK;    /* Turn off range check */
		kdebug_flags |= KDBG_VALCHECK;       /* Turn on specific value check  */
		kdebug_slowcheck |= SLOW_CHECKS;
		break;
	case KDBG_TYPENONE :
		kdebug_flags &= (unsigned int)~KDBG_CKTYPES;

		if ( (kdebug_flags & (KDBG_RANGECHECK | KDBG_VALCHECK | KDBG_PIDCHECK | KDBG_PIDEXCLUDE)) )
		        kdebug_slowcheck |= SLOW_CHECKS;
		else
		        kdebug_slowcheck &= ~SLOW_CHECKS;

		kdlog_beg = 0;
		kdlog_end = 0;
		break;
	default :
		ret = EINVAL;
		break;
	}
	return(ret);
}

int
kdbg_getreg(__unused kd_regtype * kdr)
{
#if 0	
	int i,j, ret=0;
	unsigned int val_1, val_2, val;

	switch (kdr->type) {
	case KDBG_CLASSTYPE :
		val_1 = (kdr->value1 & 0xff);
		val_2 = val_1 + 1;
		kdlog_beg = (val_1<<24);
		kdlog_end = (val_2<<24);
		kdebug_flags &= (unsigned int)~KDBG_CKTYPES;
		kdebug_flags |= (KDBG_RANGECHECK | KDBG_CLASSTYPE);
		break;
	case KDBG_SUBCLSTYPE :
		val_1 = (kdr->value1 & 0xff);
		val_2 = (kdr->value2 & 0xff);
		val = val_2 + 1;
		kdlog_beg = ((val_1<<24) | (val_2 << 16));
		kdlog_end = ((val_1<<24) | (val << 16));
		kdebug_flags &= (unsigned int)~KDBG_CKTYPES;
		kdebug_flags |= (KDBG_RANGECHECK | KDBG_SUBCLSTYPE);
		break;
	case KDBG_RANGETYPE :
		kdlog_beg = (kdr->value1);
		kdlog_end = (kdr->value2);
		kdebug_flags &= (unsigned int)~KDBG_CKTYPES;
		kdebug_flags |= (KDBG_RANGECHECK | KDBG_RANGETYPE);
		break;
	case KDBG_TYPENONE :
		kdebug_flags &= (unsigned int)~KDBG_CKTYPES;
		kdlog_beg = 0;
		kdlog_end = 0;
		break;
	default :
		ret = EINVAL;
		break;
	}
#endif /* 0 */
	return(EINVAL);
}


int
kdbg_readmap(user_addr_t buffer, size_t *number, vnode_t vp, vfs_context_t ctx)
{
	int avail = *number;
	int ret = 0;
	uint32_t count = 0;

	count = avail/sizeof (kd_threadmap);

	if (count && (count <= kd_mapcount))
	{
		if ((kdebug_flags & KDBG_MAPINIT) && kd_mapsize && kd_mapptr)
		{
			if (*number < kd_mapsize)
				ret = EINVAL;
			else
			{
				if (vp) {
					vn_rdwr(UIO_WRITE, vp, (caddr_t)&count, sizeof(uint32_t), RAW_file_offset,
						UIO_SYSSPACE, IO_NODELOCKED|IO_UNIT, vfs_context_ucred(ctx), (int *) 0, vfs_context_proc(ctx));
					RAW_file_offset += sizeof(uint32_t);

					vn_rdwr(UIO_WRITE, vp, (caddr_t)kd_mapptr, kd_mapsize, RAW_file_offset,
						UIO_SYSSPACE, IO_NODELOCKED|IO_UNIT, vfs_context_ucred(ctx), (int *) 0, vfs_context_proc(ctx));
					RAW_file_offset += kd_mapsize;

				} else {
					if (copyout(kd_mapptr, buffer, kd_mapsize))
						ret = EINVAL;
				}
			}
		}
		else
			ret = EINVAL;
	}
	else
		ret = EINVAL;

	if (ret && vp) {
		count = 0;

		vn_rdwr(UIO_WRITE, vp, (caddr_t)&count, sizeof(uint32_t), RAW_file_offset,
			UIO_SYSSPACE, IO_NODELOCKED|IO_UNIT, vfs_context_ucred(ctx), (int *) 0, vfs_context_proc(ctx));
		RAW_file_offset += sizeof(uint32_t);
	}
	if ((kdebug_flags & KDBG_MAPINIT) && kd_mapsize && kd_mapptr)
	{
		kmem_free(kernel_map, (vm_offset_t)kd_mapptr, kd_mapsize);
		kdebug_flags &= ~KDBG_MAPINIT;
		kd_mapsize = 0;
		kd_mapptr = (kd_threadmap *) 0;
		kd_mapcount = 0;
	}  

	return(ret);
}

int
kdbg_getentropy (user_addr_t buffer, size_t *number, int ms_timeout)
{
	int avail = *number;
	int ret = 0;

	if (kd_entropy_buffer)
		return(EBUSY);

	kd_entropy_count = avail/sizeof(mach_timespec_t);
	kd_entropy_bufsize = kd_entropy_count * sizeof(mach_timespec_t);
	kd_entropy_indx = 0;

	/*
	 * Enforce maximum entropy entries here if needed
	 * allocate entropy buffer
	 */
	if (kmem_alloc(kernel_map, &kd_entropy_buftomem,
		       (vm_size_t)kd_entropy_bufsize) == KERN_SUCCESS) {
		kd_entropy_buffer = (uint64_t *) kd_entropy_buftomem;
	} else {
		kd_entropy_buffer = (uint64_t *) 0;
		kd_entropy_count = 0;
		kd_entropy_indx = 0;
		return (EINVAL);
	}

	if (ms_timeout < 10)
		ms_timeout = 10;

	/*
	 * Enable entropy sampling
	 */
	kdebug_enable |= KDEBUG_ENABLE_ENTROPY;
	kdebug_slowcheck |= SLOW_ENTROPY;

	ret = tsleep (kdbg_getentropy, PRIBIO | PCATCH, "kd_entropy", (ms_timeout/(1000/HZ)));

	/*
	 * Disable entropy sampling
	 */
	kdebug_enable &= ~KDEBUG_ENABLE_ENTROPY;
	kdebug_slowcheck &= ~SLOW_ENTROPY;

	*number = 0;
	ret = 0;

	if (kd_entropy_indx > 0) {
		/*
		 * copyout the buffer
		 */
		if (copyout(kd_entropy_buffer, buffer, kd_entropy_indx * sizeof(mach_timespec_t)))
			ret = EINVAL;
		else
			*number = kd_entropy_indx;
	}
	/*
	 * Always cleanup
	 */
	kd_entropy_count = 0;
	kd_entropy_indx = 0;
	kd_entropy_buftomem = 0;
	kmem_free(kernel_map, (vm_offset_t)kd_entropy_buffer, kd_entropy_bufsize);
	kd_entropy_buffer = (uint64_t *) 0;
	
	return(ret);
}


static void
kdbg_set_nkdbufs(unsigned int value)
{
        /*
	 * We allow a maximum buffer size of 50% of either ram or max mapped address, whichever is smaller
	 * 'value' is the desired number of trace entries
	 */
        unsigned int max_entries = (sane_size/2) / sizeof(kd_buf);

	if (value <= max_entries)
		nkdbufs = value;
	else
		nkdbufs = max_entries;
}


/*
 * This function is provided for the CHUD toolkit only.
 *    int val:
 *        zero disables kdebug_chudhook function call
 *        non-zero enables kdebug_chudhook function call
 *    char *fn:
 *        address of the enabled kdebug_chudhook function
*/

void
kdbg_control_chud(int val, void *fn)
{
        if (val) {
                /* enable chudhook */
		kdebug_chudhook = fn;
	        kdebug_enable |= KDEBUG_ENABLE_CHUD;
	}
	else {
	        /* disable chudhook */
                kdebug_enable &= ~KDEBUG_ENABLE_CHUD;
		kdebug_chudhook = 0;
	}
}

	
int
kdbg_control(int *name, u_int namelen, user_addr_t where, size_t *sizep)
{
	int ret = 0;
	size_t size = *sizep;
	unsigned int value = 0;
	kd_regtype kd_Reg;
	kbufinfo_t kd_bufinfo;
	pid_t curpid;
	struct proc *p, *curproc;

	if (name[0] == KERN_KDGETENTROPY ||
		name[0] == KERN_KDEFLAGS ||
		name[0] == KERN_KDDFLAGS ||
		name[0] == KERN_KDENABLE ||
		name[0] == KERN_KDSETBUF) {
		
		if ( namelen < 2 )
	        return(EINVAL);
		value = name[1];
	}
	
	kdbg_lock_init();

	if ( !(kdebug_flags & KDBG_LOCKINIT))
	        return(ENOSPC);

	lck_mtx_lock(kd_trace_mtx_sysctl);

	if (name[0] == KERN_KDGETBUF) {
		/* 
		 * Does not alter the global_state_pid
		 * This is a passive request.
		 */
		if (size < sizeof(kd_bufinfo.nkdbufs)) {
			/* 
			 * There is not enough room to return even
			 * the first element of the info structure.
			 */
			ret = EINVAL;
			goto out;
		}
		kd_bufinfo.nkdbufs = nkdbufs;
		kd_bufinfo.nkdthreads = kd_mapsize / sizeof(kd_threadmap);

		if ( (kdebug_slowcheck & SLOW_NOLOG) )
			kd_bufinfo.nolog = 1;
		else
			kd_bufinfo.nolog = 0;

		kd_bufinfo.flags = kdebug_flags;
#if defined(__LP64__)
		kd_bufinfo.flags |= KDBG_LP64;
#endif
		kd_bufinfo.bufid = global_state_pid;
	   
		if (size >= sizeof(kd_bufinfo)) {
			/*
			 * Provide all the info we have
			 */
			if (copyout(&kd_bufinfo, where, sizeof(kd_bufinfo)))
				ret = EINVAL;
		} else {
			/* 
		 	 * For backwards compatibility, only provide
		 	 * as much info as there is room for.
		 	 */
			if (copyout(&kd_bufinfo, where, size))
				ret = EINVAL;
		}
		goto out;

	} else if (name[0] == KERN_KDGETENTROPY) {		
		if (kd_entropy_buffer)
			ret = EBUSY;
		else
			ret = kdbg_getentropy(where, sizep, value);
		goto out;
	}
	
	if ((curproc = current_proc()) != NULL)
		curpid = curproc->p_pid;
	else {
		ret = ESRCH;
		goto out;
	}
        if (global_state_pid == -1)
		global_state_pid = curpid;
	else if (global_state_pid != curpid) {
		if ((p = proc_find(global_state_pid)) == NULL) {
			/*
			 * The global pid no longer exists
			 */
			global_state_pid = curpid;
		} else {
			/*
			 * The global pid exists, deny this request
			 */
			proc_rele(p);

			ret = EBUSY;
			goto out;
		}
	}

	switch(name[0]) {
		case KERN_KDEFLAGS:
			value &= KDBG_USERFLAGS;
			kdebug_flags |= value;
			break;
		case KERN_KDDFLAGS:
			value &= KDBG_USERFLAGS;
			kdebug_flags &= ~value;
			break;
		case KERN_KDENABLE:
			/*
			 * used to enable or disable
			 */
			if (value) {
				/*
				 * enable only if buffer is initialized
				 */
				if (!(kdebug_flags & KDBG_BUFINIT)) {
					ret = EINVAL;
					break;
				}
				kdbg_mapinit();

				kdebug_enable |= KDEBUG_ENABLE_TRACE;
				kdebug_slowcheck &= ~SLOW_NOLOG;
			}
			else {
				kdebug_enable &= ~KDEBUG_ENABLE_TRACE;
				kdebug_slowcheck |= SLOW_NOLOG;
			}
			break;
		case KERN_KDSETBUF:
			kdbg_set_nkdbufs(value);
			break;
		case KERN_KDSETUP:
			ret = kdbg_reinit();
			break;
		case KERN_KDREMOVE:
			kdbg_clear();
			break;
		case KERN_KDSETREG:
			if(size < sizeof(kd_regtype)) {
				ret = EINVAL;
				break;
			}
			if (copyin(where, &kd_Reg, sizeof(kd_regtype))) {
				ret = EINVAL;
				break;
			}
			ret = kdbg_setreg(&kd_Reg);
			break;
		case KERN_KDGETREG:
			if (size < sizeof(kd_regtype)) {
				ret = EINVAL;
				break;
			}
			ret = kdbg_getreg(&kd_Reg);
		 	if (copyout(&kd_Reg, where, sizeof(kd_regtype))) {
				ret = EINVAL;
			}
			break;
		case KERN_KDREADTR:
			ret = kdbg_read(where, sizep, NULL, NULL);
			break;
		case KERN_KDPIDTR:
			if (size < sizeof(kd_regtype)) {
				ret = EINVAL;
				break;
			}
			if (copyin(where, &kd_Reg, sizeof(kd_regtype))) {
				ret = EINVAL;
				break;
			}
			ret = kdbg_setpid(&kd_Reg);
			break;
		case KERN_KDPIDEX:
			if (size < sizeof(kd_regtype)) {
				ret = EINVAL;
				break;
			}
			if (copyin(where, &kd_Reg, sizeof(kd_regtype))) {
				ret = EINVAL;
				break;
			}
			ret = kdbg_setpidex(&kd_Reg);
			break;
	        case KERN_KDTHRMAP:
		        ret = kdbg_readmap(where, sizep, NULL, NULL);
		        break;
        	case KERN_KDSETRTCDEC:
			if (size < sizeof(kd_regtype)) {
				ret = EINVAL;
				break;
			}
			if (copyin(where, &kd_Reg, sizeof(kd_regtype))) {
				ret = EINVAL;
				break;
			}
			ret = kdbg_setrtcdec(&kd_Reg);
			break;
		       
		default:
			ret = EINVAL;
	}
out:
	lck_mtx_unlock(kd_trace_mtx_sysctl);

	return(ret);
}


/*
 * This code can run for the most part concurrently with kernel_debug_internal()...
 * 'release_storage_unit' will take the kds_spin_lock which may cause us to briefly
 * synchronize with the recording side of this puzzle... otherwise, we are able to
 * move through the lists w/o use of any locks
 */
int
kdbg_read(user_addr_t buffer, size_t *number, vnode_t vp, vfs_context_t ctx)
{
	unsigned int count;
	unsigned int cpu, mincpu;
	uint64_t  mintime, t;
	int error = 0,s = 0;
	kd_buf *tempbuf;
	kd_buf *rcursor;
	kd_buf *min_rcursor;
	struct kd_storage *kdsp;
	struct kd_bufinfo *kdbp;
	uint32_t tempbuf_count;
	uint32_t tempbuf_number;
	uint32_t old_kdebug_flags;
	uint32_t old_kdebug_slowcheck;

	count = *number/sizeof(kd_buf);
	*number = 0;

	if (count == 0 || !(kdebug_flags & KDBG_BUFINIT) || kdcopybuf == 0)
		return EINVAL;

	/*
	 * because we hold kd_trace_mtx_sysctl, no other control threads can 
	 * be playing with kdebug_flags... the code that cuts new events could
	 * be running, but it grabs kds_spin_lock if it needs to acquire a new
	 * storage chunk which is where it examines kdebug_flags... it its adding
	 * to the same chunk we're reading from, no problem... 
	 */
	s = ml_set_interrupts_enabled(FALSE);
	lck_spin_lock(kds_spin_lock);

	old_kdebug_slowcheck = kdebug_slowcheck;
	old_kdebug_flags = kdebug_flags;

	kdebug_flags &= ~KDBG_WRAPPED;
	kdebug_flags |= KDBG_NOWRAP;

	lck_spin_unlock(kds_spin_lock);
	ml_set_interrupts_enabled(s);

	if (count > nkdbufs)
		count = nkdbufs;

	if ((tempbuf_count = count) > KDCOPYBUF_COUNT)
	        tempbuf_count = KDCOPYBUF_COUNT;

	while (count) {
	        tempbuf = kdcopybuf;
		tempbuf_number = 0;

	        while (tempbuf_count) {
			mintime = 0xffffffffffffffffULL; /* all actual timestamps are below */
			mincpu = -1;
			min_rcursor = NULL;

			for (cpu = 0, kdbp = &kdbip[0]; cpu < kd_cpus; cpu++, kdbp++) {

				if ((kdsp = kdbp->kd_list_head) == NULL)
				        continue;
				rcursor = kdsp->kds_readlast;

				if (rcursor == kdsp->kds_bufptr)
					continue;
				t = kdbg_get_timestamp(rcursor);

				if (t < mintime) {
					mincpu = cpu;
				        mintime = t;
					min_rcursor = rcursor;
				}
			}
			if (mincpu == (unsigned int)-1)
			        /*
				 * all buffers ran empty
				 */
			        break;
			
			kdbp = &kdbip[mincpu];
			kdsp = kdbp->kd_list_head;

			*tempbuf = *min_rcursor;

			if (mintime != kdbg_get_timestamp(tempbuf)) {
				/*
				 * we stole this storage unit and used it
				 * before we could slurp the selected event out
				 * so we need to re-evaluate
				 */
				continue;
			}
			/*
			 * Watch for out of order timestamps
			 */	
			if (mintime < kdbp->kd_prev_timebase) {
				/*
				 * if so, use the previous timestamp + 1 cycle
				 */
				kdbp->kd_prev_timebase++;
				kdbg_set_timestamp_and_cpu(tempbuf, kdbp->kd_prev_timebase, mincpu);
			} else
				kdbp->kd_prev_timebase = mintime;

			if (min_rcursor == kdsp->kds_readlast)
				kdsp->kds_readlast++;

			if (kdsp->kds_readlast == kdsp->kds_buflast)
				release_storage_unit(kdbp, kdsp);

			tempbuf_count--;
			tempbuf_number++;
			tempbuf++;
		}
		if (tempbuf_number) {

			if (vp) {
				error = vn_rdwr(UIO_WRITE, vp, (caddr_t)kdcopybuf, tempbuf_number * sizeof(kd_buf), RAW_file_offset,
						UIO_SYSSPACE, IO_NODELOCKED|IO_UNIT, vfs_context_ucred(ctx), (int *) 0, vfs_context_proc(ctx));

				RAW_file_offset += (tempbuf_number * sizeof(kd_buf));
			} else {
				error = copyout(kdcopybuf, buffer, tempbuf_number * sizeof(kd_buf));
				buffer += (tempbuf_number * sizeof(kd_buf));
			}
			if (error) {
				*number = 0;
				error = EINVAL;
				break;
			}
			count   -= tempbuf_number;
			*number += tempbuf_number;
		}
		if (tempbuf_count)
		       /*
			* all trace buffers are empty
			*/
		        break;

		if ((tempbuf_count = count) > KDCOPYBUF_COUNT)
		        tempbuf_count = KDCOPYBUF_COUNT;
	}
	if ( !(old_kdebug_flags & KDBG_NOWRAP)) {

		s = ml_set_interrupts_enabled(FALSE);
		lck_spin_lock(kds_spin_lock);

		kdebug_flags &= ~KDBG_NOWRAP;

		if ( !(old_kdebug_slowcheck & SLOW_NOLOG))
			kdebug_slowcheck &= ~SLOW_NOLOG;

		lck_spin_unlock(kds_spin_lock);
		ml_set_interrupts_enabled(s);
	}
	return (error);
}


unsigned char *getProcName(struct proc *proc);
unsigned char *getProcName(struct proc *proc) {

	return (unsigned char *) &proc->p_comm;	/* Return pointer to the proc name */

}

#define STACKSHOT_SUBSYS_LOCK() lck_mtx_lock(&stackshot_subsys_mutex)
#define STACKSHOT_SUBSYS_UNLOCK() lck_mtx_unlock(&stackshot_subsys_mutex)
#if defined(__i386__) || defined (__x86_64__)
#define TRAP_DEBUGGER __asm__ volatile("int3");
#endif
#ifdef __ppc__
#define TRAP_DEBUGGER __asm__ volatile("tw 4,r3,r3");
#endif

#define SANE_TRACEBUF_SIZE 2*1024*1024

/* Initialize the mutex governing access to the stack snapshot subsystem */
__private_extern__ void
stackshot_lock_init( void )
{
	stackshot_subsys_lck_grp_attr = lck_grp_attr_alloc_init();

	stackshot_subsys_lck_grp = lck_grp_alloc_init("stackshot_subsys_lock", stackshot_subsys_lck_grp_attr);

	stackshot_subsys_lck_attr = lck_attr_alloc_init();

	lck_mtx_init(&stackshot_subsys_mutex, stackshot_subsys_lck_grp, stackshot_subsys_lck_attr);
}

/*
 * stack_snapshot:   Obtains a coherent set of stack traces for all threads
 *		     on the system, tracing both kernel and user stacks
 *		     where available. Uses machine specific trace routines
 *		     for ppc, ppc64 and x86.
 * Inputs:	     uap->pid - process id of process to be traced, or -1
 *		     for the entire system
 *		     uap->tracebuf - address of the user space destination
 *		     buffer 
 *		     uap->tracebuf_size - size of the user space trace buffer
 *		     uap->options - various options, including the maximum
 *		     number of frames to trace.
 * Outputs:	     EPERM if the caller is not privileged
 *		     EINVAL if the supplied trace buffer isn't sanely sized
 *		     ENOMEM if we don't have enough memory to satisfy the
 *		     request
 *		     ENOENT if the target pid isn't found
 *		     ENOSPC if the supplied buffer is insufficient
 *		     *retval contains the number of bytes traced, if successful
 *		     and -1 otherwise. If the request failed due to
 *		     tracebuffer exhaustion, we copyout as much as possible.
 */
int
stack_snapshot(struct proc *p, register struct stack_snapshot_args *uap, int32_t *retval) {
	int error = 0;


	if ((error = suser(kauth_cred_get(), &p->p_acflag)))
                return(error);

	return stack_snapshot2(uap->pid, uap->tracebuf, uap->tracebuf_size,
	    uap->flags, uap->dispatch_offset, retval);
}

int
stack_snapshot2(pid_t pid, user_addr_t tracebuf, uint32_t tracebuf_size, uint32_t flags, uint32_t dispatch_offset, int32_t *retval)
{
	int error = 0;
	unsigned bytesTraced = 0;

	*retval = -1;
/* Serialize tracing */	
	STACKSHOT_SUBSYS_LOCK();
	
	if ((tracebuf_size <= 0) || (tracebuf_size > SANE_TRACEBUF_SIZE)) {
		error = EINVAL;
		goto error_exit;
	}

	MALLOC(stackshot_snapbuf, void *, tracebuf_size, M_TEMP, M_WAITOK);

	if (stackshot_snapbuf == NULL) {
		error = ENOMEM;
		goto error_exit;
	}
/* Preload trace parameters*/	
	kdp_snapshot_preflight(pid, stackshot_snapbuf, tracebuf_size, flags, dispatch_offset);

/* Trap to the debugger to obtain a coherent stack snapshot; this populates
 * the trace buffer
 */
	if (panic_active()) {
		error = ENOMEM;
		goto error_exit;
	}

	TRAP_DEBUGGER;

	bytesTraced = kdp_stack_snapshot_bytes_traced();
			
	if (bytesTraced > 0) {
		if ((error = copyout(stackshot_snapbuf, tracebuf,
			((bytesTraced < tracebuf_size) ?
			    bytesTraced : tracebuf_size))))
			goto error_exit;
		*retval = bytesTraced;
	}
	else {
		error = ENOENT;
		goto error_exit;
	}

	error = kdp_stack_snapshot_geterror();
	if (error == -1) {
		error = ENOSPC;
		*retval = -1;
		goto error_exit;
	}

error_exit:
	if (stackshot_snapbuf != NULL)
		FREE(stackshot_snapbuf, M_TEMP);
	stackshot_snapbuf = NULL;
	STACKSHOT_SUBSYS_UNLOCK();
	return error;
}

void
start_kern_tracing(unsigned int new_nkdbufs) {
	if (!new_nkdbufs)
		return;
	kdbg_set_nkdbufs(new_nkdbufs);
	kdbg_lock_init();
	kdbg_reinit();
	kdebug_enable |= KDEBUG_ENABLE_TRACE;
	kdebug_slowcheck &= ~SLOW_NOLOG;
	kdbg_mapinit();

#if defined(__i386__) || defined(__x86_64__)
	uint64_t now = mach_absolute_time();

        KERNEL_DEBUG_CONSTANT((TRACEDBG_CODE(DBG_TRACE_INFO, 1)) | DBG_FUNC_NONE,
                              (uint32_t)(tsc_rebase_abs_time >> 32), (uint32_t)tsc_rebase_abs_time,
                              (uint32_t)(now >> 32), (uint32_t)now,
                              0);
#endif
	printf("kernel tracing started\n");
}

void
kdbg_dump_trace_to_file(const char *filename)
{
	vfs_context_t	ctx;
	vnode_t		vp;
	int		error;
	size_t		number;


	if (kdebug_enable & (KDEBUG_ENABLE_CHUD | KDEBUG_ENABLE_ENTROPY))
		return;

        if (global_state_pid != -1) {
		if ((proc_find(global_state_pid)) != NULL) {
			/*
			 * The global pid exists, we're running
			 * due to fs_usage, latency, etc...
			 * don't cut the panic/shutdown trace file
			 */
			return;
		}
	}
	KERNEL_DEBUG_CONSTANT((TRACEDBG_CODE(DBG_TRACE_INFO, 0)) | DBG_FUNC_NONE, 0, 0, 0, 0, 0);

	kdebug_enable = 0;

	ctx = vfs_context_kernel();

	if ((error = vnode_open(filename, (O_CREAT | FWRITE | O_NOFOLLOW), 0600, 0, &vp, ctx)))
		return;

	number = kd_mapsize;
	kdbg_readmap(0, &number, vp, ctx);

	number = nkdbufs*sizeof(kd_buf);
	kdbg_read(0, &number, vp, ctx);
	
	vnode_close(vp, FWRITE, ctx);

	sync(current_proc(), (void *)NULL, (int *)NULL);
}
