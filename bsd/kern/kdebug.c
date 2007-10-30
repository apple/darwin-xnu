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

#include <kern/thread.h>
#include <kern/task.h>
#include <kern/debug.h>
#include <vm/vm_kern.h>
#include <sys/lock.h>

#include <sys/malloc.h>
#include <sys/kauth.h>

#include <mach/mach_host.h>		/* for host_info() */
#include <libkern/OSAtomic.h>

/* XXX should have prototypes, but Mach does not provide one */
void task_act_iterate_wth_args(task_t, void(*)(thread_t, void *), void *);
int cpu_number(void);	/* XXX <machine/...> include path broken */

/* XXX should probably be static, but it's debugging code... */
int kdbg_read(user_addr_t, size_t *);
void kdbg_control_chud(int, void *);
int kdbg_control(int *, u_int, user_addr_t, size_t *);
int kdbg_getentropy (user_addr_t, size_t *, int);
int kdbg_readmap(user_addr_t, size_t *);
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
unsigned int      kd_entropy_buftomem = 0;


#define SLOW_NOLOG	0x01
#define SLOW_CHECKS	0x02
#define SLOW_ENTROPY	0x04

unsigned int kdebug_slowcheck=SLOW_NOLOG;

unsigned int kd_cpus;

struct kd_bufinfo {
        kd_buf * kd_stop;
        kd_buf * kd_bufptr;
        kd_buf * kd_buffer;
        kd_buf * kd_buflast;
        kd_buf * kd_readlast;
        int      kd_wrapped;	/* plus, the global flag KDBG_WRAPPED is set if one of the buffers has wrapped */
        uint64_t kd_prev_timebase;
        int	 kd_pad[24];	/* pad out to 128 bytes so that no cache line is shared between CPUs */

};

struct kd_bufinfo *kdbip = NULL;

#define KDCOPYBUF_COUNT	1024
#define KDCOPYBUF_SIZE	(KDCOPYBUF_COUNT * sizeof(kd_buf))
kd_buf *kdcopybuf = NULL;


unsigned int nkdbufs = 8192;
unsigned int kd_bufsize = 0;
unsigned int kdebug_flags = 0;
unsigned int kdlog_beg=0;
unsigned int kdlog_end=0;
unsigned int kdlog_value1=0;
unsigned int kdlog_value2=0;
unsigned int kdlog_value3=0;
unsigned int kdlog_value4=0;

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
stack_snapshot2(pid_t pid, user_addr_t tracebuf, uint32_t tracebuf_size, uint32_t options, register_t *retval);

extern void
kdp_snapshot_preflight(int pid, void  *tracebuf, uint32_t tracebuf_size, uint32_t options);

extern int
kdp_stack_snapshot_geterror(void);
extern unsigned int
kdp_stack_snapshot_bytes_traced(void);

kd_threadmap *kd_mapptr = 0;
unsigned int kd_mapsize = 0;
unsigned int kd_mapcount = 0;
unsigned int kd_maptomem = 0;

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
typedef void (*kd_chudhook_fn) (unsigned int debugid, unsigned int arg1,
				unsigned int arg2, unsigned int arg3,
				unsigned int arg4, unsigned int arg5);

kd_chudhook_fn kdebug_chudhook = 0;   /* pointer to CHUD toolkit function */

__private_extern__ void stackshot_lock_init( void ) __attribute__((section("__TEXT, initcode")));

/* Support syscall SYS_kdebug_trace */
int
kdebug_trace(__unused struct proc *p, struct kdebug_trace_args *uap, __unused register_t *retval)
{
    if ( (kdebug_enable == 0) )
        return(EINVAL);
  
    kernel_debug(uap->code, uap->arg1, uap->arg2, uap->arg3, uap->arg4, 0);
    return(0);
}

static int
create_buffers(void)
{
        unsigned int	cpu, i;
	int     nentries;

	nentries = nkdbufs / kd_cpus;
	nkdbufs = nentries * kd_cpus;

	kd_bufsize = nentries * sizeof(kd_buf);

	bzero((char *)kdbip, sizeof(struct kd_bufinfo) * kd_cpus);

	if (kdcopybuf == 0) {
	        if (kmem_alloc(kernel_map, (unsigned int *)&kdcopybuf, (vm_size_t)KDCOPYBUF_SIZE) != KERN_SUCCESS)
		        return(ENOMEM);
	}
	for (cpu = 0; cpu < kd_cpus; cpu++) {
	        if (kmem_alloc(kernel_map, (unsigned int *)&kdbip[cpu].kd_buffer, kd_bufsize) != KERN_SUCCESS)
		        break;
	}
	if (cpu < kd_cpus) {
	        for (i = 0; i < cpu; i++)
		        kmem_free(kernel_map, (vm_offset_t)kdbip[i].kd_buffer, kd_bufsize);
		kd_bufsize = 0;

		kmem_free(kernel_map, (vm_offset_t)kdcopybuf, KDCOPYBUF_SIZE);
		kdcopybuf = NULL;
		
		return(ENOMEM);
	}
	for (cpu = 0; cpu < kd_cpus; cpu++) {
		kdbip[cpu].kd_bufptr = kdbip[cpu].kd_buffer;
		kdbip[cpu].kd_buflast = &kdbip[cpu].kd_bufptr[nentries];
		kdbip[cpu].kd_readlast = kdbip[cpu].kd_bufptr;
	}
	kdebug_flags |= KDBG_BUFINIT;

	return(0);
}


static void
delete_buffers(void)
{
        unsigned int	cpu;

	if (kd_bufsize && (kdebug_flags & KDBG_BUFINIT)) {
	        for (cpu = 0; cpu < kd_cpus; cpu++)
		        kmem_free(kernel_map, (vm_offset_t)kdbip[cpu].kd_buffer, kd_bufsize);
		kd_bufsize = 0;
	}
	if (kdcopybuf) {
		kmem_free(kernel_map, (vm_offset_t)kdcopybuf, KDCOPYBUF_SIZE);
		kdcopybuf = NULL;
	}
	kdebug_flags &= ~KDBG_BUFINIT;
}


static void
kernel_debug_internal(unsigned int debugid, unsigned int arg1, unsigned int arg2, unsigned int arg3,
		      unsigned int arg4, unsigned int arg5, int entropy_flag)
{
	int s;
	kd_buf * kd;
	struct proc *curproc;
	unsigned long long now;
	int cpu;
	
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

	if (entropy_flag && (kdebug_enable & KDEBUG_ENABLE_ENTROPY))
	  {
	    if (kd_entropy_indx < kd_entropy_count)
	      {
		kd_entropy_buffer [ kd_entropy_indx] = mach_absolute_time();
		kd_entropy_indx++;
	      }
	    
	    if (kd_entropy_indx == kd_entropy_count)
	      {
		/* Disable entropy collection */
		kdebug_enable &= ~KDEBUG_ENABLE_ENTROPY;
		kdebug_slowcheck &= ~SLOW_ENTROPY;
	      }
	  }

	if ( (kdebug_slowcheck & SLOW_NOLOG) )
	    goto out;
	
	if (kdebug_flags & KDBG_PIDCHECK)
	  {
	    /* If kdebug flag is not set for current proc, return  */
	    curproc = current_proc();
	    if ((curproc && !(curproc->p_kdebug)) &&
		((debugid&0xffff0000) != (MACHDBG_CODE(DBG_MACH_SCHED, 0) | DBG_FUNC_NONE)))
		goto out;
	  }
	else if (kdebug_flags & KDBG_PIDEXCLUDE)
	  {
	    /* If kdebug flag is set for current proc, return  */
	    curproc = current_proc();
	    if ((curproc && curproc->p_kdebug) &&
		((debugid&0xffff0000) != (MACHDBG_CODE(DBG_MACH_SCHED, 0) | DBG_FUNC_NONE)))
		goto out;
	  }

	if (kdebug_flags & KDBG_RANGECHECK)
	  {
	    if ((debugid < kdlog_beg)
	        || ((debugid >= kdlog_end) && (debugid >> 24 != DBG_TRACE)))
		goto out;
	  }
	else if (kdebug_flags & KDBG_VALCHECK)
	  {
	    if ((debugid & DBG_FUNC_MASK) != kdlog_value1 &&
		(debugid & DBG_FUNC_MASK) != kdlog_value2 &&
		(debugid & DBG_FUNC_MASK) != kdlog_value3 &&
		(debugid & DBG_FUNC_MASK) != kdlog_value4 &&
		(debugid >> 24 != DBG_TRACE))
		goto out;
	  }

record_trace:
	kd = kdbip[cpu].kd_bufptr;
	kd->debugid = debugid;
	kd->arg1 = arg1;
	kd->arg2 = arg2;
	kd->arg3 = arg3;
	kd->arg4 = arg4;
	kd->arg5 = arg5;
	          
	/*
	 * Watch for out of order timestamps
	 */	
	if (now < kdbip[cpu].kd_prev_timebase)
	  {
	    /*
	     * if so, just store the previous timestamp + a cycle
	     */
	    now = ++kdbip[cpu].kd_prev_timebase & KDBG_TIMESTAMP_MASK;
	  }
	else
	  {
	    kdbip[cpu].kd_prev_timebase = now;
	  }
	kd->timestamp = now | (((uint64_t)cpu) << KDBG_CPU_SHIFT);

	kdbip[cpu].kd_bufptr++;

	if (kdbip[cpu].kd_bufptr >= kdbip[cpu].kd_buflast)
	  	kdbip[cpu].kd_bufptr = kdbip[cpu].kd_buffer;

	if (kdbip[cpu].kd_bufptr == kdbip[cpu].kd_readlast) {
	        if (kdebug_flags & KDBG_NOWRAP)
			kdebug_slowcheck |= SLOW_NOLOG;
		kdbip[cpu].kd_wrapped = 1;
		kdebug_flags |= KDBG_WRAPPED;
	}

out:
	ml_set_interrupts_enabled(s);
}

void
kernel_debug(unsigned int debugid, unsigned int arg1, unsigned int arg2, unsigned int arg3,
		      unsigned int arg4, __unused unsigned int arg5)
{
	kernel_debug_internal(debugid, arg1, arg2, arg3, arg4, (int)current_thread(), 1);
}

void
kernel_debug1(unsigned int debugid, unsigned int arg1, unsigned int arg2, unsigned int arg3,
		      unsigned int arg4, unsigned int arg5)
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
	kd_cpus = hinfo.physical_cpu_max;

	if (kmem_alloc(kernel_map, (unsigned int *)&kdbip,
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
    int ret=0;

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

    if ((kdebug_flags & KDBG_MAPINIT) && kd_mapsize && kd_mapptr)
      {
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
    
    return;
}


void
kdbg_trace_string(struct proc *proc, long *arg1, long *arg2, long *arg3, long *arg4)
{
    char *dbg_nameptr; 
    int dbg_namelen;
    long dbg_parms[4];
    if (!proc)
      {
	*arg1 = 0;
	*arg2 = 0;
	*arg3 = 0;
	*arg4 = 0;
	return;
      }

    /* Collect the pathname for tracing */
    dbg_nameptr = proc->p_comm;
    dbg_namelen = strlen(proc->p_comm);
    dbg_parms[0]=0L;
    dbg_parms[1]=0L;
    dbg_parms[2]=0L;
    dbg_parms[3]=0L;
  
    if(dbg_namelen > (int)sizeof(dbg_parms))
      dbg_namelen = sizeof(dbg_parms);
    
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

  if(t->count < t->maxcount)
    {
      mapptr=&t->map[t->count];
      mapptr->thread  = (unsigned int)th_act;
      (void) strlcpy (mapptr->command, t->atts->task_comm,
		      sizeof(t->atts->task_comm));

      /*
	Some kernel threads have no associated pid.
	We still need to mark the entry as valid.
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
	struct proc *p;
	struct krt akrt;
	int tts_count;    /* number of task-to-string structures */
	struct tts *tts_mapptr;
	unsigned int tts_mapsize = 0;
	unsigned int tts_maptomem=0;
	int i;


        if (kdebug_flags & KDBG_MAPINIT)
	  return;

	/* need to use PROC_SCANPROCLIST with proc_iterate */
	proc_list_lock();

	/* Calculate the sizes of map buffers*/
	for (p = allproc.lh_first, kd_mapcount=0, tts_count=0; p; 
	     p = p->p_list.le_next)
	  {
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
	if((kmem_alloc(kernel_map, & kd_maptomem,
		       (vm_size_t)kd_mapsize) == KERN_SUCCESS))
	{
	    kd_mapptr = (kd_threadmap *) kd_maptomem;
	    bzero(kd_mapptr, kd_mapsize);
	}
	else
	    kd_mapptr = (kd_threadmap *) 0;

	tts_mapsize = tts_count * sizeof(struct tts);
	if((kmem_alloc(kernel_map, & tts_maptomem,
		       (vm_size_t)tts_mapsize) == KERN_SUCCESS))
	{
	    tts_mapptr = (struct tts *) tts_maptomem;
	    bzero(tts_mapptr, tts_mapsize);
	}
	else
	    tts_mapptr = (struct tts *) 0;


	/* 
	 * We need to save the procs command string
	 * and take a reference for each task associated
	 * with a valid process
	 */

	if (tts_mapptr) {
		/* should use proc_iterate */
		proc_list_lock();

	        for (p = allproc.lh_first, i=0; p && i < tts_count; 
		     p = p->p_list.le_next) {
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


	if (kd_mapptr && tts_mapptr)
	  {
	    kdebug_flags |= KDBG_MAPINIT;
	    /* Initialize thread map data */
	    akrt.map = kd_mapptr;
	    akrt.count = 0;
	    akrt.maxcount = kd_mapcount;
	    
	    for (i=0; i < tts_count; i++)
	      {
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
	kmem_free(kernel_map, (vm_offset_t)kd_mapptr, kd_mapsize);
	kd_mapptr = (kd_threadmap *) 0;
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

  if (pid > 0)
    {
      if ((p = proc_find(pid)) == NULL)
	ret = ESRCH;
      else
	{
	  if (flag == 1)  /* turn on pid check for this and all pids */
	    {
	      kdebug_flags |= KDBG_PIDCHECK;
	      kdebug_flags &= ~KDBG_PIDEXCLUDE;
	      kdebug_slowcheck |= SLOW_CHECKS;

	      p->p_kdebug = 1;
	    }
	  else  /* turn off pid check for this pid value */
	    {
	      /* Don't turn off all pid checking though */
	      /* kdebug_flags &= ~KDBG_PIDCHECK;*/   
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

  if (pid > 0)
    {
      if ((p = proc_find(pid)) == NULL)
	ret = ESRCH;
      else
	{
	  if (flag == 1)  /* turn on pid exclusion */
	    {
	      kdebug_flags |= KDBG_PIDEXCLUDE;
	      kdebug_flags &= ~KDBG_PIDCHECK;
	      kdebug_slowcheck |= SLOW_CHECKS;

	      p->p_kdebug = 1;
	    }
	  else  /* turn off pid exclusion for this pid value */
	    {
	      /* Don't turn off all pid exclusion though */
	      /* kdebug_flags &= ~KDBG_PIDEXCLUDE;*/   
	      p->p_kdebug = 0;
	    }
	proc_rele(p);
	}
    }
  else
    ret = EINVAL;
  return(ret);
}

/* This is for setting a maximum decrementer value */
int
kdbg_setrtcdec(kd_regtype *kdr)
{
  int ret=0;
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
kdbg_readmap(user_addr_t buffer, size_t *number)
{
  int avail = *number;
  int ret = 0;
  unsigned int count = 0;

  count = avail/sizeof (kd_threadmap);

  if (count && (count <= kd_mapcount))
    {
      if((kdebug_flags & KDBG_MAPINIT) && kd_mapsize && kd_mapptr)
	{
	  if (*number < kd_mapsize)
	    ret=EINVAL;
	  else
	    {
	      if (copyout(kd_mapptr, buffer, kd_mapsize))
		ret=EINVAL;
	    }
	}
      else
	ret=EINVAL;
    }
  else
    ret=EINVAL;

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

  /* Enforce maximum entropy entries here if needed */

  /* allocate entropy buffer */
  if (kmem_alloc(kernel_map, &kd_entropy_buftomem,
		 (vm_size_t)kd_entropy_bufsize) == KERN_SUCCESS)
    {
      kd_entropy_buffer = (uint64_t *) kd_entropy_buftomem;
    }
  else
    {
      kd_entropy_buffer = (uint64_t *) 0;
      kd_entropy_count = 0;
      kd_entropy_indx = 0;
      return (EINVAL);
    }

  if (ms_timeout < 10)
    ms_timeout = 10;

  /* Enable entropy sampling */
  kdebug_enable |= KDEBUG_ENABLE_ENTROPY;
  kdebug_slowcheck |= SLOW_ENTROPY;

  ret = tsleep (kdbg_getentropy, PRIBIO | PCATCH, "kd_entropy", (ms_timeout/(1000/HZ)));

  /* Disable entropy sampling */
  kdebug_enable &= ~KDEBUG_ENABLE_ENTROPY;
  kdebug_slowcheck &= ~SLOW_ENTROPY;

  *number = 0;
  ret = 0;

  if (kd_entropy_indx > 0)
    {
      /* copyout the buffer */
      if (copyout(kd_entropy_buffer, buffer, kd_entropy_indx * sizeof(mach_timespec_t)))
	  ret = EINVAL;
      else
	  *number = kd_entropy_indx;
    }

  /* Always cleanup */
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
	 * We allow a maximum buffer size of 25% of either ram or max mapped address, whichever is smaller
	 * 'value' is the desired number of trace entries
	 */
        unsigned int max_entries = (sane_size/4) / sizeof(kd_buf);

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
kdbg_control(int *name, __unused u_int namelen, user_addr_t where, size_t *sizep)
{
        int ret=0;
	size_t size=*sizep;
	unsigned int value = name[1];
	kd_regtype kd_Reg;
	kbufinfo_t kd_bufinfo;
	pid_t curpid;
	struct proc *p, *curproc;


	kdbg_lock_init();

	if ( !(kdebug_flags & KDBG_LOCKINIT))
	        return(ENOMEM);

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
	        lck_mtx_unlock(kd_trace_mtx_sysctl);

		return(EINVAL);
	    }
	    kd_bufinfo.nkdbufs = nkdbufs;
	    kd_bufinfo.nkdthreads = kd_mapsize / sizeof(kd_threadmap);

	    if ( (kdebug_slowcheck & SLOW_NOLOG) )
	        kd_bufinfo.nolog = 1;
	    else
	        kd_bufinfo.nolog = 0;
	    kd_bufinfo.flags = kdebug_flags;
	    kd_bufinfo.bufid = global_state_pid;
	   
	    if (size >= sizeof(kd_bufinfo)) {
            /*
		     * Provide all the info we have
		    */
	        if (copyout (&kd_bufinfo, where, sizeof(kd_bufinfo))) {
		        lck_mtx_unlock(kd_trace_mtx_sysctl);

                return(EINVAL);
		    }
	    }
	    else {
	        /* 
		 	 * For backwards compatibility, only provide
		 	 * as much info as there is room for.
		 	 */
	        if (copyout (&kd_bufinfo, where, size)) {
		        lck_mtx_unlock(kd_trace_mtx_sysctl);

		        return(EINVAL);
		    }
	    }
	    lck_mtx_unlock(kd_trace_mtx_sysctl);

	    return(0);
	} else if (name[0] == KERN_KDGETENTROPY) {
	    if (kd_entropy_buffer)
	        ret = EBUSY;
	    else
	        ret = kdbg_getentropy(where, sizep, value);
	    lck_mtx_unlock(kd_trace_mtx_sysctl);

	    return (ret);
	}
	
	if ((curproc = current_proc()) != NULL)
	    curpid = curproc->p_pid;
	else {
	    lck_mtx_unlock(kd_trace_mtx_sysctl);

	    return (ESRCH);
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
	        lck_mtx_unlock(kd_trace_mtx_sysctl);

		return(EBUSY);
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
	        case KERN_KDENABLE:    /* used to enable or disable */
		  if (value)
		    {
		      /* enable only if buffer is initialized */
		      if (!(kdebug_flags & KDBG_BUFINIT))
			{
			  ret=EINVAL;
			  break;
			}
		      kdbg_mapinit();

		      kdebug_enable |= KDEBUG_ENABLE_TRACE;
		      kdebug_slowcheck &= ~SLOW_NOLOG;
		    }
		  else
		    {
		      kdebug_enable &= ~KDEBUG_ENABLE_TRACE;
		      kdebug_slowcheck |= SLOW_NOLOG;
		    }
		  break;
		case KERN_KDSETBUF:
			kdbg_set_nkdbufs(value);
			break;
		case KERN_KDSETUP:
			ret=kdbg_reinit();
			break;
		case KERN_KDREMOVE:
			kdbg_clear();
			break;
		case KERN_KDSETREG:
			if(size < sizeof(kd_regtype)) {
				ret=EINVAL;
				break;
			}
			if (copyin(where, &kd_Reg, sizeof(kd_regtype))) {
				ret= EINVAL;
				break;
			}
			ret = kdbg_setreg(&kd_Reg);
			break;
		case KERN_KDGETREG:
			if(size < sizeof(kd_regtype)) {
				ret = EINVAL;
				break;
			}
			ret = kdbg_getreg(&kd_Reg);
		 	if (copyout(&kd_Reg, where, sizeof(kd_regtype))){
				ret=EINVAL;
			}
			break;
		case KERN_KDREADTR:
			ret = kdbg_read(where, sizep);
			break;
		case KERN_KDPIDTR:
			if (size < sizeof(kd_regtype)) {
				ret = EINVAL;
				break;
			}
			if (copyin(where, &kd_Reg, sizeof(kd_regtype))) {
				ret= EINVAL;
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
				ret= EINVAL;
				break;
			}
			ret = kdbg_setpidex(&kd_Reg);
			break;
	        case KERN_KDTHRMAP:
		        ret = kdbg_readmap(where, sizep);
		        break;
        	case KERN_KDSETRTCDEC:
			if (size < sizeof(kd_regtype)) {
				ret = EINVAL;
				break;
			}
			if (copyin(where, &kd_Reg, sizeof(kd_regtype))) {
				ret= EINVAL;
				break;
			}
			ret = kdbg_setrtcdec(&kd_Reg);
			break;
		       
		default:
			ret= EINVAL;
	}
	lck_mtx_unlock(kd_trace_mtx_sysctl);

	return(ret);
}


/*
 * This code can run concurrently with kernel_debug_internal()
 * without the need of any locks, because all reads of kd_bufptr[i],
 * which get modified by kernel_debug_internal(), are safe.
 */
int
kdbg_read(user_addr_t buffer, size_t *number)
{
	unsigned int count;
	unsigned int cpu;
	int mincpu;
	uint64_t  mintime, t, last_wrap_time;
	int last_wrap_cpu;
	int error = 0;
	kd_buf *tempbuf;
	uint32_t tempbuf_count;
	uint32_t tempbuf_number;
	unsigned int old_kdebug_flags, new_kdebug_flags;
	unsigned int old_kdebug_slowcheck, new_kdebug_slowcheck;
	boolean_t first_event = TRUE;

	count = *number/sizeof(kd_buf);
	*number = 0;

	if (count == 0 || !(kdebug_flags & KDBG_BUFINIT) || kdcopybuf == 0)
		return EINVAL;

	/*
	 * because we hold kd_trace_mtx_sysctl, no other control threads can 
	 * be playing with kdebug_flags... the code that cuts new events could
	 * be running, but it only reads kdebug_flags, it doesn't write it..
	 * use an OSCompareAndSwap to make sure the other processors see the 
	 * change of state immediately, not to protect against 2 threads racing to update it
	 */
	old_kdebug_slowcheck = kdebug_slowcheck;
	do {
	        old_kdebug_flags = kdebug_flags;
		new_kdebug_flags = old_kdebug_flags & ~KDBG_WRAPPED;
		new_kdebug_flags |= KDBG_NOWRAP;
	} while ( !OSCompareAndSwap((UInt32)old_kdebug_flags, (UInt32)new_kdebug_flags, (UInt32 *)&kdebug_flags));

	last_wrap_time = 0;
	last_wrap_cpu  = -1;

	for (cpu = 0; cpu < kd_cpus; cpu++) {
	        kd_buf *cur_bufptr;
		
		if ((cur_bufptr = kdbip[cpu].kd_bufptr) >= kdbip[cpu].kd_buflast)
		        cur_bufptr = kdbip[cpu].kd_buffer;

		if (kdbip[cpu].kd_wrapped) {
		        kdbip[cpu].kd_wrapped = 0;
			kdbip[cpu].kd_readlast = cur_bufptr;
			kdbip[cpu].kd_stop = cur_bufptr;

			if (kd_cpus > 1 && ((cur_bufptr->timestamp & KDBG_TIMESTAMP_MASK) > last_wrap_time)) {
			        last_wrap_time = cur_bufptr->timestamp & KDBG_TIMESTAMP_MASK;
				last_wrap_cpu = cpu;
			}
		} else {
		        if (kdbip[cpu].kd_readlast == cur_bufptr)
			        kdbip[cpu].kd_stop = 0;
			else
			        kdbip[cpu].kd_stop = cur_bufptr;
		}
	}
	if (count > nkdbufs)
		count = nkdbufs;

	if ((tempbuf_count = count) > KDCOPYBUF_COUNT)
	        tempbuf_count = KDCOPYBUF_COUNT;

	if (last_wrap_cpu == -1)
	        first_event = FALSE;

	while (count) {
	        tempbuf = kdcopybuf;
		tempbuf_number = 0;

	        while (tempbuf_count) {
			mintime = 0xffffffffffffffffULL; /* all actual timestamps are below */
			mincpu = -1;

			for (cpu = 0; cpu < kd_cpus; cpu++) {
			        if (kdbip[cpu].kd_stop == 0)     /* empty buffer */
				        continue;
				t = kdbip[cpu].kd_readlast[0].timestamp & KDBG_TIMESTAMP_MASK;

				if (t < mintime) {
				        mintime = t;
					mincpu = cpu;
				}
			}
			if (mincpu < 0)
			        /*
				 * all buffers ran empty early
				 */
			        break;

                        if (first_event == TRUE) {
			        /*
				 * make sure we leave room for the
				 * LAST_WRAPPER event we inject
				 * by throwing away the first event
				 * it's better to lose that one
				 * than the last one
				 */	
			        first_event = FALSE;

				kdbip[mincpu].kd_readlast++;

				if (kdbip[mincpu].kd_readlast == kdbip[mincpu].kd_buflast)
				        kdbip[mincpu].kd_readlast = kdbip[mincpu].kd_buffer;
				if (kdbip[mincpu].kd_readlast == kdbip[mincpu].kd_stop)
				        kdbip[mincpu].kd_stop = 0;

				continue;
			}
			if (last_wrap_cpu == mincpu) {
			        tempbuf->debugid = MISCDBG_CODE(DBG_BUFFER, 0) | DBG_FUNC_NONE;
				tempbuf->arg1 = kd_bufsize / sizeof(kd_buf);
				tempbuf->arg2 = kd_cpus;
				tempbuf->arg3 = 0;
				tempbuf->arg4 = 0;
				tempbuf->arg5 = (int)current_thread();
	          
				tempbuf->timestamp = last_wrap_time | (((uint64_t)last_wrap_cpu) << KDBG_CPU_SHIFT);

			        tempbuf++;

				last_wrap_cpu = -1;

			} else {
			        *(tempbuf++) = kdbip[mincpu].kd_readlast[0];

				kdbip[mincpu].kd_readlast++;

				if (kdbip[mincpu].kd_readlast == kdbip[mincpu].kd_buflast)
				        kdbip[mincpu].kd_readlast = kdbip[mincpu].kd_buffer;
				if (kdbip[mincpu].kd_readlast == kdbip[mincpu].kd_stop)
				        kdbip[mincpu].kd_stop = 0;
			}
			tempbuf_count--;
			tempbuf_number++;
		}
		if (tempbuf_number) {
		        if ((error = copyout(kdcopybuf, buffer, tempbuf_number * sizeof(kd_buf)))) {
			        *number = 0;
				error = EINVAL;
				break;
			}
			count   -= tempbuf_number;
			*number += tempbuf_number;
			buffer  += (tempbuf_number * sizeof(kd_buf));
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
	        do {
		        old_kdebug_flags = kdebug_flags;
			new_kdebug_flags = old_kdebug_flags & ~KDBG_NOWRAP;
		} while ( !OSCompareAndSwap((UInt32)old_kdebug_flags, (UInt32)new_kdebug_flags, (UInt32 *)&kdebug_flags));

		if ( !(old_kdebug_slowcheck & SLOW_NOLOG)) {
		        do {
			        old_kdebug_slowcheck = kdebug_slowcheck;
				new_kdebug_slowcheck = old_kdebug_slowcheck & ~SLOW_NOLOG;
			} while ( !OSCompareAndSwap((UInt32)old_kdebug_slowcheck, (UInt32)new_kdebug_slowcheck, (UInt32 *)&kdebug_slowcheck));
		}
	}
	return (error);
}


unsigned char *getProcName(struct proc *proc);
unsigned char *getProcName(struct proc *proc) {

	return (unsigned char *) &proc->p_comm;	/* Return pointer to the proc name */

}

#define STACKSHOT_SUBSYS_LOCK() lck_mtx_lock(&stackshot_subsys_mutex)
#define STACKSHOT_SUBSYS_UNLOCK() lck_mtx_unlock(&stackshot_subsys_mutex)
#ifdef __i386__
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
stack_snapshot(struct proc *p, register struct stack_snapshot_args *uap, register_t *retval) {
	int error = 0;

	if ((error = suser(kauth_cred_get(), &p->p_acflag)))
                return(error);

	return stack_snapshot2(uap->pid, uap->tracebuf, uap->tracebuf_size,
	    uap->options, retval);
}

int
stack_snapshot2(pid_t pid, user_addr_t tracebuf, uint32_t tracebuf_size, uint32_t options, register_t *retval)
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
	kdp_snapshot_preflight(pid, stackshot_snapbuf, tracebuf_size, options);

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
	printf("kernel tracing started\n");
}
