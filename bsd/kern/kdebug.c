/*
 * Copyright (c) 2000-2004 Apple Computer, Inc. All rights reserved.
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
 * @APPLE_LICENSE_HEADER_END@
 */

#include <machine/spl.h>

#include <sys/errno.h>
#include <sys/param.h>
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
#include <vm/vm_kern.h>
#include <sys/lock.h>

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

/* kd_buf kd_buffer[kd_bufsize/sizeof(kd_buf)]; */
kd_buf * kd_bufptr;
unsigned int kd_buftomem=0;
kd_buf * kd_buffer=0;
kd_buf * kd_buflast;
kd_buf * kd_readlast;
unsigned int nkdbufs = 8192;
unsigned int kd_bufsize = 0;
unsigned int kdebug_flags = 0;
unsigned int kdlog_beg=0;
unsigned int kdlog_end=0;
unsigned int kdlog_value1=0;
unsigned int kdlog_value2=0;
unsigned int kdlog_value3=0;
unsigned int kdlog_value4=0;

unsigned long long kd_prev_timebase = 0LL;

static lck_mtx_t  * kd_trace_mtx;
static lck_grp_t  * kd_trace_mtx_grp;
static lck_attr_t * kd_trace_mtx_attr;
static lck_grp_attr_t   *kd_trace_mtx_grp_attr;

static lck_spin_t * kd_trace_lock;
static lck_grp_t  * kd_trace_lock_grp;
static lck_attr_t * kd_trace_lock_attr;
static lck_grp_attr_t   *kd_trace_lock_grp_attr;

kd_threadmap *kd_mapptr = 0;
unsigned int kd_mapsize = 0;
unsigned int kd_mapcount = 0;
unsigned int kd_maptomem = 0;

pid_t global_state_pid = -1;       /* Used to control exclusive use of kd_buffer */

#define DBG_FUNC_MASK 0xfffffffc

#ifdef ppc
extern natural_t rtclock_decrementer_min;
#endif /* ppc */

/* task to string structure */
struct tts
{
  task_t   *task;            /* from procs task */
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


/* Support syscall SYS_kdebug_trace */
kdebug_trace(p, uap, retval)
     struct proc *p;
     struct kdebug_trace_args *uap;
     register_t *retval;
{
    if ( (kdebug_enable == 0) )
        return(EINVAL);
  
    kernel_debug(uap->code, uap->arg1, uap->arg2, uap->arg3, uap->arg4, 0);
    return(0);
}


void
kernel_debug(debugid, arg1, arg2, arg3, arg4, arg5)
unsigned int debugid, arg1, arg2, arg3, arg4, arg5;
{
	kd_buf * kd;
	struct proc *curproc;
	int      s;
	unsigned long long now;


	if (kdebug_enable & KDEBUG_ENABLE_CHUD) {
	    if (kdebug_chudhook)
	        kdebug_chudhook(debugid, arg1, arg2, arg3, arg4, arg5);

	    if ( !(kdebug_enable & (KDEBUG_ENABLE_ENTROPY | KDEBUG_ENABLE_TRACE)))
	        return;
	}
	s = ml_set_interrupts_enabled(FALSE);
	lck_spin_lock(kd_trace_lock);

	if (kdebug_slowcheck == 0)
	    goto record_trace;

	if (kdebug_enable & KDEBUG_ENABLE_ENTROPY)
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
	  {
	    lck_spin_unlock(kd_trace_lock);
	    ml_set_interrupts_enabled(s);
	    return;
	  }
	
	if (kdebug_flags & KDBG_PIDCHECK)
	  {
	    /* If kdebug flag is not set for current proc, return  */
	    curproc = current_proc();
	    if ((curproc && !(curproc->p_flag & P_KDEBUG)) &&
		((debugid&0xffff0000) != (MACHDBG_CODE(DBG_MACH_SCHED, 0) | DBG_FUNC_NONE)))
	      {
		lck_spin_unlock(kd_trace_lock);
		ml_set_interrupts_enabled(s);
		return;
	      }
	  }
	else if (kdebug_flags & KDBG_PIDEXCLUDE)
	  {
	    /* If kdebug flag is set for current proc, return  */
	    curproc = current_proc();
	    if ((curproc && (curproc->p_flag & P_KDEBUG)) &&
		((debugid&0xffff0000) != (MACHDBG_CODE(DBG_MACH_SCHED, 0) | DBG_FUNC_NONE)))
	      {
		lck_spin_unlock(kd_trace_lock);
		ml_set_interrupts_enabled(s);
		return;
	      }
	  }

	if (kdebug_flags & KDBG_RANGECHECK)
	  {
	    if ((debugid < kdlog_beg) || (debugid >= kdlog_end) 
		&& (debugid >> 24 != DBG_TRACE))
	      {
		lck_spin_unlock(kd_trace_lock);
		ml_set_interrupts_enabled(s);
		return;
	      }
	  }
	else if (kdebug_flags & KDBG_VALCHECK)
	  {
	    if ((debugid & DBG_FUNC_MASK) != kdlog_value1 &&
		(debugid & DBG_FUNC_MASK) != kdlog_value2 &&
		(debugid & DBG_FUNC_MASK) != kdlog_value3 &&
		(debugid & DBG_FUNC_MASK) != kdlog_value4 &&
		(debugid >> 24 != DBG_TRACE))
	      {
		lck_spin_unlock(kd_trace_lock);
		ml_set_interrupts_enabled(s);
		return;
	      }
	  }

record_trace:
	kd = kd_bufptr;
	kd->debugid = debugid;
	kd->arg1 = arg1;
	kd->arg2 = arg2;
	kd->arg3 = arg3;
	kd->arg4 = arg4;
	kd->arg5 = (int)current_thread();
	          
	now = mach_absolute_time() & KDBG_TIMESTAMP_MASK;

	/* Watch for out of order timestamps */	

	if (now < kd_prev_timebase)
	  {
	    now = ++kd_prev_timebase & KDBG_TIMESTAMP_MASK;
	  }
	else
	  {
	    /* Then just store the previous timestamp */
	    kd_prev_timebase = now;
	  }
	kd->timestamp = now | (((uint64_t)cpu_number()) << KDBG_CPU_SHIFT);

	kd_bufptr++;

	if (kd_bufptr >= kd_buflast)
	  	kd_bufptr = kd_buffer;
	if (kd_bufptr == kd_readlast) {
	        if (kdebug_flags & KDBG_NOWRAP)
			kdebug_slowcheck |= SLOW_NOLOG;
		kdebug_flags |= KDBG_WRAPPED;
	}
	lck_spin_unlock(kd_trace_lock);
	ml_set_interrupts_enabled(s);
}

void
kernel_debug1(debugid, arg1, arg2, arg3, arg4, arg5)
unsigned int debugid, arg1, arg2, arg3, arg4, arg5;
{
	kd_buf * kd;
	struct proc *curproc;
	int      s;
	unsigned long long now;

	if (kdebug_enable & KDEBUG_ENABLE_CHUD) {
	    if (kdebug_chudhook)
	        (void)kdebug_chudhook(debugid, arg1, arg2, arg3, arg4, arg5);

	    if ( !(kdebug_enable & (KDEBUG_ENABLE_ENTROPY | KDEBUG_ENABLE_TRACE)))
	        return;
	}
	s = ml_set_interrupts_enabled(FALSE);
	lck_spin_lock(kd_trace_lock);

	if (kdebug_slowcheck == 0)
	    goto record_trace1;

	if ( (kdebug_slowcheck & SLOW_NOLOG) )
	  {
	    lck_spin_unlock(kd_trace_lock);
	    ml_set_interrupts_enabled(s);
	    return;
	  }

	if (kdebug_flags & KDBG_PIDCHECK)
	  {
	    /* If kdebug flag is not set for current proc, return  */
	    curproc = current_proc();
	    if ((curproc && !(curproc->p_flag & P_KDEBUG)) &&
		((debugid&0xffff0000) != (MACHDBG_CODE(DBG_MACH_SCHED, 0) | DBG_FUNC_NONE)))
	      {
		lck_spin_unlock(kd_trace_lock);
	        ml_set_interrupts_enabled(s);
		return;
	      }
	  }
	else if (kdebug_flags & KDBG_PIDEXCLUDE)
	  {
	    /* If kdebug flag is set for current proc, return  */
	    curproc = current_proc();
	    if ((curproc && (curproc->p_flag & P_KDEBUG)) &&
		((debugid&0xffff0000) != (MACHDBG_CODE(DBG_MACH_SCHED, 0) | DBG_FUNC_NONE)))
	      {
		lck_spin_unlock(kd_trace_lock);
	        ml_set_interrupts_enabled(s);
		return;
	      }
	  }

	if (kdebug_flags & KDBG_RANGECHECK)
	  {
	    if ((debugid < kdlog_beg) || (debugid >= kdlog_end)
		&& (debugid >> 24 != DBG_TRACE))
	      {
		lck_spin_unlock(kd_trace_lock);
		ml_set_interrupts_enabled(s);
		return;
	      }
	  }
	else if (kdebug_flags & KDBG_VALCHECK)
	  {
	    if ((debugid & DBG_FUNC_MASK) != kdlog_value1 &&
		(debugid & DBG_FUNC_MASK) != kdlog_value2 &&
		(debugid & DBG_FUNC_MASK) != kdlog_value3 &&
		(debugid & DBG_FUNC_MASK) != kdlog_value4 &&
		(debugid >> 24 != DBG_TRACE))
	      {
		lck_spin_unlock(kd_trace_lock);
		ml_set_interrupts_enabled(s);
		return;
	      }
	  }

record_trace1:
	kd = kd_bufptr;
	kd->debugid = debugid;
	kd->arg1 = arg1;
	kd->arg2 = arg2;
	kd->arg3 = arg3;
	kd->arg4 = arg4;
	kd->arg5 = arg5;

	now = mach_absolute_time() & KDBG_TIMESTAMP_MASK;

	/* Watch for out of order timestamps */	

	if (now < kd_prev_timebase)
	  {
	    now = ++kd_prev_timebase & KDBG_TIMESTAMP_MASK;
	  }
	else
	  {
	    /* Then just store the previous timestamp */
	    kd_prev_timebase = now;
	  }
	kd->timestamp = now | (((uint64_t)cpu_number()) << KDBG_CPU_SHIFT);

	kd_bufptr++;

	if (kd_bufptr >= kd_buflast)
	  	kd_bufptr = kd_buffer;
	if (kd_bufptr == kd_readlast) {
	        if (kdebug_flags & KDBG_NOWRAP)
			kdebug_slowcheck |= SLOW_NOLOG;
		kdebug_flags |= KDBG_WRAPPED;
	}
	lck_spin_unlock(kd_trace_lock);
	ml_set_interrupts_enabled(s);
}


static void
kdbg_lock_init()
{

        if (kdebug_flags & KDBG_LOCKINIT)
                return;
        /*
	 * allocate lock group attribute and group
	 */
        kd_trace_lock_grp_attr = lck_grp_attr_alloc_init();
	//lck_grp_attr_setstat(kd_trace_lock_grp_attr);
	kd_trace_lock_grp = lck_grp_alloc_init("kdebug", kd_trace_lock_grp_attr);
		
        kd_trace_mtx_grp_attr = lck_grp_attr_alloc_init();
	//lck_grp_attr_setstat(kd_trace_mtx_grp_attr);
	kd_trace_mtx_grp = lck_grp_alloc_init("kdebug", kd_trace_mtx_grp_attr);
		
	/*
	 * allocate the lock attribute
	 */
	kd_trace_lock_attr = lck_attr_alloc_init();
	//lck_attr_setdebug(kd_trace_lock_attr);

	kd_trace_mtx_attr = lck_attr_alloc_init();
	//lck_attr_setdebug(kd_trace_mtx_attr);


	/*
	 * allocate and initialize spin lock and mutex
	 */
	kd_trace_lock  = lck_spin_alloc_init(kd_trace_lock_grp, kd_trace_lock_attr);
	kd_trace_mtx   = lck_mtx_alloc_init(kd_trace_mtx_grp, kd_trace_mtx_attr);

	kdebug_flags |= KDBG_LOCKINIT;
}


int
kdbg_bootstrap()
{

	kd_bufsize = nkdbufs * sizeof(kd_buf);

	if (kmem_alloc(kernel_map, &kd_buftomem,
			      (vm_size_t)kd_bufsize) == KERN_SUCCESS) 
	    kd_buffer = (kd_buf *) kd_buftomem;
	else
	    kd_buffer= (kd_buf *) 0;
	kdebug_flags &= ~KDBG_WRAPPED;

	if (kd_buffer) {
		kdebug_flags |= (KDBG_INIT | KDBG_BUFINIT);
		kd_bufptr = kd_buffer;
		kd_buflast = &kd_bufptr[nkdbufs];
		kd_readlast = kd_bufptr;
		kd_prev_timebase = 0LL;
		return(0);
	} else {
		kd_bufsize=0;
		kdebug_flags &= ~(KDBG_INIT | KDBG_BUFINIT);
		return(EINVAL);
	}
	
}

kdbg_reinit()
{
    int s;
    int ret=0;

    /*
     * Disable trace collecting
     * First make sure we're not in
     * the middle of cutting a trace
     */
    s = ml_set_interrupts_enabled(FALSE);
    lck_spin_lock(kd_trace_lock);

    kdebug_enable &= ~KDEBUG_ENABLE_TRACE;
    kdebug_slowcheck |= SLOW_NOLOG;

    lck_spin_unlock(kd_trace_lock);
    ml_set_interrupts_enabled(s);

    if ((kdebug_flags & KDBG_INIT) && (kdebug_flags & KDBG_BUFINIT) && kd_bufsize && kd_buffer)
        kmem_free(kernel_map, (vm_offset_t)kd_buffer, kd_bufsize);

    if ((kdebug_flags & KDBG_MAPINIT) && kd_mapsize && kd_mapptr)
      {
	kmem_free(kernel_map, (vm_offset_t)kd_mapptr, kd_mapsize);
	kdebug_flags &= ~KDBG_MAPINIT;
	kd_mapsize = 0;
	kd_mapptr = (kd_threadmap *) 0;
	kd_mapcount = 0;
      }  

    ret= kdbg_bootstrap();

    return(ret);
}

void kdbg_trace_data(struct proc *proc, long *arg_pid)
{
    if (!proc)
        *arg_pid = 0;
    else
	*arg_pid = proc->p_pid;
    
    return;
}


void kdbg_trace_string(struct proc *proc, long *arg1, long *arg2, long *arg3, long *arg4)
{
    int i;
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
  
    if(dbg_namelen > sizeof(dbg_parms))
      dbg_namelen = sizeof(dbg_parms);
    
    for(i=0;dbg_namelen > 0; i++)
      {
	dbg_parms[i]=*(long*)dbg_nameptr;
	dbg_nameptr += sizeof(long);
	dbg_namelen -= sizeof(long);
      }

    *arg1=dbg_parms[0];
    *arg2=dbg_parms[1];
    *arg3=dbg_parms[2];
    *arg4=dbg_parms[3];
}

static void
kdbg_resolve_map(thread_t th_act, krt_t *t)
{
  kd_threadmap *mapptr;

  if(t->count < t->maxcount)
    {
      mapptr=&t->map[t->count];
      mapptr->thread  = (unsigned int)th_act;
      (void) strncpy (mapptr->command, t->atts->task_comm,
		      sizeof(t->atts->task_comm)-1);
      mapptr->command[sizeof(t->atts->task_comm)-1] = '\0';

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

void kdbg_mapinit()
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

	/* Calculate the sizes of map buffers*/
	for (p = allproc.lh_first, kd_mapcount=0, tts_count=0; p; 
	     p = p->p_list.le_next)
	  {
	    kd_mapcount += get_task_numacts((task_t)p->task);
	    tts_count++;
	  }

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
	        for (p = allproc.lh_first, i=0; p && i < tts_count; 
		     p = p->p_list.le_next) {
	                if (p->p_flag & P_WEXIT)
		                continue;

			if (p->task) {
				task_reference(p->task);
				tts_mapptr[i].task = p->task;
				tts_mapptr[i].pid  = p->p_pid;
				(void)strncpy(&tts_mapptr[i].task_comm, p->p_comm, sizeof(tts_mapptr[i].task_comm) - 1);
				i++;
			}
		}
		tts_count = i;
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
        int s;

        /*
	 * Clean up the trace buffer
	 * First make sure we're not in
	 * the middle of cutting a trace
	 */
	s = ml_set_interrupts_enabled(FALSE);
	lck_spin_lock(kd_trace_lock);

	kdebug_enable &= ~KDEBUG_ENABLE_TRACE;
	kdebug_slowcheck = SLOW_NOLOG;

	if (kdebug_enable & KDEBUG_ENABLE_ENTROPY)
		kdebug_slowcheck |= SLOW_ENTROPY;

	lck_spin_unlock(kd_trace_lock);
	ml_set_interrupts_enabled(s);

        global_state_pid = -1;
	kdebug_flags &= ~KDBG_BUFINIT;
	kdebug_flags &= (unsigned int)~KDBG_CKTYPES;
	kdebug_flags &= ~(KDBG_NOWRAP | KDBG_RANGECHECK | KDBG_VALCHECK);
	kdebug_flags &= ~(KDBG_PIDCHECK | KDBG_PIDEXCLUDE);
	kmem_free(kernel_map, (vm_offset_t)kd_buffer, kd_bufsize);
	kd_buffer = (kd_buf *)0;
	kd_bufsize = 0;
	kd_prev_timebase = 0LL;

	/* Clean up the thread map buffer */
	kdebug_flags &= ~KDBG_MAPINIT;
	kmem_free(kernel_map, (vm_offset_t)kd_mapptr, kd_mapsize);
	kd_mapptr = (kd_threadmap *) 0;
	kd_mapsize = 0;
	kd_mapcount = 0;
}

kdbg_setpid(kd_regtype *kdr)
{
  pid_t pid;
  int flag, ret=0;
  struct proc *p;

  pid = (pid_t)kdr->value1;
  flag = (int)kdr->value2;

  if (pid > 0)
    {
      if ((p = pfind(pid)) == NULL)
	ret = ESRCH;
      else
	{
	  if (flag == 1)  /* turn on pid check for this and all pids */
	    {
	      kdebug_flags |= KDBG_PIDCHECK;
	      kdebug_flags &= ~KDBG_PIDEXCLUDE;
	      kdebug_slowcheck |= SLOW_CHECKS;

	      p->p_flag |= P_KDEBUG;
	    }
	  else  /* turn off pid check for this pid value */
	    {
	      /* Don't turn off all pid checking though */
	      /* kdebug_flags &= ~KDBG_PIDCHECK;*/   
	      p->p_flag &= ~P_KDEBUG;
	    }
	}
    }
  else
    ret = EINVAL;
  return(ret);
}

/* This is for pid exclusion in the trace buffer */
kdbg_setpidex(kd_regtype *kdr)
{
  pid_t pid;
  int flag, ret=0;
  struct proc *p;

  pid = (pid_t)kdr->value1;
  flag = (int)kdr->value2;

  if (pid > 0)
    {
      if ((p = pfind(pid)) == NULL)
	ret = ESRCH;
      else
	{
	  if (flag == 1)  /* turn on pid exclusion */
	    {
	      kdebug_flags |= KDBG_PIDEXCLUDE;
	      kdebug_flags &= ~KDBG_PIDCHECK;
	      kdebug_slowcheck |= SLOW_CHECKS;

	      p->p_flag |= P_KDEBUG;
	    }
	  else  /* turn off pid exclusion for this pid value */
	    {
	      /* Don't turn off all pid exclusion though */
	      /* kdebug_flags &= ~KDBG_PIDEXCLUDE;*/   
	      p->p_flag &= ~P_KDEBUG;
	    }
	}
    }
  else
    ret = EINVAL;
  return(ret);
}

/* This is for setting a minimum decrementer value */
kdbg_setrtcdec(kd_regtype *kdr)
{
  int ret=0;
  natural_t decval;

  decval = (natural_t)kdr->value1;

  if (decval && decval < KDBG_MINRTCDEC)
      ret = EINVAL;
#ifdef ppc
  else
      rtclock_decrementer_min = decval;
#else
  else
    ret = ENOTSUP;
#endif /* ppc */

  return(ret);
}

kdbg_setreg(kd_regtype * kdr)
{
	int i,j, ret=0;
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

kdbg_getreg(kd_regtype * kdr)
{
	int i,j, ret=0;
	unsigned int val_1, val_2, val;
#if 0	
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
  int count = 0;

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
  int count = 0;     /* The number of timestamp entries that will fill buffer */

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


/*
 * This function is provided for the CHUD toolkit only.
 *    int val:
 *        zero disables kdebug_chudhook function call
 *        non-zero enables kdebug_chudhook function call
 *    char *fn:
 *        address of the enabled kdebug_chudhook function
*/

void kdbg_control_chud(int val, void *fn)
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

	
kdbg_control(int *name, u_int namelen, user_addr_t where, size_t *sizep)
{
    int ret=0;
	int size=*sizep;
	int max_entries;
	unsigned int value = name[1];
	kd_regtype kd_Reg;
	kbufinfo_t kd_bufinfo;
	pid_t curpid;
	struct proc *p, *curproc;


	kdbg_lock_init();
	lck_mtx_lock(kd_trace_mtx);

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
	        lck_mtx_unlock(kd_trace_mtx);

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
		        lck_mtx_unlock(kd_trace_mtx);

                return(EINVAL);
		    }
	    }
	    else {
	        /* 
		 	 * For backwards compatibility, only provide
		 	 * as much info as there is room for.
		 	 */
	        if (copyout (&kd_bufinfo, where, size)) {
		        lck_mtx_unlock(kd_trace_mtx);

		        return(EINVAL);
		    }
	    }
	    lck_mtx_unlock(kd_trace_mtx);

	    return(0);
	} else if (name[0] == KERN_KDGETENTROPY) {
	    if (kd_entropy_buffer)
	        ret = EBUSY;
	    else
	        ret = kdbg_getentropy(where, sizep, value);
	    lck_mtx_unlock(kd_trace_mtx);

	    return (ret);
	}
	
	if (curproc = current_proc())
	    curpid = curproc->p_pid;
	else {
	    lck_mtx_unlock(kd_trace_mtx);

	    return (ESRCH);
	}
        if (global_state_pid == -1)
	    global_state_pid = curpid;
	else if (global_state_pid != curpid) {
	    if ((p = pfind(global_state_pid)) == NULL) {
	        /*
		 * The global pid no longer exists
		 */
	        global_state_pid = curpid;
	    } else {
	        /*
		 * The global pid exists, deny this request
		 */
	        lck_mtx_unlock(kd_trace_mtx);

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
		      kdebug_enable |= KDEBUG_ENABLE_TRACE;
		      kdebug_slowcheck &= ~SLOW_NOLOG;
		    }
		  else
		    {
		      kdebug_enable &= ~KDEBUG_ENABLE_TRACE;
		      kdebug_slowcheck |= SLOW_NOLOG;
		    }
		  kdbg_mapinit();
		  break;
		case KERN_KDSETBUF:
		  /* We allow a maximum buffer size of 25% of either ram or max mapped address, whichever is smaller */
		  /* 'value' is the desired number of trace entries */
		        max_entries = (sane_size/4) / sizeof(kd_buf);
			if (value <= max_entries)
				nkdbufs = value;
			else
			  nkdbufs = max_entries;
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
	lck_mtx_unlock(kd_trace_mtx);

	return(ret);
}

kdbg_read(user_addr_t buffer, size_t *number)
{
int avail=*number;
int count=0;
int copycount=0;
int totalcount=0;
int s;
unsigned int my_kdebug_flags;
kd_buf * my_kd_bufptr;

	s = ml_set_interrupts_enabled(FALSE);
	lck_spin_lock(kd_trace_lock);

	my_kdebug_flags = kdebug_flags;
	my_kd_bufptr = kd_bufptr;

	lck_spin_unlock(kd_trace_lock);
	ml_set_interrupts_enabled(s);

	count = avail/sizeof(kd_buf);

	if (count) {
		if ((my_kdebug_flags & KDBG_BUFINIT) && kd_bufsize && kd_buffer) {
			if (count > nkdbufs)
			        count = nkdbufs;
			
			if (!(my_kdebug_flags & KDBG_WRAPPED)) {
			        if (my_kd_bufptr == kd_readlast) {
				        *number = 0;
					return(0);
				}	
				if (my_kd_bufptr > kd_readlast) {
				        copycount = my_kd_bufptr - kd_readlast;
					if (copycount > count)
					        copycount = count;

					if (copyout(kd_readlast, buffer, copycount * sizeof(kd_buf))) {
					        *number = 0;
						return(EINVAL);
					}
					kd_readlast += copycount;
					*number = copycount;
					return(0);
				}
			}
			if ( (my_kdebug_flags & KDBG_WRAPPED) ) {
			        /* Note that by setting kd_readlast equal to my_kd_bufptr,
				 * we now treat the kd_buffer read the same as if we weren't
				 * wrapped and my_kd_bufptr was less than kd_readlast.
				 */
			        kd_readlast = my_kd_bufptr;
				kdebug_flags &= ~KDBG_WRAPPED;
			}
			/*
			 * first copyout from readlast to end of kd_buffer
			 */
			copycount = kd_buflast - kd_readlast;
			if (copycount > count)
			        copycount = count;
			if (copyout(kd_readlast, buffer, copycount * sizeof(kd_buf))) {
			        *number = 0;
				return(EINVAL);
			}
			buffer += (copycount * sizeof(kd_buf));
			count -= copycount;
			totalcount = copycount;
			kd_readlast += copycount;

			if (kd_readlast == kd_buflast)
			        kd_readlast = kd_buffer;
			if (count == 0) {
				*number = totalcount;
				return(0);
			}
			/* second copyout from top of kd_buffer to bufptr */
			copycount = my_kd_bufptr - kd_readlast;
			if (copycount > count)
			        copycount = count;
			if (copycount == 0) {
				*number = totalcount;
				return(0);
			}
			if (copyout(kd_readlast, buffer, copycount * sizeof(kd_buf)))
				return(EINVAL);

			kd_readlast += copycount;
			totalcount += copycount;
			*number = totalcount;
			return(0);

		} /* end if KDBG_BUFINIT */		
	} /* end if count */
	return (EINVAL);
}

unsigned char *getProcName(struct proc *proc);
unsigned char *getProcName(struct proc *proc) {

	return (unsigned char *) &proc->p_comm;	/* Return pointer to the proc name */

}
