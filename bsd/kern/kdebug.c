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

#include <machine/spl.h>

#define HZ      100
#include <mach/clock_types.h>
#include <mach/mach_types.h>
#include <machine/machine_routines.h>

#include <sys/kdebug.h>
#include <sys/errno.h>
#include <sys/param.h>
#include <sys/proc.h>
#include <sys/vm.h>
#include <sys/sysctl.h>

#include <kern/thread.h>
#include <kern/task.h>
#include <vm/vm_kern.h>
#include <sys/lock.h>

/* kd_buf kd_buffer[kd_bufsize/sizeof(kd_buf)]; */
kd_buf * kd_bufptr;
unsigned int kd_buftomem=0;
kd_buf * kd_buffer=0;
kd_buf * kd_buflast;
kd_buf * kd_readlast;
unsigned int nkdbufs = 8192;
unsigned int kd_bufsize = 0;
unsigned int kdebug_flags = 0;
unsigned int kdebug_enable=0;
unsigned int kdebug_nolog=1;
unsigned int kdlog_beg=0;
unsigned int kdlog_end=0;
unsigned int kdlog_value1=0;
unsigned int kdlog_value2=0;
unsigned int kdlog_value3=0;
unsigned int kdlog_value4=0;

unsigned long long kd_prev_timebase = 0LL;
decl_simple_lock_data(,kd_trace_lock);

kd_threadmap *kd_mapptr = 0;
unsigned int kd_mapsize = 0;
unsigned int kd_mapcount = 0;
unsigned int kd_maptomem = 0;

pid_t global_state_pid = -1;       /* Used to control exclusive use of kd_buffer */

#define DBG_FUNC_MASK 0xfffffffc

#ifdef ppc
extern natural_t rtclock_decrementer_min;
#endif /* ppc */

struct kdebug_args {
  int code;
  int arg1;
  int arg2;
  int arg3;
  int arg4;
  int arg5;
};

struct krt
{
  kd_threadmap *map;    /* pointer to the map buffer */
  int count;
  int maxcount;
  struct proc *p;
};

typedef struct krt krt_t;

/* Support syscall SYS_kdebug_trace */
kdebug_trace(p, uap, retval)
     struct proc *p;
     struct kdebug_args *uap;
     register_t *retval;
{
  if (kdebug_nolog)
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
	mach_timespec_t *tsp;

	s = ml_set_interrupts_enabled(FALSE);

	if (kdebug_nolog)
	  {
	    ml_set_interrupts_enabled(s);
	    return;
	  }

	simple_lock(&kd_trace_lock);
	if (kdebug_flags & KDBG_PIDCHECK)
	  {
	    /* If kdebug flag is not set for current proc, return  */
	    curproc = current_proc();
	    if ((curproc && !(curproc->p_flag & P_KDEBUG)) &&
		((debugid&0xffff0000) != (MACHDBG_CODE(DBG_MACH_SCHED, 0) | DBG_FUNC_NONE)))
	      {
		simple_unlock(&kd_trace_lock);
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
		simple_unlock(&kd_trace_lock);
		ml_set_interrupts_enabled(s);
		return;
	      }
	  }

	if (kdebug_flags & KDBG_RANGECHECK)
	  {
	    if ((debugid < kdlog_beg) || (debugid > kdlog_end) 
		&& (debugid >> 24 != DBG_TRACE))
	      {
		simple_unlock(&kd_trace_lock);
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
		simple_unlock(&kd_trace_lock);
		ml_set_interrupts_enabled(s);
		return;
	      }
	  }
	kd = kd_bufptr;
	kd->debugid = debugid;
	kd->arg1 = arg1;
	kd->arg2 = arg2;
	kd->arg3 = arg3;
	kd->arg4 = arg4;
	kd->arg5 = (int)current_thread();
        if (cpu_number())
            kd->arg5 |= KDBG_CPU_MASK;
	          
	ml_get_timebase((unsigned long long *)&kd->timestamp);

	/* Watch for out of order timestamps */	
	now = (((unsigned long long)kd->timestamp.tv_sec) << 32) |
	  (unsigned long long)((unsigned int)(kd->timestamp.tv_nsec));

	if (now < kd_prev_timebase)
	  {
	    /* timestamps are out of order -- adjust */
	    kd_prev_timebase++;
	    tsp = (mach_timespec_t *)&kd_prev_timebase;
	    kd->timestamp.tv_sec =  tsp->tv_sec;
	    kd->timestamp.tv_nsec = tsp->tv_nsec;
	  }
	else
	  {
	    /* Then just store the previous timestamp */
	    kd_prev_timebase = now;
	  }


	kd_bufptr++;

	if (kd_bufptr >= kd_buflast)
	  	kd_bufptr = kd_buffer;
	if (kd_bufptr == kd_readlast) {
	        if (kdebug_flags & KDBG_NOWRAP)
			kdebug_nolog = 1;
		kdebug_flags |= KDBG_WRAPPED;
	}
	simple_unlock(&kd_trace_lock);
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
	mach_timespec_t *tsp;

	s = ml_set_interrupts_enabled(FALSE);

	if (kdebug_nolog)
	  {
	    ml_set_interrupts_enabled(s);
	    return;
	  }

	simple_lock(&kd_trace_lock);
	if (kdebug_flags & KDBG_PIDCHECK)
	  {
	    /* If kdebug flag is not set for current proc, return  */
	    curproc = current_proc();
	    if ((curproc && !(curproc->p_flag & P_KDEBUG)) &&
		((debugid&0xffff0000) != (MACHDBG_CODE(DBG_MACH_SCHED, 0) | DBG_FUNC_NONE)))
	      {
		simple_unlock(&kd_trace_lock);
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
		simple_unlock(&kd_trace_lock);
	        ml_set_interrupts_enabled(s);
		return;
	      }
	  }

	if (kdebug_flags & KDBG_RANGECHECK)
	  {
	    if ((debugid < kdlog_beg) || (debugid > kdlog_end)
		&& (debugid >> 24 != DBG_TRACE))
	      {
		simple_unlock(&kd_trace_lock);
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
		simple_unlock(&kd_trace_lock);
		ml_set_interrupts_enabled(s);
		return;
	      }
	  }

	kd = kd_bufptr;
	kd->debugid = debugid;
	kd->arg1 = arg1;
	kd->arg2 = arg2;
	kd->arg3 = arg3;
	kd->arg4 = arg4;
	kd->arg5 = arg5;
	ml_get_timebase((unsigned long long *)&kd->timestamp);

	/* Watch for out of order timestamps */	
	now = (((unsigned long long)kd->timestamp.tv_sec) << 32) |
	  (unsigned long long)((unsigned int)(kd->timestamp.tv_nsec));

	if (now < kd_prev_timebase)
	  {
	    /* timestamps are out of order -- adjust */
	    kd_prev_timebase++;
	    tsp = (mach_timespec_t *)&kd_prev_timebase;
	    kd->timestamp.tv_sec =  tsp->tv_sec;
	    kd->timestamp.tv_nsec = tsp->tv_nsec;
	  }
	else
	  {
	    /* Then just store the previous timestamp */
	    kd_prev_timebase = now;
	  }

	kd_bufptr++;

	if (kd_bufptr >= kd_buflast)
	  	kd_bufptr = kd_buffer;
	if (kd_bufptr == kd_readlast) {
	        if (kdebug_flags & KDBG_NOWRAP)
			kdebug_nolog = 1;
		kdebug_flags |= KDBG_WRAPPED;
	}
	simple_unlock(&kd_trace_lock);
	ml_set_interrupts_enabled(s);
}


kdbg_bootstrap()
{
	kd_bufsize = nkdbufs * sizeof(kd_buf);
	if (kmem_alloc(kernel_map, &kd_buftomem,
			      (vm_size_t)kd_bufsize) == KERN_SUCCESS) 
	kd_buffer = (kd_buf *) kd_buftomem;
	else kd_buffer= (kd_buf *) 0;
	kdebug_flags &= ~KDBG_WRAPPED;
	if (kd_buffer) {
	        simple_lock_init(&kd_trace_lock);
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
    int x;
    int ret=0;

    kdebug_enable = 0;
    kdebug_nolog = 1;

    if ((kdebug_flags & KDBG_INIT) && (kdebug_flags & KDBG_BUFINIT) && kd_bufsize && kd_buffer)
        kmem_free(kernel_map, (char *)kd_buffer, kd_bufsize);

    if ((kdebug_flags & KDBG_MAPINIT) && kd_mapsize && kd_mapptr)
      {
	kmem_free(kernel_map, (char *)kd_mapptr, kd_mapsize);
	kdebug_flags &= ~KDBG_MAPINIT;
	kd_mapsize = 0;
	kd_mapptr = (kd_threadmap *) 0;
	kd_mapcount = 0;
      }  

    ret= kdbg_bootstrap();

    return(ret);
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

kdbg_resolve_map(thread_act_t th_act, krt_t *t)
{
  kd_threadmap *mapptr;

  if(t->count < t->maxcount)
    {
      mapptr=&t->map[t->count];
      mapptr->thread  = (unsigned int)getshuttle_thread(th_act);
      mapptr->valid = 1;
      (void) strncpy (mapptr->command, t->p->p_comm,
		      sizeof(t->p->p_comm)-1);
      mapptr->command[sizeof(t->p->p_comm)-1] = '\0';
      t->count++;
    }
}

void kdbg_mapinit()
{
	struct proc *p;
	struct krt akrt;

        if (kdebug_flags & KDBG_MAPINIT)
	  return;

	/* Calculate size of thread map buffer */
	for (p = allproc.lh_first, kd_mapcount=0; p; 
	     p = p->p_list.le_next)
	  {
	    kd_mapcount += get_task_numacts((task_t)p->task);
	  }

	kd_mapsize = kd_mapcount * sizeof(kd_threadmap);
	if((kmem_alloc(kernel_map, & kd_maptomem,
		       (vm_size_t)kd_mapsize) == KERN_SUCCESS))
	    kd_mapptr = (kd_threadmap *) kd_maptomem;
	else
	    kd_mapptr = (kd_threadmap *) 0;

	if (kd_mapptr)
	  {
	    kdebug_flags |= KDBG_MAPINIT;
	    /* Initialize thread map data */
	    akrt.map = kd_mapptr;
	    akrt.count = 0;
	    akrt.maxcount = kd_mapcount;
	    
	    for (p = allproc.lh_first; p; p = p->p_list.le_next)
	      {
		akrt.p = p;
		task_act_iterate_wth_args((task_t)p->task, kdbg_resolve_map, &akrt);
	      }	    
	  }
}

kdbg_clear()
{
int x;

        /* Clean up the trace buffer */ 
        global_state_pid = -1;
	kdebug_enable = 0;
	kdebug_nolog = 1;
	kdebug_flags &= ~KDBG_BUFINIT;
	kdebug_flags &= (unsigned int)~KDBG_CKTYPES;
	kdebug_flags &= ~(KDBG_NOWRAP | KDBG_RANGECHECK | KDBG_VALCHECK);
	kdebug_flags &= ~(KDBG_PIDCHECK | KDBG_PIDEXCLUDE);
	kmem_free(kernel_map, (char *)kd_buffer, kd_bufsize);
	kd_buffer = (kd_buf *)0;
	kd_bufsize = 0;
	kd_prev_timebase = 0LL;

	/* Clean up the thread map buffer */
	kdebug_flags &= ~KDBG_MAPINIT;
	kmem_free(kernel_map, (char *)kd_mapptr, kd_mapsize);
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
    ret = EOPNOTSUPP;
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
		break;
	case KDBG_RANGETYPE :
		kdlog_beg = (kdr->value1);
		kdlog_end = (kdr->value2);
		kdebug_flags &= (unsigned int)~KDBG_CKTYPES;
		kdebug_flags &= ~KDBG_VALCHECK;       /* Turn off specific value check  */
		kdebug_flags |= (KDBG_RANGECHECK | KDBG_RANGETYPE);
		break;
	case KDBG_VALCHECK:
		kdlog_value1 = (kdr->value1);
		kdlog_value2 = (kdr->value2);
		kdlog_value3 = (kdr->value3);
		kdlog_value4 = (kdr->value4);
		kdebug_flags &= (unsigned int)~KDBG_CKTYPES;
		kdebug_flags &= ~KDBG_RANGECHECK;    /* Turn off range check */
		kdebug_flags |= KDBG_VALCHECK;       /* Turn on specific value check  */
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



kdbg_readmap(kd_threadmap *buffer, size_t *number)
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
      kmem_free(kernel_map, (char *)kd_mapptr, kd_mapsize);
      kdebug_flags &= ~KDBG_MAPINIT;
      kd_mapsize = 0;
      kd_mapptr = (kd_threadmap *) 0;
      kd_mapcount = 0;
    }  

  return(ret);
}


kdbg_control(name, namelen, where, sizep)
int *name;
u_int namelen;
char *where;
size_t *sizep;
{
int ret=0;
int size=*sizep;
int max_entries;
unsigned int value = name[1];
kd_regtype kd_Reg;
kbufinfo_t kd_bufinfo;

pid_t curpid;
struct proc *p, *curproc;

        if(curproc = current_proc())
	  curpid = curproc->p_pid;
	else
	  return (ESRCH);

        if (global_state_pid == -1)
	    global_state_pid = curpid;
	else if (global_state_pid != curpid)
	  {
	    if((p = pfind(global_state_pid)) == NULL)
	      {
		/* The global pid no longer exists */
		global_state_pid = curpid;
	      }
	    else
	      {
		/* The global pid exists, deny this request */
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
		    }
		  kdebug_enable=(value)?1:0;
		  kdebug_nolog = (value)?0:1;
		  if (kdebug_enable)
		      kdbg_mapinit();
		  break;
		case KERN_KDSETBUF:
		  /* We allow a maximum buffer size of 25% of memory */
		  /* 'value' is the desired number of trace entries */
		        max_entries = (mem_size/4) / sizeof(kd_buf);
			if (value <= max_entries)
				nkdbufs = value;
			else
			  nkdbufs = max_entries;
			break;
		case KERN_KDGETBUF:
		        if(size < sizeof(kbufinfo_t)) {
		            ret=EINVAL;
			    break;
			}
			kd_bufinfo.nkdbufs = nkdbufs;
			kd_bufinfo.nkdthreads = kd_mapsize / sizeof(kd_threadmap);
			kd_bufinfo.nolog = kdebug_nolog;
			kd_bufinfo.flags = kdebug_flags;
			if(copyout (&kd_bufinfo, where, sizeof(kbufinfo_t))) {
			  ret=EINVAL;
			}
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
		        ret = kdbg_readmap((kd_threadmap *)where, sizep);
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
	return(ret);
}

kdbg_read(kd_buf * buffer, size_t *number)
{
int avail=*number;
int count=0;
int copycount=0;
int totalcount=0;
int s;
unsigned int my_kdebug_flags;
kd_buf * my_kd_bufptr;

	s = ml_set_interrupts_enabled(FALSE);
	simple_lock(&kd_trace_lock);
	my_kdebug_flags = kdebug_flags;
	my_kd_bufptr = kd_bufptr;
	simple_unlock(&kd_trace_lock);
	ml_set_interrupts_enabled(s);

	count = avail/sizeof(kd_buf);
	if (count) {
		if ((my_kdebug_flags & KDBG_BUFINIT) && kd_bufsize && kd_buffer) {
			if (count > nkdbufs)
			        count = nkdbufs;
			if (!(my_kdebug_flags & KDBG_WRAPPED) && (my_kd_bufptr > kd_readlast))
			  {
			    copycount = my_kd_bufptr-kd_readlast;
			    if (copycount > count)
			      copycount = count;

			    if (copyout(kd_readlast, buffer, copycount * sizeof(kd_buf)))
			      {
				*number = 0;
				return(EINVAL);
			      }
			    kd_readlast += copycount;
			    *number = copycount;
			    return(0);
			  }
			else if (!(my_kdebug_flags & KDBG_WRAPPED) && (my_kd_bufptr == kd_readlast))
			  {
			    *number = 0;
			    return(0);
			  }
			else
			  {
			    if (my_kdebug_flags & KDBG_WRAPPED)
			      {
				kd_readlast = my_kd_bufptr;
				kdebug_flags &= ~KDBG_WRAPPED;
			      }

			    /* Note that by setting kd_readlast equal to my_kd_bufptr,
			       we now treat the kd_buffer read the same as if we weren't
			       wrapped and my_kd_bufptr was less than kd_readlast.
			    */

			    /* first copyout from readlast to end of kd_buffer */
			    copycount = kd_buflast - kd_readlast;
			    if (copycount > count)
			      copycount = count;
			    if (copyout(kd_readlast, buffer, copycount * sizeof(kd_buf)))
			      {
				*number = 0;
				return(EINVAL);
			      }
			    buffer += copycount;
			    count -= copycount;
			    totalcount = copycount;
			    kd_readlast += copycount;
			    if (kd_readlast == kd_buflast)
			      kd_readlast = kd_buffer;
			    if (count == 0)
			      {
				*number = totalcount;
				return(0);
			      }

			     /* second copyout from top of kd_buffer to bufptr */
			    copycount = my_kd_bufptr - kd_readlast;
			    if (copycount > count)
			      copycount = count;
			    if (copycount == 0)
			      {
				*number = totalcount;
				return(0);
			      }
			    if (copyout(kd_readlast, buffer, copycount * sizeof(kd_buf)))
			      {
				return(EINVAL);
			      }
			    kd_readlast += copycount;
			    totalcount += copycount;
			    *number = totalcount;
			    return(0);
			  }
		} /* end if KDBG_BUFINIT */		
	} /* end if count */
	return (EINVAL);
}
