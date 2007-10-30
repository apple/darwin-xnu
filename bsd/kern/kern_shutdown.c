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
/*
 *	File:	bsd/kern/kern_shutdown.c
 *
 *	Copyright (C) 1989, NeXT, Inc.
 *
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/vm.h>
#include <sys/proc_internal.h>
#include <sys/user.h>
#include <sys/reboot.h>
#include <sys/conf.h>
#include <sys/vnode_internal.h>
#include <sys/file_internal.h>
#include <sys/clist.h>
#include <sys/callout.h>
#include <sys/mbuf.h>
#include <sys/msgbuf.h>
#include <sys/ioctl.h>
#include <sys/signal.h>
#include <sys/tty.h>
#include <kern/task.h>
#include <sys/quota.h>
#include <ufs/ufs/inode.h>
#if	NCPUS > 1
#include <kern/processor.h>
#include <kern/thread.h>
#include <sys/lock.h>
#endif	/* NCPUS > 1 */
#include <vm/vm_kern.h>
#include <mach/vm_param.h>
#include <sys/filedesc.h>
#include <mach/host_priv.h>
#include <mach/host_reboot.h>

#include <bsm/audit_kernel.h>

#include <kern/sched_prim.h>		/* for thread_block() */
#include <kern/host.h>			/* for host_priv_self() */
#include <net/if_var.h>			/* for if_down_all() */
#include <sys/buf_internal.h>		/* for count_busy_buffers() */
#include <sys/mount_internal.h>		/* for vfs_unmountall() */
#include <mach/task.h>			/* for task_suspend() */
#include <sys/sysproto.h>		/* abused for sync() */
#include <kern/clock.h>			/* for delay_for_interval() */

/* XXX should be in a header file somewhere, but isn't */
extern void md_prepare_for_shutdown(int, int, char *);

int	waittime = -1;
static int shutting_down = 0;

static void proc_shutdown(void);
int in_shutdown(void);

extern void IOSystemShutdownNotification(void);

struct sd_filterargs{
	int delayterm;
	int shutdownstate;
};


struct sd_iterargs {
	int signo;	/* the signal to be posted */
	int setsdstate;  /* shutdown state to be set */
};

static int sd_filt1(proc_t, void *);
static int sd_filt2(proc_t, void *);
static int  sd_callback1(proc_t p, void * arg);
static int  sd_callback2(proc_t p, void * arg);
static int  sd_callback3(proc_t p, void * arg);

void
boot(int paniced, int howto, char *command)
{
	struct proc *p = current_proc();	/* XXX */
	int hostboot_option=0;
	int funnel_state;

	funnel_state = thread_funnel_set(kernel_flock, TRUE);

       /*
	* Temporary hack to notify the power management root domain
	* that the system will shut down.
	*/
	IOSystemShutdownNotification();

	shutting_down = 1;
	    
	md_prepare_for_shutdown(paniced, howto, command);

	if ((howto&RB_NOSYNC)==0 && waittime < 0) {
		int iter, nbusy;

		waittime = 0;
		
		printf("syncing disks... ");

		/*
		 * Release vnodes held by texts before sync.
		 */

		/* handle live procs (deallocate their root and current directories). */		
		proc_shutdown();

#if AUDIT
 		audit_shutdown();
#endif

		sync(p, (void *)NULL, (int *)NULL);

		/*
		 * Now that all processes have been terminated and system is
		 * sync'ed up, suspend init
		 */

		if (initproc && p != initproc)
			task_suspend(initproc->task);

		/*
		 * Unmount filesystems
		 */
		vfs_unmountall();

		/* Wait for the buffer cache to clean remaining dirty buffers */
		for (iter = 0; iter < 100; iter++) {
			nbusy = count_busy_buffers();
			if (nbusy == 0)
				break;
			printf("%d ", nbusy);
			delay_for_interval( 1 * nbusy, 1000 * 1000);
		}
		if (nbusy)
			printf("giving up\n");
		else
			printf("done\n");
	}

#if NETWORKING
	/*
	 * Can't just use an splnet() here to disable the network
	 * because that will lock out softints which the disk
	 * drivers depend on to finish DMAs.
	 */
	if_down_all();
#endif /* NETWORKING */

	if (howto & RB_POWERDOWN)
		hostboot_option = HOST_REBOOT_HALT;
	if (howto & RB_HALT)
		hostboot_option = HOST_REBOOT_HALT;
	if (paniced == RB_PANIC)
		hostboot_option = HOST_REBOOT_HALT;

    if (howto & RB_UPSDELAY) {
        hostboot_option = HOST_REBOOT_UPSDELAY;
    }

	host_reboot(host_priv_self(), hostboot_option);

	thread_funnel_set(kernel_flock, FALSE);
}

static int
sd_filt1(proc_t p, void * args)
{
	proc_t self = current_proc();
	struct sd_filterargs * sf = (struct sd_filterargs *)args;
	int delayterm = sf-> delayterm;
	int shutdownstate = sf->shutdownstate;

	if (((p->p_flag&P_SYSTEM) != 0) || (p->p_ppid == 0) 
		||(p == self) || (p->p_stat == SZOMB) 
		|| (p->p_shutdownstate != shutdownstate) 
		||((delayterm == 0) && ((p->p_lflag& P_LDELAYTERM) == P_LDELAYTERM))
		|| ((p->p_sigcatch & sigmask(SIGTERM))== 0)) {
			return(0);
		}
        else 
                return(1);
}


static int  
sd_callback1(proc_t p, void * args)
{
	struct sd_iterargs * sd = (struct sd_iterargs *)args;
	int signo = sd->signo;
	int setsdstate = sd->setsdstate;

	proc_lock(p);
	p->p_shutdownstate = setsdstate;
	if (p->p_stat != SZOMB) {
		proc_unlock(p);
		psignal(p, signo);
	} else
		proc_unlock(p);
	return(PROC_RETURNED);

}

static int
sd_filt2(proc_t p, void * args)
{
	proc_t self = current_proc();
	struct sd_filterargs * sf = (struct sd_filterargs *)args;
	int delayterm = sf-> delayterm;
	int shutdownstate = sf->shutdownstate;

	if (((p->p_flag&P_SYSTEM) != 0) || (p->p_ppid == 0) 
		||(p == self) || (p->p_stat == SZOMB) 
		|| (p->p_shutdownstate == shutdownstate) 
		||((delayterm == 0) && ((p->p_lflag& P_LDELAYTERM) == P_LDELAYTERM))) {
			return(0);
		}
        else
                return(1);
}

static int  
sd_callback2(proc_t p, void * args)
{
	struct sd_iterargs * sd = (struct sd_iterargs *)args;
	int signo = sd->signo;
	int setsdstate = sd->setsdstate;

	proc_lock(p);
	p->p_shutdownstate = setsdstate;
	if (p->p_stat != SZOMB) {
		proc_unlock(p);
		psignal(p, signo);
	} else
		proc_unlock(p);

	return(PROC_RETURNED);

}

static int  
sd_callback3(proc_t p, void * args)
{
	struct sd_iterargs * sd = (struct sd_iterargs *)args;
	int setsdstate = sd->setsdstate;

	proc_lock(p);
	p->p_shutdownstate = setsdstate;
	if (p->p_stat != SZOMB) {
	       /*
		* NOTE: following code ignores sig_lock and plays
		* with exit_thread correctly.  This is OK unless we
		* are a multiprocessor, in which case I do not
		* understand the sig_lock.  This needs to be fixed.
		* XXX
		*/
		if (p->exit_thread) {	/* someone already doing it */
			proc_unlock(p);
			/* give him a chance */
			thread_block(THREAD_CONTINUE_NULL);
		} else {
			p->exit_thread = current_thread();
			printf(".");
			proc_unlock(p);
			exit1(p, 1, (int *)NULL);
		}
	} else
		proc_unlock(p);

	return(PROC_RETURNED);
}


/*
 * proc_shutdown()
 *
 *	Shutdown down proc system (release references to current and root
 *	dirs for each process).
 *
 * POSIX modifications:
 *
 *	For POSIX fcntl() file locking call vno_lockrelease() on 
 *	the file to release all of its record locks, if any.
 */

static void
proc_shutdown(void)
{
	struct proc	*p, *self;
	int		i, TERM_catch;
	int delayterm = 0;
	struct sd_filterargs sfargs;
	struct sd_iterargs sdargs;

	/*
	 *	Kill as many procs as we can.  (Except ourself...)
	 */
	self = (struct proc *)current_proc();
	
	/*
	 * Signal the init with SIGTERM so that he does not launch
	 * new processes 
	 */
	p = proc_find(1);
	if (p && p != self) {
		psignal(p, SIGTERM);
	}
	proc_rele(p);

	printf("Killing all processes ");

sigterm_loop:
	/*
	 * send SIGTERM to those procs interested in catching one
	 */
	sfargs.delayterm = delayterm;
	sfargs.shutdownstate = 0;
	sdargs.signo = SIGTERM;
	sdargs.setsdstate = 1;

	/* post a SIGTERM to all that catch SIGTERM and not marked for delay */
	proc_rebootscan(sd_callback1, (void *)&sdargs, sd_filt1, (void *)&sfargs);

	/*
	 * now wait for up to 30 seconds to allow those procs catching SIGTERM
	 * to digest it
	 * as soon as these procs have exited, we'll continue on to the next step
	 */
	for (i = 0; i < 300; i++) {
	        /*
		 * sleep for a tenth of a second
		 * and then check to see if the tasks that were sent a
		 * SIGTERM have exited
		 */
		delay_for_interval(100, 1000 * 1000);
		TERM_catch = 0;


		proc_list_lock();

		for (p = allproc.lh_first; p; p = p->p_list.le_next) {
			if (p->p_shutdownstate == 1) {
				TERM_catch++;
			}
		}

		proc_list_unlock();

		if (TERM_catch == 0)
		        break;
	}
	if (TERM_catch) {
		/*
		 * log the names of the unresponsive tasks
		 */


		proc_list_lock();

	        for (p = allproc.lh_first; p; p = p->p_list.le_next) {
			if (p->p_shutdownstate == 1) {
				  printf("%s[%d]: didn't act on SIGTERM\n", p->p_comm, p->p_pid);
			}
		}

		proc_list_unlock();

		delay_for_interval(1000 * 5, 1000 * 1000);
	}

	/*
	 * send a SIGKILL to all the procs still hanging around
	 */
	sfargs.delayterm = delayterm;
	sfargs.shutdownstate = 2;
	sdargs.signo = SIGKILL;
	sdargs.setsdstate = 2;

	/* post a SIGTERM to all that catch SIGTERM and not marked for delay */
	proc_rebootscan(sd_callback2, (void *)&sdargs, sd_filt2, (void *)&sfargs);

	/*
	 * wait for up to 60 seconds to allow these procs to exit normally
	 *
	 * History:	The delay interval was changed from 100 to 200
	 *		for NFS requests in particular.
	 */
	for (i = 0; i < 300; i++) {
		delay_for_interval(200, 1000 * 1000);


		proc_list_lock();

	        for (p = allproc.lh_first; p; p = p->p_list.le_next) {
				if (p->p_shutdownstate == 2)
			        break;
		}

		proc_list_unlock();

		if (!p)
		        break;
	}

	/*
	 * if we still have procs that haven't exited, then brute force 'em
	 */
	sfargs.delayterm = delayterm;
	sfargs.shutdownstate = 3;
	sdargs.signo = 0;
	sdargs.setsdstate = 3;

	/* post a SIGTERM to all that catch SIGTERM and not marked for delay */
	proc_rebootscan(sd_callback3, (void *)&sdargs, sd_filt2, (void *)&sfargs);
	printf("\n");

	/* Now start the termination of processes that are marked for delayed termn */
	if (delayterm == 0) {
		delayterm = 1;
		goto  sigterm_loop;
	}
	/* drop the ref on initproc */
	proc_rele(initproc);
	printf("continuing\n");
}

/*
 * Check whether the system has begun its shutdown sequence. 
 */
int
in_shutdown(void)
{
	return shutting_down;
}
