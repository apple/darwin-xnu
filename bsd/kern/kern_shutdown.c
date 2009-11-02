/*
 * Copyright (c) 2000-2004 Apple Computer, Inc. All rights reserved.
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

int	waittime = -1;
static void proc_shutdown();

void
boot(paniced, howto, command)
	int paniced, howto;
	char *command;
{
	register int i;
	int s;
	struct proc *p = current_proc();	/* XXX */
	int hostboot_option=0;
	int funnel_state;
	struct proc  *launchd_proc;

    extern void md_prepare_for_shutdown(int paniced, int howto, char * command);

	funnel_state = thread_funnel_set(kernel_flock, TRUE);

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

		audit_shutdown();

		sync(p, (void *)NULL, (int *)NULL);

		/*
		 * Now that all processes have been  termianted and system is sync'ed up, 
		 * suspend launchd
		 */

		launchd_proc = pfind(1);
		if (launchd_proc && p != launchd_proc) {
			task_suspend(launchd_proc->task);
		}

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
			IOSleep( 1 * nbusy );
		}
		if (nbusy)
			printf("giving up\n");
		else
			printf("done\n");
	}

	/*
	 * Can't just use an splnet() here to disable the network
	 * because that will lock out softints which the disk
	 * drivers depend on to finish DMAs.
	 */
	if_down_all();

	if (howto & RB_POWERDOWN)
		hostboot_option = HOST_REBOOT_HALT;
	if (howto & RB_HALT)
		hostboot_option = HOST_REBOOT_HALT;
	if (paniced == RB_PANIC)
		hostboot_option = HOST_REBOOT_HALT;

	/*
	 * if we're going to power down due to a halt,
	 * give the disks a chance to finish getting
	 * the track cache flushed to the media... 
	 * unfortunately, some of our earlier drives
	 * don't properly hold off on returning 
	 * from the track flush command (issued by
	 * the unmounts) until it's actully fully
	 * committed.
	 */
	if (hostboot_option == HOST_REBOOT_HALT)
	        IOSleep( 1 * 1000 );

	host_reboot(host_priv_self(), hostboot_option);

	thread_funnel_set(kernel_flock, FALSE);
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
proc_shutdown()
{
	struct proc	*p, *self;
	struct vnode	**cdirp, **rdirp, *vp;
	int		restart, i, TERM_catch;
	int delayterm = 0;

	/*
	 *	Kill as many procs as we can.  (Except ourself...)
	 */
	self = (struct proc *)current_proc();
	
	/*
	 * Signal the init with SIGTERM so that he does not launch
	 * new processes 
	 */
	p = pfind(1);
	if (p && p != self) {
		psignal(p, SIGTERM);
	}

	printf("Killing all processes ");

	/*
	 * send SIGTERM to those procs interested in catching one
	 */
sigterm_loop:
	for (p = allproc.lh_first; p; p = p->p_list.le_next) {
	        if (((p->p_flag&P_SYSTEM) == 0) && (p->p_pptr->p_pid != 0) && (p != self) && (p->p_stat != SZOMB) && (p->p_shutdownstate == 0)) {

			if ((delayterm == 0) && ((p->p_lflag& P_LDELAYTERM) == P_LDELAYTERM)) {
				continue;
			}
		        if (p->p_sigcatch & sigmask(SIGTERM)) {
					p->p_shutdownstate = 1;
					if (proc_refinternal(p, 1) == p) {
			        	psignal(p, SIGTERM);
						proc_dropinternal(p, 1);
					}
				goto sigterm_loop;
		}
	}
	}
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
		IOSleep(100);   
		TERM_catch = 0;

		for (p = allproc.lh_first; p; p = p->p_list.le_next) {
			if (p->p_shutdownstate == 1) {
				TERM_catch++;
			}
		}
		if (TERM_catch == 0)
		        break;
	}
	if (TERM_catch) {
		/*
		 * log the names of the unresponsive tasks
		 */

	        for (p = allproc.lh_first; p; p = p->p_list.le_next) {
			if (p->p_shutdownstate == 1) {
				  printf("%s[%d]: didn't act on SIGTERM\n", p->p_comm, p->p_pid);
			}
		}
		IOSleep(1000 * 5);
	}

	/*
	 * send a SIGKILL to all the procs still hanging around
	 */
sigkill_loop:
	for (p = allproc.lh_first; p; p = p->p_list.le_next) {
	        if (((p->p_flag&P_SYSTEM) == 0) && (p->p_pptr->p_pid != 0) && (p != self) && (p->p_stat != SZOMB) && (p->p_shutdownstate != 2)) {

			if ((delayterm == 0) && ((p->p_lflag& P_LDELAYTERM) == P_LDELAYTERM)) {
				continue;
			}
			if (proc_refinternal(p, 1) == p) {
				psignal(p, SIGKILL);
				proc_dropinternal(p, 1);
			}
			p->p_shutdownstate = 2;
			goto sigkill_loop;
		}
	}
	/*
	 * wait for up to 60 seconds to allow these procs to exit normally
	 */
	for (i = 0; i < 300; i++) {
		IOSleep(200);  /* double the time from 100 to 200 for NFS requests in particular */

	        for (p = allproc.lh_first; p; p = p->p_list.le_next) {
				if (p->p_shutdownstate == 2)
			        break;
		}
		if (!p)
		        break;
	}

	/*
	 * if we still have procs that haven't exited, then brute force 'em
	 */
	p = allproc.lh_first;
	while (p) {
	        if ((p->p_shutdownstate == 3) || (p->p_flag&P_SYSTEM) || (!delayterm && ((p->p_lflag& P_LDELAYTERM))) 
				|| (p->p_pptr->p_pid == 0) || (p == self)) {
		        p = p->p_list.le_next;
		}
		else {
			p->p_shutdownstate = 3;
		        /*
			 * NOTE: following code ignores sig_lock and plays
			 * with exit_thread correctly.  This is OK unless we
			 * are a multiprocessor, in which case I do not
			 * understand the sig_lock.  This needs to be fixed.
			 * XXX
			 */
			if (p->exit_thread) {	/* someone already doing it */
				/* give him a chance */
				thread_block(THREAD_CONTINUE_NULL);
			} else {
				p->exit_thread = current_thread();
				printf(".");
				if (proc_refinternal(p, 1) == p) {
					exit1(p, 1, (int *)NULL);
					proc_dropinternal(p, 1);
				}
			}
			p = allproc.lh_first;
		}
	}
	printf("\n");


	/* Now start the termination of processes that are marked for delayed termn */
	if (delayterm == 0) {
		delayterm = 1;
		goto  sigterm_loop;
	}
	printf("continuing\n");
}

