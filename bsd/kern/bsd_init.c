/*
 * Copyright (c) 2000-2003 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_LICENSE_HEADER_START@
 * 
 * Copyright (c) 1999-2003 Apple Computer, Inc.  All Rights Reserved.
 * 
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. Please obtain a copy of the License at
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
 * @APPLE_LICENSE_HEADER_END@
 */
/*
 * Copyright (c) 1982, 1986, 1989, 1991, 1992, 1993
 *	The Regents of the University of California.  All rights reserved.
 * (c) UNIX System Laboratories, Inc.
 * All or some portions of this file are derived from material licensed
 * to the University of California by American Telephone and Telegraph
 * Co. or Unix System Laboratories, Inc. and are reproduced herein with
 * the permission of UNIX System Laboratories, Inc.
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in the
 *    documentation and/or other materials provided with the distribution.
 * 3. All advertising materials mentioning features or use of this software
 *    must display the following acknowledgement:
 *	This product includes software developed by the University of
 *	California, Berkeley and its contributors.
 * 4. Neither the name of the University nor the names of its contributors
 *    may be used to endorse or promote products derived from this software
 *    without specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE REGENTS AND CONTRIBUTORS ``AS IS'' AND
 * ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
 * ARE DISCLAIMED.  IN NO EVENT SHALL THE REGENTS OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
 * OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
 * HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
 * LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
 * OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
 * SUCH DAMAGE.
 *
 *	@(#)init_main.c	8.16 (Berkeley) 5/14/95
 */

/* 
 *
 * Mach Operating System
 * Copyright (c) 1987 Carnegie-Mellon University
 * All rights reserved.  The CMU software License Agreement specifies
 * the terms and conditions for use and redistribution.
 */

#include <sys/param.h>
#include <sys/filedesc.h>
#include <sys/kernel.h>
#include <sys/mount.h>
#include <sys/proc.h>
#include <sys/systm.h>
#include <sys/vnode.h>
#include <sys/conf.h>
#include <sys/buf.h>
#include <sys/clist.h>
#include <sys/user.h>
#include <sys/time.h>
#include <sys/systm.h>

#include <sys/kern_audit.h>

#include <sys/malloc.h>
#include <sys/dkstat.h>

#include <machine/spl.h>
#include <kern/thread.h>
#include <kern/task.h>
#include <kern/ast.h>

#include <mach/vm_param.h>

#include <vm/vm_map.h>
#include <vm/vm_kern.h>

#include <sys/ux_exception.h>	/* for ux_exception_port */

#include <sys/reboot.h>
#include <mach/exception_types.h>
#include <dev/busvar.h>			/* for pseudo_inits */
#include <sys/kdebug.h>

#include <mach/mach_types.h>
#include <mach/vm_prot.h>
#include <mach/semaphore.h>
#include <mach/sync_policy.h>
#include <kern/clock.h>
#include <mach/kern_return.h>

#include <mach/shared_memory_server.h>
#include <vm/vm_shared_memory_server.h>

extern int app_profile;		/* on/off switch for pre-heat cache */

char    copyright[] =
"Copyright (c) 1982, 1986, 1989, 1991, 1993\n\t"
"The Regents of the University of California. "
"All rights reserved.\n\n";

extern void	ux_handler();

/* Components of the first process -- never freed. */
struct	proc proc0;
struct	session session0;
struct	pgrp pgrp0;
struct	pcred cred0;
struct	filedesc filedesc0;
struct	plimit limit0;
struct	pstats pstats0;
struct	sigacts sigacts0;
struct	proc *kernproc, *initproc;

long tk_cancc;
long tk_nin;
long tk_nout;
long tk_rawcc;

/* Global variables to make pstat happy. We do swapping differently */
int nswdev, nswap;
int nswapmap;
void *swapmap;
struct swdevt swdevt[1];

dev_t	rootdev;		/* device of the root */
dev_t	dumpdev;		/* device to take dumps on */
long	dumplo;			/* offset into dumpdev */
long	hostid;
char	hostname[MAXHOSTNAMELEN];
int		hostnamelen;
char	domainname[MAXDOMNAMELEN];
int		domainnamelen;
char	classichandler[32] = {0};  
long	classichandler_fsid = -1L;
long	classichandler_fileid = -1L;

char rootdevice[16]; 	/* hfs device names have at least 9 chars */
struct	timeval boottime;		/* GRODY!  This has to go... */

#ifdef  KMEMSTATS
struct	kmemstats kmemstats[M_LAST];
#endif

int	lbolt;				/* awoken once a second */
struct	vnode *rootvp;
int boothowto = RB_DEBUG;

#define	BSD_PAGABLE_MAP_SIZE	(16 * 512 * 1024)
vm_map_t	bsd_pageable_map;
vm_map_t	mb_map;
semaphore_t execve_semaphore;

int	cmask = CMASK;

int parse_bsd_args(void);
extern int bsd_hardclockinit;
extern task_t bsd_init_task;
extern char    init_task_failure_data[];
extern void time_zone_slock_init(void);

funnel_t *kernel_flock;
funnel_t *network_flock;
int disable_funnel = 0;		/* disables split funnel */
int enable_funnel = 0;		/* disables split funnel */

/*
 * Initialization code.
 * Called from cold start routine as
 * soon as a stack and segmentation
 * have been established.
 * Functions:
 *	turn on clock
 *	hand craft 0th process
 *	call all initialization routines
 *  hand craft 1st user process
 */

/*
 *	Sets the name for the given task.
 */
void
proc_name(s, p)
	char		*s;
	struct proc *p;
{
	int		length = strlen(s);

	bcopy(s, p->p_comm,
		length >= sizeof(p->p_comm) ? sizeof(p->p_comm) :
			length + 1);
}

/* To allow these values to be patched, they're globals here */
#include <machine/vmparam.h>
struct rlimit vm_initial_limit_stack = { DFLSSIZ, MAXSSIZ };
struct rlimit vm_initial_limit_data = { DFLDSIZ, MAXDSIZ };
struct rlimit vm_initial_limit_core = { DFLCSIZ, MAXCSIZ };

extern thread_t first_thread;
extern thread_act_t	cloneproc(struct proc *, int);
extern int 	(*mountroot) __P((void));
extern int 	netboot_mountroot(); 	/* netboot.c */
extern int	netboot_setup(struct proc * p);

/* hook called after root is mounted XXX temporary hack */
void (*mountroot_post_hook)(void);

void
bsd_init()
{
	register struct proc *p;
	extern struct ucred *rootcred;
	register int i;
	int s;
	thread_t	th;
	void		lightning_bolt(void );
	kern_return_t	ret;
	boolean_t funnel_state;
	extern void uthread_zone_init();


	/* split funnel is enabled by default */
	PE_parse_boot_arg("dfnl", &disable_funnel);

	kernel_flock = funnel_alloc(KERNEL_FUNNEL);
	if (kernel_flock == (funnel_t *)0 ) {
		panic("bsd_init: Failed to allocate kernel funnel");
	}
        
	funnel_state = thread_funnel_set(kernel_flock, TRUE);

	if (!disable_funnel) {
		network_flock = funnel_alloc(NETWORK_FUNNEL);
		if (network_flock == (funnel_t *)0 ) {
			panic("bsd_init: Failed to allocate network funnel");
		}
	} else {
		network_flock = kernel_flock;
	}

	printf(copyright);

	kmeminit();
	
	parse_bsd_args();

	bsd_bufferinit();

	/* Initialize the uthread zone */
	uthread_zone_init();

	/*
	 * Initialize process and pgrp structures.
	 */
	procinit();

	kernproc = &proc0;

	p = kernproc;

	/* kernel_task->proc = kernproc; */
	set_bsdtask_info(kernel_task,(void *)p);
	p->p_pid = 0;

	/* give kernproc a name */
	proc_name("kernel_task", p);

	if (current_task() != kernel_task)
		printf("bsd_init: We have a problem, "
				"current task is not kernel task\n");
	
	/*
	 * Create process 0.
	 */
	LIST_INSERT_HEAD(&allproc, p, p_list);
	p->p_pgrp = &pgrp0;
	LIST_INSERT_HEAD(PGRPHASH(0), &pgrp0, pg_hash);
	LIST_INIT(&pgrp0.pg_members);
	LIST_INSERT_HEAD(&pgrp0.pg_members, p, p_pglist);

	pgrp0.pg_session = &session0;
	session0.s_count = 1;
	session0.s_leader = p;

	p->task = kernel_task;
	
	p->p_stat = SRUN;
	p->p_flag = P_INMEM|P_SYSTEM;
	p->p_nice = NZERO;
	p->p_pptr = p;
	lockinit(&p->signal_lock, PVM, "signal", 0, 0);
	TAILQ_INIT(&p->p_uthlist);
	p->sigwait = FALSE;
	p->sigwait_thread = THREAD_NULL;
	p->exit_thread = THREAD_NULL;

	/* Create credentials. */
	lockinit(&cred0.pc_lock, PLOCK, "proc0 cred", 0, 0);
	cred0.p_refcnt = 1;
	p->p_cred = &cred0;
	p->p_ucred = crget();
	p->p_ucred->cr_ngroups = 1;	/* group 0 */
	
	TAILQ_INIT(&p->aio_activeq);
	TAILQ_INIT(&p->aio_doneq);
	p->aio_active_count = 0;
	p->aio_done_count = 0;

	/* Set the audit info for this process */
	audit_proc_init(p);

	/* Create the file descriptor table. */
	filedesc0.fd_refcnt = 1+1;	/* +1 so shutdown will not _FREE_ZONE */
	p->p_fd = &filedesc0;
	filedesc0.fd_cmask = cmask;
	filedesc0.fd_knlistsize = -1;
	filedesc0.fd_knlist = NULL;
	filedesc0.fd_knhash = NULL;
	filedesc0.fd_knhashmask = 0;

	/* Create the limits structures. */
	p->p_limit = &limit0;
	for (i = 0; i < sizeof(p->p_rlimit)/sizeof(p->p_rlimit[0]); i++)
		limit0.pl_rlimit[i].rlim_cur = 
			limit0.pl_rlimit[i].rlim_max = RLIM_INFINITY;
	limit0.pl_rlimit[RLIMIT_NOFILE].rlim_cur = NOFILE;
	limit0.pl_rlimit[RLIMIT_NPROC].rlim_cur = MAXUPRC;
	limit0.pl_rlimit[RLIMIT_NPROC].rlim_max = maxproc;
	limit0.pl_rlimit[RLIMIT_STACK] = vm_initial_limit_stack;
	limit0.pl_rlimit[RLIMIT_DATA] = vm_initial_limit_data;
	limit0.pl_rlimit[RLIMIT_CORE] = vm_initial_limit_core;
	limit0.p_refcnt = 1;

	p->p_stats = &pstats0;
	p->p_sigacts = &sigacts0;

	/*
	 * Charge root for one process.
	 */
	(void)chgproccnt(0, 1);

	/*
	 *	Allocate a kernel submap for pageable memory
	 *	for temporary copying (execve()).
	 */
	{
		vm_offset_t	min;

		ret = kmem_suballoc(kernel_map,
				&min,
				(vm_size_t)BSD_PAGABLE_MAP_SIZE,
				TRUE,
				TRUE,
				&bsd_pageable_map);
		if (ret != KERN_SUCCESS) 
			panic("bsd_init: Failed to allocate bsd pageable map");
	}

	/* Initialize the execve() semaphore */
	ret = semaphore_create(kernel_task, &execve_semaphore,
			SYNC_POLICY_FIFO, (BSD_PAGABLE_MAP_SIZE / NCARGS));
	if (ret != KERN_SUCCESS)
		panic("bsd_init: Failed to create execve semaphore");

	/*
	 * Initialize the calendar.
	 */
	IOKitResetTime();

	ubc_init();

	/* Initialize the file systems. */
	vfsinit();

	/* Initialize mbuf's. */
	mbinit();

	/* Initialize syslog */
	log_init();

	/*
	 * Initializes security event auditing.
	 * XXX: Should/could this occur later?
	 */
	audit_init();  

	/* Initialize kqueues */
	knote_init();

	/* Initialize for async IO */
	aio_init();

	/* POSIX Shm and Sem */
	pshm_cache_init();
	psem_cache_init();
	time_zone_slock_init();

	/*
	 * Initialize protocols.  Block reception of incoming packets
	 * until everything is ready.
	 */
	s = splimp();
	sysctl_register_fixed(); 
	sysctl_mib_init();
	dlil_init();
	socketinit();
	domaininit();
	splx(s);

	p->p_fd->fd_cdir = NULL;
	p->p_fd->fd_rdir = NULL;

#ifdef GPROF
	/* Initialize kernel profiling. */
	kmstartup();
#endif

	/* kick off timeout driven events by calling first time */
	thread_wakeup(&lbolt);
	timeout((void (*)(void *))lightning_bolt, 0, hz);

	bsd_autoconf();

	/*
	 * We attach the loopback interface *way* down here to ensure
	 * it happens after autoconf(), otherwise it becomes the
	 * "primary" interface.
	 */
#include <loop.h>
#if NLOOP > 0
	loopattach();			/* XXX */
#endif
        
        /* Register the built-in dlil ethernet interface family */
	ether_family_init();

	vnode_pager_bootstrap();

	/* Mount the root file system. */
	while( TRUE) {
		int err;

		setconf();
		/*
		 * read the time after clock_initialize_calendar()
		 * and before nfs mount
		 */
		microtime((struct timeval  *)&time);

		bsd_hardclockinit = -1;	/* start ticking */

		if (0 == (err = vfs_mountroot()))
			break;
		if (mountroot == netboot_mountroot) {
			printf("cannot mount network root, errno = %d\n", err);
			mountroot = NULL;
			if (0 == (err = vfs_mountroot()))
				break;
		}
		printf("cannot mount root, errno = %d\n", err);
		boothowto |= RB_ASKNAME;
	}

	mountlist.cqh_first->mnt_flag |= MNT_ROOTFS;

	/* Get the vnode for '/'.  Set fdp->fd_fd.fd_cdir to reference it. */
	if (VFS_ROOT(mountlist.cqh_first, &rootvnode))
		panic("bsd_init: cannot find root vnode");
	VREF(rootvnode);
	filedesc0.fd_cdir = rootvnode;
	VOP_UNLOCK(rootvnode, 0, p);

	if (mountroot == netboot_mountroot) {
		int err;
		/* post mount setup */
		if (err = netboot_setup(p)) {
			panic("bsd_init: NetBoot could not find root, %d", err);
		}
	}
	

	/*
	 * Now can look at time, having had a chance to verify the time
	 * from the file system.  Reset p->p_rtime as it may have been
	 * munched in mi_switch() after the time got set.
	 */
	p->p_stats->p_start = boottime = time;
	p->p_rtime.tv_sec = p->p_rtime.tv_usec = 0;

#if DEVFS
	{
	    extern void devfs_kernel_mount(char * str);
	    
	    devfs_kernel_mount("/dev");
	}
#endif /* DEVFS */
	
	/* Initialize signal state for process 0. */
	siginit(p);

	bsd_utaskbootstrap();

	/* invoke post-root-mount hook */
	if (mountroot_post_hook != NULL)
		mountroot_post_hook();
	
	(void) thread_funnel_set(kernel_flock, funnel_state);
}

/* Called with kernel funnel held */
void
bsdinit_task(void)
{
	struct proc *p = current_proc();
	struct uthread *ut;
	kern_return_t	kr;
	thread_act_t th_act;
	shared_region_mapping_t system_region;

	proc_name("init", p);

	ux_handler_init();

	th_act = current_act();
	(void) host_set_exception_ports(host_priv_self(),
					EXC_MASK_ALL & ~(EXC_MASK_SYSCALL |
							 EXC_MASK_MACH_SYSCALL |
							 EXC_MASK_RPC_ALERT),
					ux_exception_port,
					EXCEPTION_DEFAULT, 0);

	(void) task_set_exception_ports(get_threadtask(th_act),
					EXC_MASK_ALL & ~(EXC_MASK_SYSCALL |
							 EXC_MASK_MACH_SYSCALL |
							 EXC_MASK_RPC_ALERT),
					ux_exception_port,
					EXCEPTION_DEFAULT, 0);




	ut = (uthread_t)get_bsdthread_info(th_act);
	ut->uu_ar0 = (void *)get_user_regs(th_act);

	bsd_hardclockinit = 1;	/* Start bsd hardclock */
	bsd_init_task = get_threadtask(th_act);
	init_task_failure_data[0] = 0;
	system_region = lookup_default_shared_region(ENV_DEFAULT_ROOT,
				machine_slot[cpu_number()].cpu_type);
        if (system_region == NULL) {
		shared_file_boot_time_init(ENV_DEFAULT_ROOT,
				machine_slot[cpu_number()].cpu_type);
	} else {
		vm_set_shared_region(get_threadtask(th_act), system_region);
	}
	load_init_program(p);
	/* turn on app-profiling i.e. pre-heating */
	app_profile = 1;
}

void
lightning_bolt()
{			
	boolean_t 	funnel_state;
	extern void klogwakeup(void);

	funnel_state = thread_funnel_set(kernel_flock, TRUE);

	thread_wakeup(&lbolt);
	timeout(lightning_bolt,0,hz);
	klogwakeup();

	(void) thread_funnel_set(kernel_flock, FALSE);
}

bsd_autoconf()
{
	extern kern_return_t IOKitBSDInit( void );

	kminit();

	/* 
	 * Early startup for bsd pseudodevices.
	 */
	{
	    struct pseudo_init *pi;
	
	    for (pi = pseudo_inits; pi->ps_func; pi++)
		(*pi->ps_func) (pi->ps_count);
	}

	return( IOKitBSDInit());
}


#include <sys/disklabel.h>  /* for MAXPARTITIONS */

setconf()
{	
	extern kern_return_t IOFindBSDRoot( char * rootName,
				dev_t * root, u_int32_t * flags );
	u_int32_t	flags;
	kern_return_t	err;

	/*
	 * calls into IOKit can generate networking registrations
	 * which needs to be under network funnel. Right thing to do
	 * here is to drop the funnel alltogether and regrab it afterwards
	 */
	thread_funnel_set(kernel_flock, FALSE);
	err = IOFindBSDRoot( rootdevice, &rootdev, &flags );
	thread_funnel_set(kernel_flock, TRUE);
	if( err) {
		printf("setconf: IOFindBSDRoot returned an error (%d);"
			"setting rootdevice to 'sd0a'.\n", err); /* XXX DEBUG TEMP */
		rootdev = makedev( 6, 0 );
		strcpy( rootdevice, "sd0a" );
		flags = 0;
	}

	if( flags & 1 ) {
		/* network device */
		mountroot = netboot_mountroot;
	} else {
		/* otherwise have vfs determine root filesystem */
		mountroot = NULL;
	}

}

bsd_utaskbootstrap()
{
	thread_act_t th_act;
	struct uthread *ut;

	th_act = cloneproc(kernproc, 0);
	initproc = pfind(1);				
	/* Set the launch time for init */
	initproc->p_stats->p_start = time;

	ut = (struct uthread *)get_bsdthread_info(th_act);
	ut->uu_sigmask = 0;
	act_set_astbsd(th_act);
	(void) thread_resume(th_act);
}

parse_bsd_args()
{
	extern char init_args[];
	char	namep[16];
	extern int boothowto;
	extern int srv;
	extern int ncl;

	int len;

	if (PE_parse_boot_arg("-s", namep)) {
		boothowto |= RB_SINGLE;
		len = strlen(init_args);
		if(len != 0)
			strcat(init_args," -s");
		else
			strcat(init_args,"-s");
	}

	if (PE_parse_boot_arg("-b", namep)) {
		boothowto |= RB_NOBOOTRC;
		len = strlen(init_args);
		if(len != 0)
			strcat(init_args," -b");
		else
			strcat(init_args,"-b");
	}

	if (PE_parse_boot_arg("-F", namep)) {
		len = strlen(init_args);
		if(len != 0)
			strcat(init_args," -F");
		else
			strcat(init_args,"-F");
	}

	if (PE_parse_boot_arg("-v", namep)) {
		len = strlen(init_args);
		if(len != 0)
			strcat(init_args," -v");
		else
			strcat(init_args,"-v");
	}

	if (PE_parse_boot_arg("-x", namep)) { /* safe boot */
		len = strlen(init_args);
		if(len != 0)
			strcat(init_args," -x");
		else
			strcat(init_args,"-x");
	}

	if (PE_parse_boot_arg("-d", namep)) {
		len = strlen(init_args);
		if(len != 0)
			strcat(init_args," -d");
		else
			strcat(init_args,"-d");
	}

	PE_parse_boot_arg("srv", &srv);
	PE_parse_boot_arg("ncl", &ncl);
	PE_parse_boot_arg("nbuf", &nbuf);

	return 0;
}

boolean_t
thread_funnel_switch(
        int	oldfnl,
	int	newfnl)
{
	boolean_t	funnel_state_prev;
	int curfnl;
	funnel_t * curflock;
	funnel_t * oldflock;
	funnel_t * newflock;
	funnel_t * exist_funnel;
	extern int disable_funnel;
       
        
		if (disable_funnel)
			return(TRUE);

        if(oldfnl == newfnl) {
            panic("thread_funnel_switch: can't switch to same funnel");
        }
        
        if ((oldfnl != NETWORK_FUNNEL) && (oldfnl != KERNEL_FUNNEL)) {
            panic("thread_funnel_switch: invalid oldfunnel");
        }
        if ((newfnl != NETWORK_FUNNEL) && (newfnl != KERNEL_FUNNEL)) {
            panic("thread_funnel_switch: invalid newfunnel");
        }
        
	if((curflock = thread_funnel_get()) == THR_FUNNEL_NULL) {
            panic("thread_funnel_switch: no funnel held");
	}
        
        if ((oldfnl == NETWORK_FUNNEL) && (curflock != network_flock))
            panic("thread_funnel_switch: network funnel not held");
            
        if ((oldfnl == KERNEL_FUNNEL) && (curflock != kernel_flock))
            panic("thread_funnel_switch: kernel funnel not held");

        if(oldfnl == NETWORK_FUNNEL) {
            oldflock = network_flock;
            newflock = kernel_flock;
        } else {
            oldflock = kernel_flock;
            newflock = network_flock;
        }
		KERNEL_DEBUG(0x603242c | DBG_FUNC_NONE, oldflock, 1, 0, 0, 0);
        thread_funnel_set(oldflock, FALSE);
		KERNEL_DEBUG(0x6032428 | DBG_FUNC_NONE, newflock, 1, 0, 0, 0);
        thread_funnel_set(newflock, TRUE);
		KERNEL_DEBUG(0x6032434 | DBG_FUNC_NONE, newflock, 1, 0, 0, 0);

        return(TRUE);        
}
