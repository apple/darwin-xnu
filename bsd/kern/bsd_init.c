/*
 * Copyright (c) 2000-2001 Apple Computer, Inc. All rights reserved.
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
/*
 * HISTORY
 * 16-Apr-98  A. Ramesh at Apple
 *	Created for Apple Core from DR2 init_main.c.
 */

#include <quota.h>

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
#include <ufs/ufs/quota.h>

#include <sys/malloc.h>
#include <sys/dkstat.h>

#include <machine/spl.h>
#include <kern/thread.h>
#include <kern/task.h>
#include <kern/ast.h>

#include <mach/vm_param.h>

#include <vm/vm_map.h>
#include <vm/vm_kern.h>

#include <sys/ux_exception.h>

#include <sys/reboot.h>
#include <mach/exception_types.h>
#include <dev/busvar.h>
#include <sys/kdebug.h>

#include <mach/mach_types.h>
#include <mach/vm_prot.h>
#include <mach/semaphore.h>
#include <mach/sync_policy.h>
#include <kern/clock.h>
#include <mach/kern_return.h>

extern shared_region_mapping_t       system_shared_region;

char    copyright[] =
"Copyright (c) 1982, 1986, 1989, 1991, 1993\n\tThe Regents of the University of California.  All rights reserved.\n\n";

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


long cp_time[CPUSTATES];
long dk_seek[DK_NDRIVE];
long dk_time[DK_NDRIVE];
long dk_wds[DK_NDRIVE];
long dk_wpms[DK_NDRIVE];
long dk_xfer[DK_NDRIVE];
long dk_bps[DK_NDRIVE];

int dk_busy;
int dk_ndrive;

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
int	hostnamelen;
char	domainname[MAXDOMNAMELEN];
int	domainnamelen;

char rootdevice[16]; 	/* hfs device names have at least 9 chars */
struct	timeval boottime;		/* GRODY!  This has to go... */
#if FIXME  /* [ */
struct	timeval time;
#endif  /* FIXME ] */

#ifdef  KMEMSTATS
struct	kmemstats kmemstats[M_LAST];
#endif

int	lbolt;				/* awoken once a second */
struct	vnode *rootvp;
int boothowto = RB_DEBUG;

#define	BSD_PAGABLE_MAP_SIZE	(4 * 512 * 1024)
vm_map_t	bsd_pageable_map;
vm_map_t	mb_map;
semaphore_t execve_semaphore;

int	cmask = CMASK;

int parse_bsd_args(void);
extern int bsd_hardclockinit;
extern vm_address_t bsd_init_task;
extern char    init_task_failure_data[];

funnel_t * kernel_flock;
funnel_t * network_flock;
int disable_funnel = 0;		/* disables split funnel */
int enable_funnel = 0;		/* disables split funnel */

/*
 * Initialization code.
 * Called from cold start routine as
 * soon as a stack and segmentation
 * have been established.
 * Functions:
 *	clear and free user core
 *	turn on clock
 *	hand craft 0th process
 *	call all initialization routines
 *	fork - process 0 to schedule
 *	     - process 1 execute bootstrap
 *	     - process 2 to page out
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

#define SPL_DEBUG	0
#if	SPL_DEBUG
#define	dprintf(x)	printf x
#else	SPL_DEBUG
#define dprintf(x)
#endif	/* SPL_DEBUG */

extern thread_t	cloneproc(struct proc *, int);

void
bsd_init()
{
	register struct proc *p;
	extern struct ucred *rootcred;
	register int i;
	int s;
	thread_t	th;
	extern void	bsdinit_task();
	void		lightning_bolt(void );
	kern_return_t	ret;
	boolean_t funnel_state;
	extern void uthread_zone_init();

	extern int (*mountroot) __P((void));


#if 1
	/* split funnel is enabled by default */
	PE_parse_boot_arg("dfnl", &disable_funnel);
#else
	/* split funnel is disabled befault */
	disable_funnel = 1;
	PE_parse_boot_arg("efnl", &enable_funnel);
	if (enable_funnel)  {
			/* enable only if efnl is set in bootarg */
			disable_funnel = 0;
	}
#endif

	kernel_flock = funnel_alloc(KERNEL_FUNNEL);
	if (kernel_flock == (funnel_t *)0 ) {
		panic("bsd_init: Fail to allocate kernel mutex lock");
	}
        
        
	funnel_state = thread_funnel_set(kernel_flock, TRUE);

	if (!disable_funnel) {
		network_flock = funnel_alloc(NETWORK_FUNNEL);
		if (network_flock == (funnel_t *)0 ) {
			panic("bds_init: Fail to allocate network mutex lock");
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
	set_bsdtask_info(kernel_task,(void *)kernproc);
	p->p_pid = 0;

	/* give kernproc a name */
	proc_name("kernel_task", p);

	if (current_task() != kernel_task)
		printf("We are in for problem, current task in not kernel task\n");
	
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
	p->sigwait = FALSE;
	p->sigwait_thread = THREAD_NULL;
	p->exit_thread = THREAD_NULL;

	/* Create credentials. */
	lockinit(&cred0.pc_lock, PLOCK, "proc0 cred", 0, 0);
	cred0.p_refcnt = 1;
	p->p_cred = &cred0;
	p->p_ucred = crget();
	p->p_ucred->cr_ngroups = 1;	/* group 0 */

	/* Create the file descriptor table. */
	filedesc0.fd_refcnt = 1+1;	/* +1 so shutdown will not _FREE_ZONE */
	p->p_fd = &filedesc0;
	filedesc0.fd_cmask = cmask;

	/* Create the limits structures. */
	p->p_limit = &limit0;
	for (i = 0; i < sizeof(p->p_rlimit)/sizeof(p->p_rlimit[0]); i++)
		limit0.pl_rlimit[i].rlim_cur = 
			limit0.pl_rlimit[i].rlim_max = RLIM_INFINITY;
	limit0.pl_rlimit[RLIMIT_NOFILE].rlim_cur = NOFILE;
	limit0.pl_rlimit[RLIMIT_NPROC].rlim_cur = MAXUPRC;
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
		panic("bsd_init: Failed to allocare bsd pageable map");
	}

	/* Initialize the execve() semaphore */
	{
		kern_return_t kret;
		int value;

		value = BSD_PAGABLE_MAP_SIZE / NCARGS;

		kret = semaphore_create(kernel_task, &execve_semaphore,
				SYNC_POLICY_FIFO, value);
		if (kret != KERN_SUCCESS)
			panic("bsd_init: Failed to create execve semaphore");
	}

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

	/* Initialize SysV shm */
	shminit();

        /* POSIX Shm and Sem */
        pshm_cache_init();
        psem_cache_init();
        
	/*
	 * Initialize protocols.  Block reception of incoming packets
	 * until everything is ready.
	 */
	s = splimp();
	sysctl_register_fixed(); 
	dlil_init();
	socketinit();
	domaininit();
	splx(s);

	/*
	 *	Create kernel idle cpu processes.  This must be done
 	 *	before a context switch can occur (and hence I/O can
	 *	happen in the binit() call).
	 */
	p->p_fd->fd_cdir = NULL;
	p->p_fd->fd_rdir = NULL;


#ifdef GPROF
	/* Initialize kernel profiling. */
	kmstartup();
#endif

	/* kick off timeout driven events by calling first time */
	thread_wakeup(&lbolt);
	timeout(lightning_bolt,0,hz);

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

	vnode_pager_bootstrap();

	/* Mount the root file system. */
	while( TRUE) {
		int err;

		setconf();
		/*
		 * read the time after clock_initialize_calendar()
		 * and before nfs mount
		 */
		microtime(&time);

		if (0 == (err = vfs_mountroot()))
			break;
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
	

	/*
	 * Now can look at time, having had a chance to verify the time
	 * from the file system.  Reset p->p_rtime as it may have been
	 * munched in mi_switch() after the time got set.
	 */
	p->p_stats->p_start = boottime = time;
	p->p_rtime.tv_sec = p->p_rtime.tv_usec = 0;

#ifdef DEVFS
	{
	    extern void devfs_kernel_mount(char * str);
	    
	    devfs_kernel_mount("/dev");
	}
#endif DEVFS
	
	/* Initialize signal state for process 0. */
	siginit(p);

	/* printf("Launching user process\n"); */

	bsd_utaskbootstrap();

	(void) thread_funnel_set(kernel_flock, FALSE);
}

void
bsdinit_task()
{
	struct proc *p = current_proc();
	struct uthread *ut;
	kern_return_t	kr;
	thread_act_t th_act;
	boolean_t funnel_state;

	funnel_state = thread_funnel_set(kernel_flock, TRUE);

#if FIXME  /* [ */

	ipc_port_t	master_bootstrap_port;
	task_t		bootstrap_task;
	thread_act_t	bootstrap_thr_act;
	ipc_port_t	root_device_port;

	master_bootstrap_port = ipc_port_alloc_kernel();
	if (master_bootstrap_port == IP_NULL)
		panic("can't allocate master bootstrap port");
	printf("setting bootstrap port \n");
	task_set_special_port(bootstrap_task,
			      TASK_BOOTSTRAP_PORT,
			      ipc_port_make_send(master_bootstrap_port));
	
	printf("Setting exception port for the init task\n");
	(void) task_set_exception_ports(get_threadtask(th),
					EXC_MASK_ALL &
					~(EXC_MASK_SYSCALL |
			  EXC_MASK_MACH_SYSCALL | EXC_MASK_RPC_ALERT),
					ux_exception_port,
					EXCEPTION_DEFAULT, 0);

#endif /* FIXME  ] */
	proc_name("init", p);

	ux_handler_init();
	/* port_reference(ux_exception_port);*/

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
	vm_set_shared_region(get_threadtask(th_act), system_shared_region);
	load_init_program(p);

	(void) thread_funnel_set(kernel_flock, FALSE);
	
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

bsd_autoconf(){
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


#include <sys/disklabel.h>  // for MAXPARTITIONS

setconf()
{	
	extern kern_return_t IOFindBSDRoot( char * rootName,
				dev_t * root, u_int32_t * flags );

	extern int 	(*mountroot) __P((void));
	extern int 	nfs_mountroot(); 	/* nfs_vfsops.c */

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

	/* if network device then force nfs root */
	if( flags & 1 ) {
		printf("mounting nfs root\n");
		mountroot = nfs_mountroot;
	} else {
		/* otherwise have vfs determine root filesystem */
		mountroot = NULL;
	}

}

bsd_utaskbootstrap()
{
	thread_act_t th_act;

	th_act = (thread_act_t)cloneproc(kernproc, 0);
	initproc = pfind(1);				
	thread_hold(th_act);
	(void) thread_stop_wait(getshuttle_thread(th_act));
	thread_ast_set(th_act,AST_BSD_INIT);
	thread_release(th_act);
	thread_unstop(getshuttle_thread(th_act));
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
	thread_t	cur_thread;
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
        
        if ((oldfnl != NETWORK_FUNNEL) && (oldfnl != KERNEL_FUNNEL))
        {
            panic("thread_funnel_switch: invalid oldfunnel");
        }
        if ((newfnl != NETWORK_FUNNEL) && (newfnl != KERNEL_FUNNEL))
        {
            panic("thread_funnel_switch: invalid oldfunnel");
        }
        
	if((curflock = thread_funnel_get()) == THR_FUNNEL_NULL) {
            panic("thread_funnel_switch: no funnel held");
	}
        
	cur_thread = current_thread();
        
        if ((oldfnl == NETWORK_FUNNEL) && (curflock != network_flock))
            panic("thread_funnel_switch: network funnel not held");
            
        if ((oldfnl == KERNEL_FUNNEL) && (curflock != kernel_flock))
            panic("thread_funnel_switch: network funnel not held");

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
