/*
 * Copyright (c) 1995-1999, 2000-2002 Apple Computer, Inc. All rights reserved.
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

#include <sys/appleapiopts.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/signal.h>
#include <sys/mount.h>

/* serial or parallel system call */
#define syss(fn,no) {no, 0, KERNEL_FUNNEL, fn}
#define sysp(fn,no) {no, 1, KERNEL_FUNNEL, fn}
#define sysnets(fn,no) {no, 0, NETWORK_FUNNEL, fn}
#define sysnetp(fn,no) {no, 1, NETWORK_FUNNEL, fn}
#define sysnofnl(fn,no) {no, 0, NO_FUNNEL, fn}

/*
 * definitions
 */
int	nosys();
int	exit();
int	fork();
int	read();
int	write();
int	open();
int	close();
int	wait4();
int	link();
int	unlink();
int	chdir();
int	fchdir();
int	mknod();
int	chmod();
int	chown();
int	obreak();
int	getfsstat();
#if COMPAT_GETFSSTAT
int	ogetfsstat();
#endif
int	getpid();
int	mount();
int	unmount();
int	setuid();
int	getuid();
int	geteuid();
int	ptrace();
int	recvmsg();
int	sendmsg();
int	recvfrom();
int	accept();
int	getpeername();
int	getsockname();
int	access();
int	chflags();
int	fchflags();
int	sync();
int	kill();
int	getppid();
int	dup();
int	pipe();
int	getegid();
int	profil();
int	load_shared_file();
int	reset_shared_file();
int	new_system_shared_regions();
int	ktrace();
int	sigaction();
int	getgid();
int	sigprocmask();
int	getlogin();
int	setlogin();
int	acct();
int	sigpending();
int	sigaltstack();
int	ioctl();
int	reboot();
int	revoke();
int	symlink();
int	readlink();
int	execve();
int	umask();
int	chroot();
int	msync();
int	vfork();
int	sbrk();
int	sstk();
int	ovadvise();
int	munmap();
int	mprotect();
int	madvise();
int	mincore();
int	getgroups();
int	setgroups();
int	getpgrp();
int	setpgid();
int	setitimer();
int	swapon();
int	getitimer();
int	getdtablesize();
int	dup2();
int	fcntl();
int	select();
int	fsync();
int	setpriority();
int	socket();
int	connect();
int	getpriority();
int	sigreturn();
int	bind();
int	setsockopt();
int	listen();
int	sigsuspend();
#if TRACE
int	vtrace();
#else
#endif
int	gettimeofday();
#ifdef __ppc__
int	ppc_gettimeofday();
#endif
int	getrusage();
int	getsockopt();
int	readv();
int	writev();
int	settimeofday();
int	fchown();
int	fchmod();
int	rename();
int	flock();
int	mkfifo();
int	sendto();
int	shutdown();
int	socketpair();
int	mkdir();
int	rmdir();
int	utimes();
int	futimes();
int	adjtime();
int	setsid();
int	quotactl();
int	nfssvc();
int	statfs();
int	fstatfs();
int	getfh();
int	setgid();
int	setegid();
int	seteuid();
int	stat();
int	fstat();
int	lstat();
int	pathconf();
int	fpathconf();
int	getrlimit();
int	setrlimit();
int	getdirentries();
int	mmap();
int	nosys();
int	lseek();
int	truncate();
int	ftruncate();
int	__sysctl();
int	undelete();
int setprivexec();
int add_profil();

int	kdebug_trace();

int	mlock();
int	munlock();
int	minherit();
int	mlockall();
int	munlockall();
#if COMPAT_43
#define compat(name,n) syss(__CONCAT(o,name),n)
#define compatp(name,n) sysp(__CONCAT(o,name),n)
#define comaptnet(name,n) sysnets(__CONCAT(o,name),n)
#define comaptnetp(name,n) sysnetp(__CONCAT(o,name),n)

int	ocreat();
int	olseek();
int	ostat();
int	olstat();
int	ofstat();
int	ogetkerninfo();
int	osmmap();
int	ogetpagesize();
int	ommap();
int	owait();
int	ogethostname();
int	osethostname();
int	oaccept();
int	osend();
int	orecv();
int	osigvec();
int	osigblock();
int	osigsetmask();
int	osigstack();
int	orecvmsg();
int	osendmsg();
int	orecvfrom();
int	osetreuid();
int	osetregid();
int	otruncate();
int	oftruncate();
int	ogetpeername();
int	ogethostid();
int	osethostid();
int	ogetrlimit();
int	osetrlimit();
int	okillpg();
int	oquota();
int	ogetsockname();
int ogetdomainname();
int osetdomainname();
int	owait3();
int	ogetdirentries();

#if NETAT
int ATsocket();
int ATgetmsg();
int ATputmsg();
int ATPsndreq();
int ATPsndrsp();
int ATPgetreq();
int ATPgetrsp();
#endif /* NETAT */

/* Calls for supporting HFS Semantics */

int mkcomplex();		
int statv();				
int lstatv();				
int fstatv();			
int getattrlist();		
int setattrlist();		
int getdirentriesattr();		
int exchangedata();		
int checkuseraccess();		
int searchfs();
int delete();
int copyfile();

/* end of HFS calls */

#else /* COMPAT_43 */
#define compat(n, name) syss(nosys,0)
#define compatp(n, name) sysp(nosys,0)
#define comaptnet(n, name) sysnets(nosys,0)
#define comaptnetp(n, name) sysnetp(nosys,0)
#endif /* COMPAT_43 */

int watchevent();
int waitevent();
int modwatch();
int fsctl();		
int semsys();
int msgsys();
int shmsys();
int semctl();
int semget();
int semop();
int semconfig();
int msgctl();
int msgget();
int msgsnd();
int msgrcv();
int shmat();
int shmctl();
int shmdt();
int shmget();
int shm_open();
int shm_unlink();
int sem_open();
int sem_close();
int sem_unlink();
int sem_wait();
int sem_trywait();
int sem_post();
int sem_getvalue();
int sem_init();
int sem_destroy();

int	issetugid();
int	utrace();
int	pread();
int	pwrite();
int	getsid();
int	getpgid();

int __pthread_kill();
int sigwait();
int pthread_sigmask();
int __disable_threadsignal();

/*
 * System call switch table.
 */

struct sysent sysent[] = {
	syss(nosys,0),			/*   0 = indir */
	syss(exit,1),			/*   1 = exit */
	syss(fork,0),			/*   2 = fork */
	sysp(read,3),			/*   3 = read */
	sysp(write,3),			/*   4 = write */
	syss(open,3),			/*   5 = open */
	syss(close,1),			/*   6 = close */
	syss(wait4, 4),			/*   7 = wait4 */
	compat(creat,2),	/*   8 = old creat */
	syss(link,2),			/*   9 = link */
	syss(unlink,1),			/*  10 = unlink */
	syss(nosys, 0),			/*  11 was obsolete execv */
	syss(chdir,1),			/*  12 = chdir */
	syss(fchdir,1),			/*  13 = fchdir */
	syss(mknod,3),			/*  14 = mknod */
	syss(chmod,2),			/*  15 = chmod */
	syss(chown,3),			/*  16 = chown; now 3 args */
	syss(obreak,1),			/*  17 = old break */
#if COMPAT_GETFSSTAT
	syss(ogetfsstat, 3),	/*  18 = ogetfsstat */
#else
	syss(getfsstat, 3),		/*  18 = getfsstat */
#endif
	compat(lseek,3),	/*  19 = old lseek */
	sysp(getpid,0),			/*  20 = getpid */
	syss(nosys, 0),			/*  21 was obsolete mount */
	syss(nosys, 0),			/*  22 was obsolete umount */
	syss(setuid,1),			/*  23 = setuid */
	sysp(getuid,0),			/*  24 = getuid */
	sysp(geteuid,0),		/*  25 = geteuid */
	syss(ptrace,4),			/*  26 = ptrace */
	sysnets(recvmsg,3),		/*  27 = recvmsg */
	sysnets(sendmsg,3),		/*  28 = sendmsg */
	sysnets(recvfrom,6),		/*  29 = recvfrom */
	sysnets(accept,3),			/*  30 = accept */
	sysnets(getpeername,3),	/*  31 = getpeername */
	sysnets(getsockname,3),	/*  32 = getsockname */
	syss(access,2),			/*  33 = access */
	syss(chflags,2),		/* 34 = chflags */
	syss(fchflags,2),		/* 35 = fchflags */
	syss(sync,0),			/*  36 = sync */
	syss(kill,2),			/*  37 = kill */
	compat(stat,2),	/*  38 = old stat */
	sysp(getppid,0),		/*  39 = getppid */
	compat(lstat,2),	/*  40 = old lstat */
	syss(dup,1),			/*  41 = dup */
	syss(pipe,0),			/*  42 = pipe */
	sysp(getegid,0),		/*  43 = getegid */
	syss(profil,4),			/*  44 = profil */
	syss(ktrace,4),			/*  45 = ktrace */
	syss(sigaction,3),		/*  46 = sigaction */
	sysp(getgid,0),			/*  47 = getgid */
	syss(sigprocmask,3),	/*  48 = sigprocmask */
	syss(getlogin,2),		/*  49 = getlogin */
	syss(setlogin,1),		/*  50 = setlogin */
	syss(acct,1),			/*  51 = turn acct off/on */
	syss(sigpending,1),		/*  52 = sigpending */
	syss(sigaltstack,2),	/*  53 = sigaltstack */
	syss(ioctl,3),			/*  54 = ioctl */
	syss(reboot,2),			/*  55 = reboot */
	syss(revoke,1),			/*  56 = revoke */
	syss(symlink,2),		/*  57 = symlink */
	syss(readlink,3),		/*  58 = readlink */
	syss(execve,3),			/*  59 = execve */
	syss(umask,1),			/*  60 = umask */
	syss(chroot,1),			/*  61 = chroot */
	compat(fstat,2),	/*  62 = old fstat */
	syss(nosys,0),			/*  63 = used internally, reserved */
	compat(getpagesize,0),	/*  64 = old getpagesize */
	syss(msync,3),			/*  65 = msync */
	syss(vfork,0),			/*  66 = vfork */
	syss(nosys,0),			/*  67 was obsolete vread */
	syss(nosys,0),			/*  68 was obsolete vwrite */
	syss(sbrk,1),			/*  69 = sbrk */
	syss(sstk,1),			/*  70 = sstk */
	compat(smmap,6),		/*  71 = old mmap */
	syss(ovadvise,1),		/*  72 = old vadvise */
	syss(munmap,2),			/*  73 = munmap */
	syss(mprotect,3),		/*  74 = mprotect */
	syss(madvise,3),		/*  75 = madvise */
	syss(nosys,0),			/*  76 was obsolete vhangup */
	syss(nosys,0),			/*  77 was obsolete vlimit */
	syss(mincore,3),		/*  78 = mincore */
	sysp(getgroups,2),		/*  79 = getgroups */
	sysp(setgroups,2),		/*  80 = setgroups */
	sysp(getpgrp,0),		/*  81 = getpgrp */
	sysp(setpgid,2),		/*  82 = setpgid */
	syss(setitimer,3),		/*  83 = setitimer */
	compat(wait,0),	/*  84 = old wait */
	syss(swapon,1),			/*  85 = swapon */
	syss(getitimer,2),		/*  86 = getitimer */
	compat(gethostname,2),	/*  87 = old gethostname */
	compat(sethostname,2),	/*  88 = old sethostname */
	sysp(getdtablesize, 0),		/* 89 getdtablesize */
	syss(dup2,2),			/*  90 = dup2 */
	syss(nosys,0),			/*  91 was obsolete getdopt */
	syss(fcntl,3),			/*  92 = fcntl */
	syss(select,5),			/*  93 = select */
	syss(nosys,0),			/*  94 was obsolete setdopt */
	syss(fsync,1),			/*  95 = fsync */
	sysp(setpriority,3),	/*  96 = setpriority */
	sysnets(socket,3),		/*  97 = socket */
	sysnets(connect,3),		/*  98 = connect */
	comaptnet(accept,3),	/*  99 = accept */
	sysp(getpriority,2),	/* 100 = getpriority */
	comaptnet(send,4),		/* 101 = old send */
	comaptnet(recv,4),		/* 102 = old recv */
	syss(sigreturn,1),		/* 103 = sigreturn */
	sysnets(bind,3),		/* 104 = bind */
	sysnets(setsockopt,5),	/* 105 = setsockopt */
	sysnets(listen,2),		/* 106 = listen */
	syss(nosys,0),			/* 107 was vtimes */
	compat(sigvec,3),		/* 108 = sigvec */
	compat(sigblock,1),		/* 109 = sigblock */
	compat(sigsetmask,1),	/* 110 = sigsetmask */
	syss(sigsuspend,1),		/* 111 = sigpause */
	compat(sigstack,2),		/* 112 = sigstack */
	comaptnet(recvmsg,3),	/* 113 = recvmsg */
	comaptnet(sendmsg,3),	/* 114 = sendmsg */
	syss(nosys,0),			/* 115 = old vtrace */
#ifdef __ppc__
	sysnofnl(ppc_gettimeofday,2),	/* 116 = gettimeofday */
#else
	sysnofnl(gettimeofday,2),	/* 116 = gettimeofday */
#endif
	sysp(getrusage,2),		/* 117 = getrusage */
	sysnets(getsockopt,5),	/* 118 = getsockopt */
	syss(nosys,0),			/* 119 = old resuba */
	sysp(readv,3),			/* 120 = readv */
	sysp(writev,3),			/* 121 = writev */
	syss(settimeofday,2),	/* 122 = settimeofday */
	syss(fchown,3),			/* 123 = fchown */
	syss(fchmod,2),			/* 124 = fchmod */
	comaptnet(recvfrom,6),	/* 125 = recvfrom */
	compat(setreuid,2),		/* 126 = setreuid */
	compat(setregid,2),		/* 127 = setregid */
	syss(rename,2),			/* 128 = rename */
	compat(truncate,2),		/* 129 = old truncate */
	compat(ftruncate,2),	/* 130 = ftruncate */
	syss(flock,2),			/* 131 = flock */
	syss(mkfifo,2),			/* 132 = mkfifo */
	sysnets(sendto,6),		/* 133 = sendto */
	sysnets(shutdown,2),	/* 134 = shutdown */
	sysnets(socketpair,4),	/* 135 = socketpair */
	syss(mkdir,2),			/* 136 = mkdir */
	syss(rmdir,1),			/* 137 = rmdir */
	syss(utimes,2),			/* 138 = utimes */
	syss(futimes,2),		/* 139 = futimes */
	syss(adjtime,2),		/* 140 = adjtime */
	comaptnet(getpeername,3),/* 141 = getpeername */
	compat(gethostid,0),	/* 142 = old gethostid */
	sysp(nosys,0),			/* 143 = old sethostid */
	compat(getrlimit,2),		/* 144 = old getrlimit */
	compat(setrlimit,2),		/* 145 = old setrlimit */
	compat(killpg,2),	/* 146 = old killpg */
	syss(setsid,0),			/* 147 = setsid */
	syss(nosys,0),			/* 148 was setquota */
	syss(nosys,0),			/* 149 was qquota */
	comaptnet(getsockname,3),/* 150 = getsockname */
	syss(getpgid,1),		/* 151 = getpgid */
	sysp(setprivexec,1),/* 152 = setprivexec */
#ifdef DOUBLE_ALIGN_PARAMS
	syss(pread,5),		/* 153 = pread */
	syss(pwrite,5),		/* 154 = pwrite */
#else
	syss(pread,4),		/* 153 = pread */
	syss(pwrite,4),		/* 154 = pwrite */
#endif
	syss(nfssvc,2),			/* 155 = nfs_svc */
	compat(getdirentries,4),	/* 156 = old getdirentries */
	syss(statfs, 2),		/* 157 = statfs */
	syss(fstatfs, 2),		/* 158 = fstatfs */
	syss(unmount, 2),		/* 159 = unmount */
	syss(nosys,0),			/* 160 was async_daemon */
	syss(getfh,2),			/* 161 = get file handle */
	compat(getdomainname,2),	/* 162 = getdomainname */
	compat(setdomainname,2),	/* 163 = setdomainname */
	syss(nosys,0),			/* 164 */
#if	QUOTA
	syss(quotactl, 4),		/* 165 = quotactl */
#else	QUOTA
	syss(nosys, 0),		/* 165 = not configured */
#endif	/* QUOTA */
	syss(nosys,0),			/* 166 was exportfs */
	syss(mount, 4),			/* 167 = mount */
	syss(nosys,0),			/* 168 was ustat */
	syss(nosys,0),		    /* 169 = nosys */
	syss(nosys,0),			/* 170 was table */
	compat(wait3,3),	/* 171 = old wait3 */
	syss(nosys,0),			/* 172 was rpause */
	syss(nosys,0),			/* 173 = nosys */
	syss(nosys,0),			/* 174 was getdents */
	syss(nosys,0),			/* 175 was gc_control */
	syss(add_profil,4),		/* 176 = add_profil */
	syss(nosys,0),			/* 177 */
	syss(nosys,0),			/* 178 */
	syss(nosys,0),			/* 179 */
	syss(kdebug_trace,6),           /* 180 */
	syss(setgid,1),			/* 181 */
	syss(setegid,1),		/* 182 */
	syss(seteuid,1),		/* 183 */
	syss(nosys,0),			/* 184 = nosys */
	syss(nosys,0),			/* 185 = nosys */
	syss(nosys,0),			/* 186 = nosys */
	syss(nosys,0),			/* 187 = nosys */
	syss(stat,2),			/* 188 = stat */
	syss(fstat,2),			/* 189 = fstat */
	syss(lstat,2),			/* 190 = lstat */
	syss(pathconf,2),		/* 191 = pathconf */
	syss(fpathconf,2),		/* 192 = fpathconf */
#if COMPAT_GETFSSTAT
	syss(getfsstat,3),		/* 193 = getfsstat */
#else
	syss(nosys,0),			/* 193 is unused */ 
#endif
	syss(getrlimit,2),		/* 194 = getrlimit */
	syss(setrlimit,2),		/* 195 = setrlimit */
	syss(getdirentries,4),	/* 196 = getdirentries */
#ifdef DOUBLE_ALIGN_PARAMS
	syss(mmap,8),			/* 197 = mmap */
#else
	syss(mmap,7),			/* 197 = mmap */
#endif
	syss(nosys,0),			/* 198 = __syscall */
#ifdef DOUBLE_ALIGN_PARAMS
	syss(lseek,5),			/* 199 = lseek */
#else
	syss(lseek,4),			/* 199 = lseek */
#endif
#ifdef DOUBLE_ALIGN_PARAMS
	syss(truncate,4),		/* 200 = truncate */
	syss(ftruncate,4),		/* 201 = ftruncate */
#else
	syss(truncate,3),		/* 200 = truncate */
	syss(ftruncate,3),		/* 201 = ftruncate */
#endif
	syss(__sysctl,6),		/* 202 = __sysctl */
	sysp(mlock, 2),			/* 203 = mlock */
	syss(munlock, 2),		/* 204 = munlock */
	syss(undelete,1),		/* 205 = undelete */
#if NETAT
	sysnets(ATsocket,1),		/* 206 = ATsocket */
	sysnets(ATgetmsg,4),		/* 207 = ATgetmsg*/
	sysnets(ATputmsg,4),		/* 208 = ATputmsg*/
	sysnets(ATPsndreq,4),		/* 209 = ATPsndreq*/
	sysnets(ATPsndrsp,4),		/* 210 = ATPsndrsp*/
	sysnets(ATPgetreq,3),		/* 211 = ATPgetreq*/
	sysnets(ATPgetrsp,2),		/* 212 = ATPgetrsp*/
	syss(nosys,0),			/* 213 = Reserved for AppleTalk */
	syss(nosys,0),			/* 214 = Reserved for AppleTalk */
	syss(nosys,0),			/* 215 = Reserved for AppleTalk */
#else
	syss(nosys,0),			/* 206 = Reserved for AppleTalk */
	syss(nosys,0),			/* 207 = Reserved for AppleTalk */
	syss(nosys,0),			/* 208 = Reserved for AppleTalk */
	syss(nosys,0),			/* 209 = Reserved for AppleTalk */
	syss(nosys,0),			/* 210 = Reserved for AppleTalk */
	syss(nosys,0),			/* 211 = Reserved for AppleTalk */
	syss(nosys,0),			/* 212 = Reserved for AppleTalk */
	syss(nosys,0),			/* 213 = Reserved for AppleTalk */
	syss(nosys,0),			/* 214 = Reserved for AppleTalk */
	syss(nosys,0),			/* 215 = Reserved for AppleTalk */
#endif /* NETAT */

/*
 * System Calls 216 - 230 are reserved for calls to support HFS/HFS Plus
 * file system semantics. Currently, we only use 215-227.  The rest is 
 * for future expansion in anticipation of new MacOS APIs for HFS Plus.
 * These calls are not conditionalized becuase while they are specific
 * to HFS semantics, they are not specific to the HFS filesystem.
 * We expect all filesystems to recognize the call and report that it is
 * not supported or to actually implement it.
 */
	syss(nosys,3),	/* 216 = HFS make complex file call (multipel forks */
	syss(nosys,2),		/* 217 = HFS statv extended stat call for HFS */
	syss(nosys,2),		/* 218 = HFS lstatv extended lstat call for HFS */	
	syss(nosys,2),		/* 219 = HFS fstatv extended fstat call for HFS */
	syss(getattrlist,5),	/* 220 = HFS getarrtlist get attribute list cal */
	syss(setattrlist,5),	/* 221 = HFS setattrlist set attribute list */
	syss(getdirentriesattr,8),	/* 222 = HFS getdirentriesattr get directory attributes */
	syss(exchangedata,3),	/* 223 = HFS exchangedata exchange file contents */
#ifdef __APPLE_API_OBSOLETE
	syss(checkuseraccess,6),/* 224 = HFS checkuseraccess check access to a file */
#else
	syss(nosys,6),/* 224 = HFS checkuseraccess check access to a file */
#endif /* __APPLE_API_OBSOLETE */
	syss(searchfs,6),	/* 225 = HFS searchfs to implement catalog searching */
	syss(delete,1),		/* 226 = private delete (Carbon semantics) */
	syss(copyfile,4),	/* 227 = copyfile - orignally for AFP */
	syss(nosys,0),		/* 228 */
	syss(nosys,0),		/* 229 */
	syss(nosys,0),		/* 230 */
	sysnets(watchevent,2),		/* 231 */
	sysnets(waitevent,2),		/* 232 */
	sysnets(modwatch,2),		/* 233 */
	syss(nosys,0),		/* 234 */
	syss(nosys,0),		/* 235 */
	syss(nosys,0),		/* 236 */
	syss(nosys,0),		/* 237 */
	syss(nosys,0),		/* 238 */
	syss(nosys,0),		/* 239 */
	syss(nosys,0),		/* 240 */
	syss(nosys,0),		/* 241 */
	syss(fsctl,4),		/* 242 = fsctl */
	syss(nosys,0),		/* 243 */
	syss(nosys,0),		/* 244 */
	syss(nosys,0),		/* 245 */
	syss(nosys,0),		/* 246 */
	syss(nosys,0),		/* 247 */
	syss(nosys,0),		/* 248 */
	syss(nosys,0),		/* 249 */
	syss(minherit,3),	/* 250 = minherit */
	syss(semsys,5),		/* 251 = semsys */
	syss(msgsys,6),		/* 252 = msgsys */
	syss(shmsys,4),		/* 253 = shmsys */
	syss(semctl,4),		/* 254 = semctl */
	syss(semget,3),		/* 255 = semget */
	syss(semop,3),		/* 256 = semop */
	syss(semconfig,1),	/* 257 = semconfig */
	syss(msgctl,3),		/* 258 = msgctl */
	syss(msgget,2),		/* 259 = msgget */
	syss(msgsnd,4),		/* 260 = msgsnd */
	syss(msgrcv,5),		/* 261 = msgrcv */
	syss(shmat,3),		/* 262 = shmat */
	syss(shmctl,3),		/* 263 = shmctl */
	syss(shmdt,1),		/* 264 = shmdt */
	syss(shmget,3),		/* 265 = shmget */
	syss(shm_open,3),	/* 266 = shm_open */
	syss(shm_unlink,1),	/* 267 = shm_unlink */
	syss(sem_open,4),	/* 268 = sem_open */
	syss(sem_close,1),	/* 269 = sem_close */
	syss(sem_unlink,1),	/* 270 = sem_unlink */
	syss(sem_wait,1),	/* 271 = sem_wait */
	syss(sem_trywait,1),	/* 272 = sem_trywait */
	syss(sem_post,1),	/* 273 = sem_post */
	syss(sem_getvalue,2),	/* 274 = sem_getvalue */
	syss(sem_init,3),	/* 275 = sem_init */
	syss(sem_destroy,1),	/* 276 = sem_destroy */
	syss(nosys,0),		/* 277 */
	syss(nosys,0),		/* 278 */
	syss(nosys,0),		/* 279 */
	syss(nosys,0),		/* 280 */
	syss(nosys,0),		/* 281 */
	syss(nosys,0),		/* 282 */
	syss(nosys,0),		/* 283 */
	syss(nosys,0),		/* 284 */
	syss(nosys,0),		/* 285 */
	syss(nosys,0),		/* 286 */
	syss(nosys,0),		/* 287 */
	syss(nosys,0),		/* 288 */
	syss(nosys,0),		/* 289 */
	syss(nosys,0),		/* 290 */
	syss(nosys,0),		/* 291 */
	syss(nosys,0),		/* 292 */
	syss(nosys,0),		/* 293 */
	syss(nosys,0),		/* 294 */
	syss(nosys,0),		/* 295 */
	syss(load_shared_file,7), /* 296 = load_shared_file */
	syss(reset_shared_file,3), /* 297 = reset_shared_file */
	syss(new_system_shared_regions,0), /* 298 = new_system_shared_regions */
	syss(nosys,0),		/* 299 */
	syss(nosys,0),		/* 300 */
	syss(nosys,0),		/* 301 */
	syss(nosys,0),		/* 302 */
	syss(nosys,0),		/* 303 */
	syss(nosys,0),		/* 304 */
	syss(nosys,0),		/* 305 */
	syss(nosys,0),		/* 306 */
	syss(nosys,0),		/* 307 */
	syss(nosys,0),		/* 308 */
	syss(nosys,0),		/* 309 */
	syss(getsid,1),		/* 310 = getsid */
	syss(nosys,0),		/* 311 */
	syss(nosys,0),		/* 312 */
	syss(nosys,0),		/* 313 */
	syss(nosys,0),		/* 314 */
	syss(nosys,0),		/* 315 */
	syss(nosys,0),		/* 316 */
	syss(nosys,0),		/* 317 */
	syss(nosys,0),		/* 318 */
	syss(nosys,0),		/* 319 */
	syss(nosys,0),		/* 320 */
	syss(nosys,0),		/* 321 */
	syss(nosys,0),		/* 322 */
	syss(nosys,0),		/* 323 */
	syss(mlockall,1),	/* 324 = mlockall*/
	syss(munlockall,1),	/* 325 = munlockall*/
	syss(nosys,0),		/* 326 */
	sysp(issetugid,0),	/* 327 = issetugid */
	syss(__pthread_kill,2),		/* 328 */
	syss(pthread_sigmask,3),		/* 329 */
	syss(sigwait,2),		/* 330 */
	syss(__disable_threadsignal,1),		/* 331 */
	syss(nosys,0),		/* 332 */
	syss(nosys,0),		/* 333 */
	syss(nosys,0),		/* 334 */
	syss(utrace,2),		/* 335 = utrace */
	syss(nosys,0),		/* 336 */
	syss(nosys,0),		/* 337 */
	syss(nosys,0),		/* 338 */
	syss(nosys,0),		/* 339 */
	syss(nosys,0),		/* 340 */
	syss(nosys,0),		/* 341 */
	syss(nosys,0),		/* 342 */
	syss(nosys,0),		/* 343 */
	syss(nosys,0),		/* 344 */
	syss(nosys,0),		/* 345 */
	syss(nosys,0),		/* 346 */
	syss(nosys,0),		/* 347 */
	syss(nosys,0),		/* 348 */
	syss(nosys,0)		/* 349 */
};
int	nsysent = sizeof(sysent) / sizeof(sysent[0]);
