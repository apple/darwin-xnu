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
/* Copyright (c) 1992,1995-1999 Apple Computer, Inc.  All rights resereved. */
/*
 * HISTORY
 *
 * 02-10-99 Clark Warner (warner_c) ta Apple
 * 	Chaned call 227 to copyfile 
 * 07-14-99 Earsh Nandkeshwar (earsh) at Apple
 *    	Renamed getdirentryattr to getdirentriesattr
 * 01-22-98 Clark Warner (warner_c) at Apple
 *    	Created new HFS style Systemcalls
 * 25-May-95 Mac Gillon (mgillon) at NeXT
 *	Created from NS 3.3 and 4.4BSD
 *
 */

char *syscallnames[] = {
	"syscall",			/* 0 = syscall */
	"exit",				/* 1 = exit */
	"fork",				/* 2 = fork */
	"read",				/* 3 = read */
	"write",			/* 4 = write */
	"open",				/* 5 = open */
	"close",			/* 6 = close */
	"wait4",			/* 7 = wait4 */
	"old_creat",		/* 8 = old creat */
	"link",				/* 9 = link */
	"unlink",			/* 10 = unlink */
	"obs_execv",		/* 11 = obsolete execv */
	"chdir",			/* 12 = chdir */
	"fchdir",			/* 13 = fchdir */
	"mknod",			/* 14 = mknod */
	"chmod",			/* 15 = chmod */
	"chown",			/* 16 = chown */
	"sbreak",			/* 17 = obsolete sbreak */
	"obs_stat",			/* 18 = obsolete stat */
	"old_lseek",		/* 19 = old lseek */
	"getpid",			/* 20 = getpid */
	"obs_mount",		/* 21 = obsolete mount */
	"obs_unmount",		/* 22 = obsolete unmount */
	"setuid",			/* 23 = setuid */
	"getuid",			/* 24 = getuid */
	"geteuid",			/* 25 = geteuid */
	"ptrace",			/* 26 = ptrace */
	"recvmsg",			/* 27 = recvmsg */
	"sendmsg",			/* 28 = sendmsg */
	"recvfrom",			/* 29 = recvfrom */
	"accept",			/* 30 = accept */
	"getpeername",		/* 31 = getpeername */
	"getsockname",		/* 32 = getsockname */
	"access",			/* 33 = access */
	"chflags",			/* 34 = chflags */
	"fchflags",			/* 35 = fchflags */
	"sync",				/* 36 = sync */
	"kill",				/* 37 = kill */
	"old_stat",			/* 38 = old stat */
	"getppid",			/* 39 = getppid */
	"old_lstat",		/* 40 = old lstat */
	"dup",				/* 41 = dup */
	"pipe",				/* 42 = pipe */
	"getegid",			/* 43 = getegid */
	"profil",			/* 44 = profil */
	"ktrace",			/* 45 = ktrace */
	"sigaction",		/* 46 = sigaction */
	"getgid",			/* 47 = getgid */
	"sigprocmask",		/* 48 = sigprocmask */
	"getlogin",			/* 49 = getlogin */
	"setlogin",			/* 50 = setlogin */
	"acct",				/* 51 = acct */
	"sigpending",		/* 52 = sigpending */
	"sigaltstack",		/* 53 = sigaltstack */
	"ioctl",			/* 54 = ioctl */
	"reboot",			/* 55 = reboot */
	"revoke",			/* 56 = revoke */
	"symlink",			/* 57 = symlink */
	"readlink",			/* 58 = readlink */
	"execve",			/* 59 = execve */
	"umask",			/* 60 = umask */
	"chroot",			/* 61 = chroot */
	"old_fstat",		/* 62 = old fstat */
	"old_getkerninfo",	/* 63 = old getkerninfo */
	"old_getpagesize",	/* 64 = old getpagesize */
	"msync",			/* 65 = msync */
	"vfork",			/* 66 = vfork */
	"obs_vread",		/* 67 = obsolete vread */
	"obs_vwrite",		/* 68 = obsolete vwrite */
	"sbrk",				/* 69 = sbrk */
	"sstk",				/* 70 = sstk */
	"old_mmap",			/* 71 = old mmap */
	"obs_vadvise",		/* 72 = obsolete vadvise */
	"munmap",			/* 73 = munmap */
	"mprotect",			/* 74 = mprotect */
	"madvise",			/* 75 = madvise */
	"obs_vhangup",		/* 76 = obsolete vhangup */
	"obs_vlimit",		/* 77 = obsolete vlimit */
	"mincore",			/* 78 = mincore */
	"getgroups",		/* 79 = getgroups */
	"setgroups",		/* 80 = setgroups */
	"getpgrp",			/* 81 = getpgrp */
	"setpgid",			/* 82 = setpgid */
	"setitimer",		/* 83 = setitimer */
	"old_wait",			/* 84 = old wait */
	"swapon",			/* 85 = swapon */
	"getitimer",		/* 86 = getitimer */
	"old_gethostname",	/* 87 = old gethostname */
	"old_sethostname",	/* 88 = old sethostname */
	"getdtablesize",	/* 89 = getdtablesize */
	"dup2",				/* 90 = dup2 */
	"#91",				/* 91 = getdopt */
	"fcntl",			/* 92 = fcntl */
	"select",			/* 93 = select */
	"#94",				/* 94 = setdopt */
	"fsync",			/* 95 = fsync */
	"setpriority",		/* 96 = setpriority */
	"socket",			/* 97 = socket */
	"connect",			/* 98 = connect */
	"old_accept",		/* 99 = old accept */
	"getpriority",		/* 100 = getpriority */
	"old_send",			/* 101 = old send */
	"old_recv",			/* 102 = old recv */
	"sigreturn",		/* 103 = sigreturn */
	"bind",				/* 104 = bind */
	"setsockopt",		/* 105 = setsockopt */
	"listen",			/* 106 = listen */
	"obs_vtimes",		/* 107 = obsolete vtimes */
	"old_sigvec",		/* 108 = old sigvec */
	"old_sigblock",		/* 109 = old sigblock */
	"old_sigsetmask",	/* 110 = old sigsetmask */
	"sigsuspend",		/* 111 = sigsuspend */
	"old_sigstack",		/* 112 = old sigstack */
	"old_recvmsg",		/* 113 = old recvmsg */
	"old_sendmsg",		/* 114 = old sendmsg */
	"obs_vtrace",		/* 115 = obsolete vtrace */
	"gettimeofday",		/* 116 = gettimeofday */
	"getrusage",		/* 117 = getrusage */
	"getsockopt",		/* 118 = getsockopt */
	"#119",				/* 119 = nosys */
	"readv",			/* 120 = readv */
	"writev",			/* 121 = writev */
	"settimeofday",		/* 122 = settimeofday */
	"fchown",			/* 123 = fchown */
	"fchmod",			/* 124 = fchmod */
	"old_recvfrom",		/* 125 = old recvfrom */
	"old_setreuid",		/* 126 = old setreuid */
	"old_setregid",		/* 127 = old setregid */
	"rename",			/* 128 = rename */
	"old_truncate",		/* 129 = old truncate */
	"old_ftruncate",	/* 130 = old ftruncate */
	"flock",			/* 131 = flock */
	"mkfifo",			/* 132 = mkfifo */
	"sendto",			/* 133 = sendto */
	"shutdown",			/* 134 = shutdown */
	"socketpair",		/* 135 = socketpair */
	"mkdir",			/* 136 = mkdir */
	"rmdir",			/* 137 = rmdir */
	"utimes",			/* 138 = utimes */
	"#139",				/* 139 = nosys */
	"adjtime",			/* 140 = adjtime */
	"old_getpeername",	/* 141 = old getpeername */
	"old_gethostid",	/* 142 = old gethostid */
	"old_sethostid",	/* 143 = old sethostid */
	"old_getrlimit",	/* 144 = old getrlimit */
	"old_setrlimit",	/* 145 = old setrlimit */
	"old_killpg",		/* 146 = old killpg */
	"setsid",			/* 147 = setsid */
	"obs_setquota",		/* 148 = obsolete setquota */
	"obs_quota",		/* 149 = obsolete quota */
	"old_getsockname",	/* 150 = old getsockname */
	"#151",				/* 151 = nosys */
	"setprivexec",		/* 152 = setprivexec */
	"#153",				/* 153 = nosys */
	"#154",				/* 154 = nosys */
	"nfssvc",			/* 155 = nfssvc */
	"getdirentries",	/* 156 =getdirentries */
	"statfs",			/* 157 = statfs */
	"fstatfs",			/* 158 = fstatfs */
	"unmount",			/* 159 = unmount */
	"obs_async_daemon",	/* 160 = obsolete async_daemon */
	"getfh",			/* 161 = getfh */
	"old_getdomainname",/* 162 = old getdomainname */
	"old_setdomainname",/* 163 = old setdomainname */
	"obs_pcfs_mount",	/* 164 = obsolete pcfs_mount */
	"quotactl",			/* 165 = quotactl */
	"obs_exportfs",		/* 166 = obsolete exportfs */
	"mount",			/* 167 = mount */
	"obs_ustat",		/* 168 = obsolete ustat */
	"#169",				/* 169 = nosys */
	"obs_table",		/* 170 = obsolete table */
	"old_wait_3",		/* 171 = old wait_3 */
	"obs_rpause",		/* 172 = obsolete rpause */
	"#173",				/* 173 = nosys */
	"obs_getdents",		/* 174 = obsolete getdents */
	"#175",				/* 175 = nosys */
	"add_profil",		/* 176 = add_profil */ /* NeXT */
	"#177",				/* 177 = nosys */
	"#178",				/* 178 = nosys */
	"#179",				/* 179 = nosys */
	"kdebug_trace",			/* 180 = kdebug_trace */
	"setgid",			/* 181 = setgid */
	"setegid",			/* 182 = setegid */
	"seteuid",			/* 183 = seteuid */
#ifdef LFS
	"lfs_bmapv",		/* 184 = lfs_bmapv */
	"lfs_markv",		/* 185 = lfs_markv */
	"lfs_segclean",		/* 186 = lfs_segclean */
	"lfs_segwait",		/* 187 = lfs_segwait */
#else
	"#184",				/* 184 = nosys */
	"#185",				/* 185 = nosys */
	"#186",				/* 186 = nosys */
	"#187",				/* 187 = nosys */
#endif
	"stat",				/* 188 = stat */
	"fstat",			/* 189 = fstat */
	"lstat",			/* 190 = lstat */
	"pathconf",			/* 191 = pathconf */
	"fpathconf",		/* 192 = fpathconf */
	"#193",				/* 193 = nosys */
	"getrlimit",		/* 194 = getrlimit */
	"setrlimit",		/* 195 = setrlimit */
	"#196",				/* 196 = unused */
	"mmap",				/* 197 = mmap */
	"__syscall",		/* 198 = __syscall */
	"lseek",			/* 199 = lseek */
	"truncate",			/* 200 = truncate */
	"ftruncate",		/* 201 = ftruncate */
	"__sysctl",			/* 202 = __sysctl */
	"mlock",			/* 203 = mlock */
	"munlock",			/* 204 = munlock */
	"#205",			/* 205 = nosys */

	/*
	 * 206 - 215 are all reserved for AppleTalk.
	 * When AppleTalk is defined some of them are in use
	 */

	"#206",			/* 206 = nosys */
	"#207",			/* 207 = nosys */
	"#208",			/* 208 = nosys */
	"#209",			/* 209 = nosys */
	"#210",			/* 210 = nosys */
	"#211",			/* 205 = nosys */
	"#212",			/* 206 = nosys */
	"#213",			/* 207 = nosys */
	"#214",			/* 208 = nosys */
	"#215",			/* 209 = nosys */
	"mkcomplex",		/* 216 = mkcomplex	*/
	"statv",		/* 217 = stav		*/		
	"lstatv",		/* 218 = lstav 		*/			
	"fstatv",		/* 219 = fstav 		*/			
	"getattrlist",		/* 220 = getattrlist 	*/		
	"setattrlist",		/* 221 = setattrlist 	*/		
	"getdirentriesattr",	/* 222 = getdirentriesattr*/	
	"exchangedata",		/* 223 = exchangedata   */			
	"checkuseraccess",	/* 224 - checkuseraccess*/
	"searchfs",		/* 225 = searchfs */
	"#226",			/* 226 = private delete call */
	"#227",			/* 227 = copyfile  */
	"#228",			/* 228 = nosys */
	"#229",			/* 229 = nosys */
	"#230",			/* 230 = reserved for AFS */
		
	/*
	 * 216 - 230 are all reserved for suppoorting HFS/AFP File System
	 * Semantics.  225-230 are reserved for future use.
	 */
	"watchevent",		/* 231 = watchevent */
	"waitevent",		/* 232 = waitevent */
	"modwatch",		/* 233 = modwatch */
	"#234",			/* 234 = nosys */
	"#235",			/* 235 = nosys */
	"#236",			/* 236 = nosys */
	"#237",			/* 237 = nosys */
	"#238",			/* 238 = nosys */
	"#239",			/* 239 = nosys */
	"#240",			/* 240 = nosys */
	"#241",			/* 241 = nosys */
	"#242",			/* 242 = nosys */
	"#243",			/* 243 = nosys */
	"#244",			/* 244 = nosys */
	"#245",			/* 245 = nosys */
	"#246",			/* 246 = nosys */
	"#247",			/* 247 = nosys */
	"#248",			/* 248 = nosys */
	"#249",			/* 249 = nosys */
	"minherit",		/* 250 = minherit */
	"semsys",		/* 251 = semsys */
	"msgsys",		/* 252 = msgsys */
	"shmsys",		/* 253 = shmsys */
	"semctl",		/* 254 = semctl */
	"semget",		/* 255 = semget */
	"semop",		/* 256 = semop */
	"semconfig",		/* 257 = semconfig */
	"msgctl",		/* 258 = msgctl */
	"msgget",		/* 259 = msgget */
	"msgsnd",		/* 260 = msgsnd */
	"msgrcv",		/* 261 = msgrcv */
	"shmat",		/* 262 = shmat */
	"shmctl",		/* 263 = shmctl */
	"shmdt",		/* 264 = shmdt */
	"shmget",		/* 265 = shmget */
	"shm_open",		/* 266 = shm_open */
	"shm_unlink",		/* 267 = shm_unlink */
	"sem_open",		/* 268 = sem_open */
	"sem_close",		/* 269 = sem_close */
	"sem_unlink",		/* 270 = sem_unlink */
	"sem_wait",		/* 271 = sem_wait */
	"sem_trywait",		/* 272 = sem_trywait */
	"sem_post",		/* 273 = sem_post */
	"sem_getvalue",		/* 274 = sem_getvalue */
	"sem_init",		/* 275 = sem_init */
	"sem_destroy",		/* 276 = sem_destroy */
	"#277",			/* 277 = nosys */
	"#278",			/* 278 = nosys */
	"#279",			/* 279 = nosys */
	"#280",			/* 280 = nosys */
	"#281",			/* 281 = nosys */
	"#282",			/* 282 = nosys */
	"#283",			/* 283 = nosys */
	"#284",			/* 284 = nosys */
	"#285",			/* 285 = nosys */
	"#286",			/* 286 = nosys */
	"#287",			/* 287 = nosys */
	"#288",			/* 288 = nosys */
	"#289",			/* 289 = nosys */
	"#290",			/* 290 = nosys */
	"#291",			/* 291 = nosys */
	"#292",			/* 292 = nosys */
	"#293",			/* 293 = nosys */
	"#294",			/* 294 = nosys */
	"#295",			/* 295 = nosys */
	"load_shared_file",	/* 296 = load_shared_file */
	"reset_shared_file",	/* 297 = reset_shared_file */
	"#298",			/* 298 = nosys */
	"#299",			/* 299 = nosys */
	"#300",			/* 300 = modnext */
	"#301",			/* 301 = modstat */
	"#302",			/* 302 = modfnext */
	"#303",			/* 303 = modfind */
	"#304",			/* 304 = kldload */
	"#305",			/* 305 = kldunload */
	"#306",			/* 306 = kldfind */
	"#307",			/* 307 = kldnext */
	"#308",			/* 308 = kldstat */
	"#309",			/* 309 = kldfirstmod */
	"#310",			/* 310 = getsid */
	"#311",			/* 311 = setresuid */
	"#312",			/* 312 = setresgid */
	"#313",			/* 313 = obsolete signanosleep */
	"#314",			/* 314 = aio_return */
	"#315",			/* 315 = aio_suspend */
	"#316",			/* 316 = aio_cancel */
	"#317",			/* 317 = aio_error */
	"#318",			/* 318 = aio_read */
	"#319",			/* 319 = aio_write */
	"#320",			/* 320 = lio_listio */
	"#321",			/* 321 = yield */
	"#322",			/* 322 = thr_sleep */
	"#323",			/* 323 = thr_wakeup */
	"mlockall",		/* 324 = mlockall */
	"munlockall",	/* 325 = munlockall */
	"#326",			/* 326 */
	"issetugid"		/* 327 = issetugid */
};
