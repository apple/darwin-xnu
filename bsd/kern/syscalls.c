/*
 * Copyright (c) 2000-2002 Apple Computer, Inc. All rights reserved.
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
/* Copyright (c) 1992,1995-1999 Apple Computer, Inc.  All rights resereved. */

char *syscallnames[] = {
	"syscall",			/* 0 = syscall */
	"exit",				/* 1 = exit */
	"fork",				/* 2 = fork */
	"read",				/* 3 = read */
	"write",			/* 4 = write */
	"open",				/* 5 = open */
	"close",			/* 6 = close */
	"wait4",			/* 7 = wait4 */
	"obs_creat",		/* 8 = old creat */
	"link",				/* 9 = link */
	"unlink",			/* 10 = unlink */
	"obs_execv",		/* 11 = obsolete execv */
	"chdir",			/* 12 = chdir */
	"fchdir",			/* 13 = fchdir */
	"mknod",			/* 14 = mknod */
	"chmod",			/* 15 = chmod */
	"chown",			/* 16 = chown */
	"obs_break",		/* 17 = obsolete break */
	"obs_getfsstat",	/* 18 = obsolete getfsstat */
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
	"obs_stat",			/* 38 = old stat */
	"getppid",			/* 39 = getppid */
	"obs_lstat",		/* 40 = old lstat */
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
	"obs_fstat",		/* 62 = old fstat */
	"#63",				/* 63 = reserved */
	"obs_getpagesize",	/* 64 = old getpagesize */
	"msync",			/* 65 = msync */
	"vfork",			/* 66 = vfork */
	"obs_vread",		/* 67 = obsolete vread */
	"obs_vwrite",		/* 68 = obsolete vwrite */
	"sbrk",				/* 69 = sbrk */
	"sstk",				/* 70 = sstk */
	"obs_mmap",			/* 71 = old mmap */
	"obs_vadvise",		/* 72 = obsolete vadvise */
	"munmap",			/* 73 = munmap */
	"mprotect",			/* 74 = mprotect */
	"madvise",			/* 75 = madvise */
	"#76",				/* 76 = obsolete vhangup */
	"#77",				/* 77 = obsolete vlimit */
	"mincore",			/* 78 = mincore */
	"getgroups",		/* 79 = getgroups */
	"setgroups",		/* 80 = setgroups */
	"getpgrp",			/* 81 = getpgrp */
	"setpgid",			/* 82 = setpgid */
	"setitimer",		/* 83 = setitimer */
	"old_wait",			/* 84 = old wait */
	"obs_swapon",		/* 85 = swapon */
	"getitimer",		/* 86 = getitimer */
	"obs_gethostname",	/* 87 = old gethostname */
	"obs_sethostname",	/* 88 = old sethostname */
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
	"obs_accept",		/* 99 = old accept */
	"getpriority",		/* 100 = getpriority */
	"old_send",			/* 101 = old send */
	"old_recv",			/* 102 = old recv */
	"sigreturn",		/* 103 = sigreturn */
	"bind",				/* 104 = bind */
	"setsockopt",		/* 105 = setsockopt */
	"listen",			/* 106 = listen */
	"#107",				/* 107 = obsolete vtimes */
	"obs_sigvec",		/* 108 = old sigvec */
	"obs_sigblock",		/* 109 = old sigblock */
	"obs_sigsetmask",	/* 110 = old sigsetmask */
	"sigsuspend",		/* 111 = sigsuspend */
	"obs_sigstack",		/* 112 = old sigstack */
	"obs_recvmsg",		/* 113 = old recvmsg */
	"obs_sendmsg",		/* 114 = old sendmsg */
	"#115",				/* 115 = obsolete vtrace */
	"gettimeofday",		/* 116 = gettimeofday */
	"getrusage",		/* 117 = getrusage */
	"getsockopt",		/* 118 = getsockopt */
	"#119",				/* 119 = nosys */
	"readv",			/* 120 = readv */
	"writev",			/* 121 = writev */
	"settimeofday",		/* 122 = settimeofday */
	"fchown",			/* 123 = fchown */
	"fchmod",			/* 124 = fchmod */
	"obs_recvfrom",		/* 125 = old recvfrom */
	"obs_setreuid",		/* 126 = old setreuid */
	"obs_setregid",		/* 127 = old setregid */
	"rename",			/* 128 = rename */
	"obs_truncate",		/* 129 = old truncate */
	"obs_ftruncate",	/* 130 = old ftruncate */
	"flock",			/* 131 = flock */
	"mkfifo",			/* 132 = mkfifo */
	"sendto",			/* 133 = sendto */
	"shutdown",			/* 134 = shutdown */
	"socketpair",		/* 135 = socketpair */
	"mkdir",			/* 136 = mkdir */
	"rmdir",			/* 137 = rmdir */
	"utimes",			/* 138 = utimes */
	"futimes",			/* 139 = futimes */
	"adjtime",			/* 140 = adjtime */
	"obs_getpeername",	/* 141 = old getpeername */
	"obs_gethostid",	/* 142 = old gethostid */
	"#143",				/* 143 = old sethostid */
	"obs_getrlimit",	/* 144 = old getrlimit */
	"obs_setrlimit",	/* 145 = old setrlimit */
	"obs_killpg",		/* 146 = old killpg */
	"setsid",			/* 147 = setsid */
	"#148",				/* 148 = obsolete setquota */
	"#149",				/* 149 = obsolete qquota */
	"obs_getsockname",	/* 150 = old getsockname */
	"getpgid",			/* 151 = getpgid */
	"setprivexec",		/* 152 = setprivexec */
	"pread",			/* 153 = pread */
	"pwrite",			/* 154 = pwrite */
	"nfssvc",			/* 155 = nfssvc */
	"getdirentries",	/* 156 =getdirentries */
	"statfs",			/* 157 = statfs */
	"fstatfs",			/* 158 = fstatfs */
	"unmount",			/* 159 = unmount */
	"#160",				/* 160 = obsolete async_daemon */
	"getfh",			/* 161 = getfh */
	"obs_getdomainname",/* 162 = old getdomainname */
	"obs_setdomainname",/* 163 = old setdomainname */
	"#164",				/* 164 */
	"quotactl",			/* 165 = quotactl */
	"#166",				/* 166 = obsolete exportfs */
	"mount",			/* 167 = mount */
	"#168",				/* 168 = obsolete ustat */
	"#169",				/* 169 = nosys */
	"#170",				/* 170 = obsolete table */
	"obs_wait3",		/* 171 = old wait3 */
	"#172",				/* 172 = obsolete rpause */
	"#173",				/* 173 = nosys */
	"#174",				/* 174 = obsolete getdents */
	"#175",				/* 175 = nosys */
	"add_profil",		/* 176 = add_profil */ /* NeXT */
	"#177",				/* 177 = nosys */
	"#178",				/* 178 = nosys */
	"#179",				/* 179 = nosys */
	"kdebug_trace",		/* 180 = kdebug_trace */
	"setgid",			/* 181 = setgid */
	"setegid",			/* 182 = setegid */
	"seteuid",			/* 183 = seteuid */
	"#184",				/* 184 = nosys */
	"#185",				/* 185 = nosys */
	"#186",				/* 186 = nosys */
	"#187",				/* 187 = nosys */
	"stat",				/* 188 = stat */
	"fstat",			/* 189 = fstat */
	"lstat",			/* 190 = lstat */
	"pathconf",			/* 191 = pathconf */
	"fpathconf",		/* 192 = fpathconf */
	"obs_getfsstat",	/* 193 = old getfsstat */
	"getrlimit",		/* 194 = getrlimit */
	"setrlimit",		/* 195 = setrlimit */
	"getdirentries",	/* 196 = getdirentries */
	"mmap",				/* 197 = mmap */
	"#198",				/* 198 = __syscall */
	"lseek",			/* 199 = lseek */
	"truncate",			/* 200 = truncate */
	"ftruncate",		/* 201 = ftruncate */
	"__sysctl",			/* 202 = __sysctl */
	"mlock",			/* 203 = mlock */
	"munlock",			/* 204 = munlock */
	"undelete",			/* 205 = undelete */
	"ATsocket",			/* 206 = ATsocket */
	"ATgetmsg",			/* 207 = ATgetmsg */
	"ATputmsg",			/* 208 = ATputmsg */
	"ATPsndreq",		/* 209 = ATPsndreq */
	"ATPsndrsp",		/* 210 = ATPsndrsp */
	"ATPgetreq",		/* 211 = ATPgetreq */
	"ATPgetrsp",		/* 212 = ATPgetrsp */
	"#213",				/* 213 = Reserved for AppleTalk */
	"#214",				/* 214 = Reserved for AppleTalk */
	"#215",				/* 215 = Reserved for AppleTalk */
	"#216",				/* 216 = Reserved */
	"#217",				/* 217 = Reserved */
	"#218",				/* 218 = Reserved */
	"#219",				/* 219 = Reserved */
	"getattrlist",		/* 220 = getattrlist */
	"setattrlist",		/* 221 = setattrlist */
	"getdirentriesattr",	/* 222 = getdirentriesattr */
	"exchangedata",		/* 223 = exchangedata */
	"checkuseraccess",	/* 224 - checkuseraccess */
	"searchfs",			/* 225 = searchfs */
	"delete",			/* 226 = private delete call */
	"copyfile",			/* 227 = copyfile  */
	"#228",				/* 228 = nosys */
	"#229",				/* 229 = nosys */
	"#230",				/* 230 = reserved for AFS */
	"watchevent",		/* 231 = watchevent */
	"waitevent",		/* 232 = waitevent */
	"modwatch",			/* 233 = modwatch */
	"#234",				/* 234 = nosys */
	"#235",				/* 235 = nosys */
	"#236",				/* 236 = nosys */
	"#237",				/* 237 = nosys */
	"#238",				/* 238 = nosys */
	"#239",				/* 239 = nosys */
	"#240",				/* 240 = nosys */
	"#241",				/* 241 = nosys */
	"fsctl",			/* 242 = fsctl */
	"#243",				/* 243 = nosys */
	"#244",				/* 244 = nosys */
	"#245",				/* 245 = nosys */
	"#246",				/* 246 = nosys */
	"#247",				/* 247 = nosys */
	"#248",				/* 248 = nosys */
	"#249",				/* 249 = nosys */
	"minherit",			/* 250 = minherit */
	"semsys",			/* 251 = semsys */
	"msgsys",			/* 252 = msgsys */
	"shmsys",			/* 253 = shmsys */
	"semctl",			/* 254 = semctl */
	"semget",			/* 255 = semget */
	"semop",			/* 256 = semop */
	"semconfig",		/* 257 = semconfig */
	"msgctl",			/* 258 = msgctl */
	"msgget",			/* 259 = msgget */
	"msgsnd",			/* 260 = msgsnd */
	"msgrcv",			/* 261 = msgrcv */
	"shmat",			/* 262 = shmat */
	"shmctl",			/* 263 = shmctl */
	"shmdt",			/* 264 = shmdt */
	"shmget",			/* 265 = shmget */
	"shm_open",			/* 266 = shm_open */
	"shm_unlink",		/* 267 = shm_unlink */
	"sem_open",			/* 268 = sem_open */
	"sem_close",		/* 269 = sem_close */
	"sem_unlink",		/* 270 = sem_unlink */
	"sem_wait",			/* 271 = sem_wait */
	"sem_trywait",		/* 272 = sem_trywait */
	"sem_post",			/* 273 = sem_post */
	"sem_getvalue",		/* 274 = sem_getvalue */
	"sem_init",			/* 275 = sem_init */
	"sem_destroy",		/* 276 = sem_destroy */
	"#277",				/* 277 = nosys */
	"#278",				/* 278 = nosys */
	"#279",				/* 279 = nosys */
	"#280",				/* 280 = nosys */
	"#281",				/* 281 = nosys */
	"#282",				/* 282 = nosys */
	"#283",				/* 283 = nosys */
	"#284",				/* 284 = nosys */
	"#285",				/* 285 = nosys */
	"#286",				/* 286 = nosys */
	"#287",				/* 287 = nosys */
	"#288",				/* 288 = nosys */
	"#289",				/* 289 = nosys */
	"#290",				/* 290 = nosys */
	"#291",				/* 291 = nosys */
	"#292",				/* 292 = nosys */
	"#293",				/* 293 = nosys */
	"#294",				/* 294 = nosys */
	"#295",				/* 295 = nosys */
	"load_shared_file",	/* 296 = load_shared_file */
	"reset_shared_file",	/* 297 = reset_shared_file */
	"new_system_shared_regions",	/* 298 = new_system_shared_regions */
	"#299",				/* 299 = nosys */
	"#300",				/* 300 = modnext */
	"#301",				/* 301 = modstat */
	"#302",				/* 302 = modfnext */
	"#303",				/* 303 = modfind */
	"#304",				/* 304 = kldload */
	"#305",				/* 305 = kldunload */
	"#306",				/* 306 = kldfind */
	"#307",				/* 307 = kldnext */
	"#308",				/* 308 = kldstat */
	"#309",				/* 309 = kldfirstmod */
	"getsid",			/* 310 = getsid */
	"#311",				/* 311 = setresuid */
	"#312",				/* 312 = setresgid */
	"#313",				/* 313 = obsolete signanosleep */
	"#314",				/* 314 = aio_return */
	"#315",				/* 315 = aio_suspend */
	"#316",				/* 316 = aio_cancel */
	"#317",				/* 317 = aio_error */
	"#318",				/* 318 = aio_read */
	"#319",				/* 319 = aio_write */
	"#320",				/* 320 = lio_listio */
	"#321",				/* 321 = yield */
	"#322",				/* 322 = thr_sleep */
	"#323",				/* 323 = thr_wakeup */
	"mlockall",			/* 324 = mlockall */
	"munlockall",		/* 325 = munlockall */
	"#326",				/* 326 */
	"issetugid",		/* 327 = issetugid */
	"__pthread_kill",	/* 328  = __pthread_kill */
	"pthread_sigmask",	/* 329  = pthread_sigmask */
	"sigwait",			/* 330 = sigwait */
	"#331",				/* 331 */
	"#332",				/* 332 */
	"#333",				/* 333 */
	"#334",				/* 334 */
	"utrace",			/* 335 = utrace */
	"#336",				/* 336 */
	"#337",				/* 337 */
	"#338",				/* 338 */
	"#339",				/* 339 */
	"#340",				/* 340 */
	"#341",				/* 341 */
	"#342",				/* 342 */
	"#343",				/* 343 */
	"#344",				/* 344 */
	"#345",				/* 345 */
	"#346",				/* 346 */
	"#347",				/* 347 */
	"#348",				/* 348 */
	"#349"				/* 349 */
};
