/*
 * Copyright (c) 2003 Apple Computer, Inc. All rights reserved.
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

#include <sys/types.h>
#include <sys/vnode.h>
#include <sys/fcntl.h>
#include <sys/filedesc.h>
#include <sys/sem.h>
#include <sys/audit.h>
#include <sys/kern_audit.h>
#include <sys/bsm_kevents.h>
#include <sys/bsm_klib.h>

/*
 * Initialize the system call to audit event mapping table. This table 
 * must be kept in sync with the system call table. This table is meant to
 * be directly accessed. 
 * XXX This should be improved, though, to make it independent of the syscall
 * table (but we don't want to traverse a large table for every system call
 * to find a match). Ultimately, it would be best to place the audit event
 * number in the system call table.
 */
au_event_t sys_au_event[] = {
	AUE_NULL,			/*   0 = indir */
	AUE_EXIT,			/*   1 = exit */
	AUE_NULL,			/*   2 = fork */
	AUE_NULL,			/*   3 = read */
	AUE_NULL,			/*   4 = write */
	AUE_OPEN_R,			/*   5 = open */
	AUE_NULL,			/*   6 = close */
	AUE_NULL,			/*   7 = wait4 */
	AUE_NULL,			/*   8 = old creat */
	AUE_LINK,			/*   9 = link */
	AUE_UNLINK,			/*  10 = unlink */
	AUE_NULL,			/*  11 was obsolete execv */
	AUE_CHDIR,			/*  12 = chdir */
	AUE_FCHDIR,			/*  13 = fchdir */
	AUE_MKNOD,			/*  14 = mknod */
	AUE_CHMOD,			/*  15 = chmod */
	AUE_CHOWN,			/*  16 = chown; now 3 args */
	AUE_NULL,			/*  17 = old break */
#if COMPAT_GETFSSTAT
	AUE_NULL,			/*  18 = ogetfsstat */
#else
	AUE_GETFSSTAT,			/*  18 = getfsstat */
#endif
	AUE_NULL,			/*  19 = old lseek */
	AUE_NULL,			/*  20 = getpid */
	AUE_NULL,			/*  21 was obsolete mount */
	AUE_NULL,			/*  22 was obsolete umount */
	AUE_SETUID,			/*  23 = setuid */
	AUE_NULL,			/*  24 = getuid */
	AUE_NULL,			/*  25 = geteuid */
	AUE_NULL,			/*  26 = ptrace */
	AUE_RECVMSG,			/*  27 = recvmsg */
	AUE_SENDMSG,			/*  28 = sendmsg */
	AUE_RECVFROM,			/*  29 = recvfrom */
	AUE_ACCEPT,			/*  30 = accept */
	AUE_NULL,			/*  31 = getpeername */
	AUE_NULL,			/*  32 = getsockname */
	AUE_ACCESS,			/*  33 = access */
	AUE_CHFLAGS,			/* 34 = chflags */
	AUE_FCHFLAGS,			/* 35 = fchflags */
	AUE_NULL,			/*  36 = sync */
	AUE_NULL,			/*  37 = kill */
	AUE_NULL,			/*  38 = old stat */
	AUE_NULL,			/*  39 = getppid */
	AUE_NULL,			/*  40 = old lstat */
	AUE_NULL,			/*  41 = dup */
	AUE_PIPE,			/*  42 = pipe */
	AUE_NULL,			/*  43 = getegid */
	AUE_NULL,			/*  44 = profil */
	AUE_NULL,			/*  45 = ktrace */
	AUE_NULL,			/*  46 = sigaction */
	AUE_NULL,			/*  47 = getgid */
	AUE_NULL,			/*  48 = sigprocmask */
	AUE_NULL,			/*  49 = getlogin */
	AUE_NULL,			/*  50 = setlogin */
	AUE_NULL,			/*  51 = turn acct off/on */
	AUE_NULL,			/*  52 = sigpending */
	AUE_NULL,			/*  53 = sigaltstack */
	AUE_NULL,			/*  54 = ioctl */
	AUE_NULL,			/*  55 = reboot */
	AUE_REVOKE,			/*  56 = revoke */
	AUE_SYMLINK,			/*  57 = symlink */
	AUE_READLINK,			/*  58 = readlink */
	AUE_EXECVE,			/*  59 = execve */
	AUE_UMASK,			/*  60 = umask */
	AUE_CHROOT,			/*  61 = chroot */
	AUE_NULL,			/*  62 = old fstat */
	AUE_NULL,			/*  63 = used internally, reserved */
	AUE_NULL,			/*  64 = old getpagesize */
	AUE_NULL,			/*  65 = msync */
	AUE_NULL,			/*  66 = vfork */
	AUE_NULL,			/*  67 was obsolete vread */
	AUE_NULL,			/*  68 was obsolete vwrite */
	AUE_NULL,			/*  69 = sbrk */
	AUE_NULL,			/*  70 = sstk */
	AUE_NULL,			/*  71 = old mmap */
	AUE_NULL,			/*  72 = old vadvise */
	AUE_NULL,			/*  73 = munmap */
	AUE_NULL,			/*  74 = mprotect */
	AUE_NULL,			/*  75 = madvise */
	AUE_NULL,			/*  76 was obsolete vhangup */
	AUE_NULL,			/*  77 was obsolete vlimit */
	AUE_NULL,			/*  78 = mincore */
	AUE_NULL,			/*  79 = getgroups */
	AUE_SETGROUPS,			/*  80 = setgroups */
	AUE_NULL,			/*  81 = getpgrp */
	AUE_SETPGRP,			/*  82 = setpgid */
	AUE_NULL,			/*  83 = setitimer */
	AUE_NULL,			/*  84 = old wait */
	AUE_NULL,			/*  85 = swapon */
	AUE_NULL,			/*  86 = getitimer */
	AUE_NULL,			/*  87 = old gethostname */
	AUE_NULL,			/*  88 = old sethostname */
	AUE_NULL,			/* 89 getdtablesize */
	AUE_NULL,			/*  90 = dup2 */
	AUE_NULL,			/*  91 was obsolete getdopt */
	AUE_FCNTL,			/*  92 = fcntl */
	AUE_NULL,			/*  93 = select */
	AUE_NULL,			/*  94 was obsolete setdopt */
	AUE_NULL,			/*  95 = fsync */
	AUE_NULL,			/*  96 = setpriority */
	AUE_SOCKET,			/*  97 = socket */
	AUE_CONNECT,			/*  98 = connect */
	AUE_NULL,			/*  99 = accept */
	AUE_NULL,			/* 100 = getpriority */
	AUE_NULL,			/* 101 = old send */
	AUE_NULL,			/* 102 = old recv */
	AUE_NULL,			/* 103 = sigreturn */
	AUE_BIND,			/* 104 = bind */
	AUE_SETSOCKOPT,			/* 105 = setsockopt */
	AUE_NULL,			/* 106 = listen */
	AUE_NULL,			/* 107 was vtimes */
	AUE_NULL,			/* 108 = sigvec */
	AUE_NULL,			/* 109 = sigblock */
	AUE_NULL,			/* 110 = sigsetmask */
	AUE_NULL,			/* 111 = sigpause */
	AUE_NULL,			/* 112 = sigstack */
	AUE_NULL,			/* 113 = recvmsg */
	AUE_NULL,			/* 114 = sendmsg */
	AUE_NULL,			/* 115 = old vtrace */
	AUE_NULL,			/* 116 = gettimeofday */
	AUE_NULL,			/* 117 = getrusage */
	AUE_NULL,			/* 118 = getsockopt */
	AUE_NULL,			/* 119 = old resuba */
	AUE_NULL,			/* 120 = readv */
	AUE_NULL,			/* 121 = writev */
	AUE_NULL,			/* 122 = settimeofday */
	AUE_FCHOWN,			/* 123 = fchown */
	AUE_FCHMOD,			/* 124 = fchmod */
	AUE_NULL,			/* 125 = recvfrom */
	AUE_NULL,			/* 126 = setreuid */
	AUE_NULL,			/* 127 = setregid */
	AUE_RENAME,			/* 128 = rename */
	AUE_NULL,			/* 129 = old truncate */
	AUE_NULL,			/* 130 = old ftruncate */
	AUE_FLOCK,			/* 131 = flock */
	AUE_MKFIFO,			/* 132 = mkfifo */
	AUE_SENDTO,			/* 133 = sendto */
	AUE_SHUTDOWN,			/* 134 = shutdown */
	AUE_SOCKETPAIR,			/* 135 = socketpair */
	AUE_MKDIR,			/* 136 = mkdir */
	AUE_RMDIR,			/* 137 = rmdir */
	AUE_UTIMES,			/* 138 = utimes */
	AUE_FUTIMES,			/* 139 = futimes */
	AUE_ADJTIME,			/* 140 = adjtime */
	AUE_NULL,			/* 141 = getpeername */
	AUE_NULL,			/* 142 = old gethostid */
	AUE_NULL,			/* 143 = old sethostid */
	AUE_NULL,			/* 144 = old getrlimit */
	AUE_NULL,			/* 145 = old setrlimit */
	AUE_NULL,			/* 146 = old killpg */
	AUE_NULL,			/* 147 = setsid */
	AUE_NULL,			/* 148 was setquota */
	AUE_NULL,			/* 149 was qquota */
	AUE_NULL,			/* 150 = getsockname */
	AUE_NULL,			/* 151 = getpgid */
	AUE_NULL,			/* 152 = setprivexec */
	AUE_NULL,			/* 153 = pread */
	AUE_NULL,			/* 154 = pwrite */
	AUE_NULL,			/* 155 = nfs_svc */
	AUE_NULL,			/* 156 = old getdirentries */
	AUE_STATFS,			/* 157 = statfs */
	AUE_FSTATFS,			/* 158 = fstatfs */
	AUE_UMOUNT,			/* 159 = unmount */
	AUE_NULL,			/* 160 was async_daemon */
	AUE_GETFH,			/* 161 = get file handle */
	AUE_NULL,			/* 162 = getdomainname */
	AUE_NULL,			/* 163 = setdomainname */
	AUE_NULL,			/* 164 */
#if	QUOTA
	AUE_QUOTACTL,			/* 165 = quotactl */
#else	/* QUOTA */
	AUE_NULL,			/* 165 = not configured */
#endif	/* QUOTA */
	AUE_NULL,			/* 166 was exportfs */
	AUE_MOUNT,			/* 167 = mount */
	AUE_NULL,			/* 168 was ustat */
	AUE_NULL,			/* 169 = nosys */
	AUE_NULL,			/* 170 was table */
	AUE_NULL,			/* 171 = old wait3 */
	AUE_NULL,			/* 172 was rpause */
	AUE_NULL,			/* 173 = nosys */
	AUE_NULL,			/* 174 was getdents */
	AUE_NULL,			/* 175 was gc_control */
	AUE_NULL,			/* 176 = add_profil */
	AUE_NULL,			/* 177 */
	AUE_NULL,			/* 178 */
	AUE_NULL,			/* 179 */
	AUE_NULL,			/* 180 */
	AUE_SETGID,			/* 181 */
	AUE_SETEGID,			/* 182 */
	AUE_SETEUID,			/* 183 */
	AUE_NULL,			/* 184 = nosys */
	AUE_NULL,			/* 185 = nosys */
	AUE_NULL,			/* 186 = nosys */
	AUE_NULL,			/* 187 = nosys */
	AUE_STAT,			/* 188 = stat */
	AUE_FSTAT,			/* 189 = fstat */
	AUE_LSTAT,			/* 190 = lstat */
	AUE_PATHCONF,			/* 191 = pathconf */
	AUE_FPATHCONF,			/* 192 = fpathconf */

#if COMPAT_GETFSSTAT
	AUE_GETFSSTAT,			/* 193 = getfsstat */
#else
	AUE_NULL,			/* 193 is unused */ 
#endif
	AUE_NULL,			/* 194 = getrlimit */
	AUE_SETRLIMIT,			/* 195 = setrlimit */
	AUE_GETDIRENTRIES,		/* 196 = getdirentries */
	AUE_NULL,			/* 197 = mmap */
	AUE_NULL,			/* 198 = __syscall */
	AUE_NULL,			/* 199 = lseek */
	AUE_TRUNCATE,			/* 200 = truncate */
	AUE_FTRUNCATE,			/* 201 = ftruncate */
	AUE_NULL,			/* 202 = __sysctl */
	AUE_NULL,			/* 203 = mlock */
	AUE_NULL,			/* 204 = munlock */
	AUE_UNDELETE,			/* 205 = undelete */
	AUE_NULL,			/* 206 = ATsocket */
	AUE_NULL,			/* 207 = ATgetmsg*/
	AUE_NULL,			/* 208 = ATputmsg*/
	AUE_NULL,			/* 209 = ATPsndreq*/
	AUE_NULL,			/* 210 = ATPsndrsp*/
	AUE_NULL,			/* 211 = ATPgetreq*/
	AUE_NULL,			/* 212 = ATPgetrsp*/
	AUE_NULL,			/* 213 = Reserved for AppleTalk */
	AUE_NULL,			/* 214 = Reserved for AppleTalk */
	AUE_NULL,			/* 215 = Reserved for AppleTalk */
	
	AUE_NULL,	/* 216 = HFS make complex file call (multipel forks */
	AUE_NULL,	/* 217 = HFS statv extended stat call for HFS */
	AUE_NULL,	/* 218 = HFS lstatv extended lstat call for HFS */	
	AUE_NULL,	/* 219 = HFS fstatv extended fstat call for HFS */
	AUE_GETATTRLIST,/* 220 = HFS getarrtlist get attribute list cal */
	AUE_SETATTRLIST,/* 221 = HFS setattrlist set attribute list */
	AUE_GETDIRENTRIESATTR,/* 222 = HFS getdirentriesattr get directory attributes */
	AUE_EXCHANGEDATA,/* 223 = HFS exchangedata exchange file contents */
	AUE_NULL,/* 224 = HFS checkuseraccess check access to a file */
	AUE_SEARCHFS,	/* 225 = HFS searchfs to implement catalog searching */
	AUE_NULL,	/* 226 = private delete (Carbon semantics) */
	AUE_NULL,	/* 227 = copyfile - orignally for AFP */
	AUE_NULL,			/* 228 */
	AUE_NULL,			/* 229 */
	AUE_NULL,			/* 230 */
	AUE_NULL,			/* 231 */
	AUE_NULL,			/* 232 */
	AUE_NULL,			/* 233 */
	AUE_NULL,			/* 234 */
	AUE_NULL,			/* 235 */
	AUE_NULL,			/* 236 */
	AUE_NULL,			/* 237 */
	AUE_NULL,			/* 238 */
	AUE_NULL,			/* 239 */
	AUE_NULL,			/* 240 */
	AUE_NULL,			/* 241 */
	AUE_NULL,			/* 242 = fsctl */
	AUE_NULL,			/* 243 */
	AUE_NULL,			/* 244 */
	AUE_NULL,			/* 245 */
	AUE_NULL,			/* 246 */
	AUE_NULL,			/* 247 = nfsclnt*/
	AUE_NULL,			/* 248 = fhopen */
	AUE_NULL,			/* 249 */
	AUE_NULL,			/* 250 = minherit */
	AUE_NULL,			/* 251 = semsys */
	AUE_NULL,			/* 252 = msgsys */
	AUE_NULL,			/* 253 = shmsys */
	AUE_SEMCTL,			/* 254 = semctl */
	AUE_SEMGET,			/* 255 = semget */
	AUE_SEMOP,			/* 256 = semop */
	AUE_NULL,			/* 257 = semconfig */
	AUE_MSGCTL,			/* 258 = msgctl */
	AUE_MSGGET,			/* 259 = msgget */
	AUE_MSGSND,			/* 260 = msgsnd */
	AUE_MSGRCV,			/* 261 = msgrcv */
	AUE_SHMAT,			/* 262 = shmat */
	AUE_SHMCTL,			/* 263 = shmctl */
	AUE_SHMDT,			/* 264 = shmdt */
	AUE_SHMGET,			/* 265 = shmget */
	AUE_NULL,			/* 266 = shm_open */
	AUE_NULL,			/* 267 = shm_unlink */
	AUE_NULL,			/* 268 = sem_open */
	AUE_NULL,			/* 269 = sem_close */
	AUE_NULL,			/* 270 = sem_unlink */
	AUE_NULL,			/* 271 = sem_wait */
	AUE_NULL,			/* 272 = sem_trywait */
	AUE_NULL,			/* 273 = sem_post */
	AUE_NULL,			/* 274 = sem_getvalue */
	AUE_NULL,			/* 275 = sem_init */
	AUE_NULL,			/* 276 = sem_destroy */
	AUE_NULL,			/* 277 */
	AUE_NULL,			/* 278 */
	AUE_NULL,			/* 279 */
	AUE_NULL,			/* 280 */
	AUE_NULL,			/* 281 */
	AUE_NULL,			/* 282 */
	AUE_NULL,			/* 283 */
	AUE_NULL,			/* 284 */
	AUE_NULL,			/* 285 */
	AUE_NULL,			/* 286 */
	AUE_NULL,			/* 287 */
	AUE_NULL,			/* 288 */
	AUE_NULL,			/* 289 */
	AUE_NULL,			/* 290 */
	AUE_NULL,			/* 291 */
	AUE_NULL,			/* 292 */
	AUE_NULL,			/* 293 */
	AUE_NULL,			/* 294 */
	AUE_NULL,			/* 295 */
	AUE_NULL, 			/* 296 = load_shared_file */
	AUE_NULL, 			/* 297 = reset_shared_file */
	AUE_NULL, 			/* 298 = new_system_shared_regions */
	AUE_NULL,			/* 299 */
	AUE_NULL,			/* 300 */
	AUE_NULL,			/* 301 */
	AUE_NULL,			/* 302 */
	AUE_NULL,			/* 303 */
	AUE_NULL,			/* 304 */
	AUE_NULL,			/* 305 */
	AUE_NULL,			/* 306 */
	AUE_NULL,			/* 307 */
	AUE_NULL,			/* 308 */
	AUE_NULL,			/* 309 */
	AUE_NULL,			/* 310 = getsid */
	AUE_NULL,			/* 311 */
	AUE_NULL,			/* 312 */
	AUE_NULL,			/* 313 */
	AUE_NULL,			/* 314 */
	AUE_NULL,			/* 315 */
	AUE_NULL,			/* 316 */
	AUE_NULL,			/* 317 */
	AUE_NULL,			/* 318 */
	AUE_NULL,			/* 319 */
	AUE_NULL,			/* 320 */
	AUE_NULL,			/* 321 */
	AUE_NULL,			/* 322 */
	AUE_NULL,			/* 323 */
	AUE_NULL,			/* 324 = mlockall*/
	AUE_NULL,			/* 325 = munlockall*/
	AUE_NULL,			/* 326 */
	AUE_NULL,			/* 327 = issetugid */
	AUE_NULL,			/* 328 */
	AUE_NULL,			/* 329 */
	AUE_NULL,			/* 330 */
	AUE_NULL,			/* 331 */
	AUE_NULL,			/* 332 */
	AUE_NULL,			/* 333 */
	AUE_NULL,			/* 334 */
	AUE_NULL,			/* 335 = utrace */
	AUE_NULL,			/* 336 */
	AUE_NULL,			/* 337 */
	AUE_NULL,			/* 338 */
	AUE_NULL,			/* 339 */
	AUE_NULL,			/* 340 */
	AUE_NULL,			/* 341 */
	AUE_NULL,			/* 342 */
	AUE_NULL,			/* 343 */
	AUE_NULL,			/* 344 */
	AUE_NULL,			/* 345 */
	AUE_NULL,			/* 346 */
	AUE_NULL,			/* 347 */
	AUE_NULL,			/* 348 */
	AUE_NULL,			/* 349 */
	AUE_AUDIT,			/* 350 */
	AUE_NULL,			/* 351 */
	AUE_NULL,			/* 352 */
	AUE_GETAUID,			/* 353 */
	AUE_SETAUID,			/* 354 */
	AUE_NULL,			/* 355 */
	AUE_NULL,			/* 356 */
	AUE_NULL,			/* 357 */
	AUE_NULL,			/* 358 */
	AUE_NULL,			/* 359 */
	AUE_NULL,			/* 360 */
	AUE_NULL,			/* 361 */
	AUE_NULL,			/* 362 = kqueue */
	AUE_NULL,			/* 363 = kevent */
	AUE_NULL,			/* 364 */
	AUE_NULL,			/* 365 */
	AUE_NULL,			/* 366 */
	AUE_NULL,			/* 367 */
	AUE_NULL,			/* 368 */
	AUE_NULL			/* 369 */
};
int	nsys_au_event = sizeof(sys_au_event) / sizeof(sys_au_event[0]);

/*
 * Check whether an event is aditable by comparing the mask of classes this
 * event is part of against the kernel's preselection mask the given mask
 * which will be the process event mask.
 *
 * XXX This needs to eventually implement the selection based on the 
 *     event->class mapping that is controlled by a configuration file.
 */
int au_preselect(au_event_t event, au_mask_t *mask_p, int sorf)
{
	au_class_t ae_class;
	au_class_t effmask = 0;

	if(mask_p == NULL)
		return (-1);

	/*
	 * XXX Set the event class using a big ugly switch statement. This	
	 * will change to use the mapping defined by a configuration file.
	 */
	switch (event) {
	case AUE_MMAP:
	case AUE_PIPE:
		/* mmap() and pipe() are AU_NULL in some systems; we'll
		 * place them in AU_IPC for now.
		 */
		ae_class = AU_IPC; break;
	case AUE_READLINK:
	case AUE_GETDIRENTRIES:
		ae_class = AU_FREAD; break;
	case AUE_ACCESS:
	case AUE_FSTAT:
	case AUE_FSTATFS:
	case AUE_GETFH:
	case AUE_LSTAT:
	case AUE_FPATHCONF:
	case AUE_PATHCONF:
	case AUE_STAT:
	case AUE_STATFS:
	case AUE_GETATTRLIST:
	case AUE_GETFSSTAT:
	case AUE_GETDIRENTRIESATTR:
	case AUE_SEARCHFS:
		ae_class = AU_FACCESS; break;
	case AUE_CHMOD:
	case AUE_CHOWN:
	case AUE_FCHMOD:
	case AUE_FCHOWN:
	case AUE_FCNTL:
	case AUE_FLOCK:
	case AUE_UTIMES:
	case AUE_CHFLAGS:
	case AUE_FCHFLAGS:
	case AUE_FUTIMES:
	case AUE_SETATTRLIST:
	case AUE_TRUNCATE:
	case AUE_FTRUNCATE:
	case AUE_UNDELETE:
	case AUE_EXCHANGEDATA:
		ae_class = AU_FMODIFY; break;
	case AUE_LINK:
	case AUE_MKDIR:
	case AUE_MKNOD:
	case AUE_SYMLINK:
	case AUE_MKFIFO:
		ae_class = AU_FCREATE; break;
	case AUE_RMDIR:
	case AUE_UNLINK:
		ae_class = AU_FDELETE; break;
	case AUE_CLOSE:
	case AUE_MUNMAP:
	case AUE_REVOKE:
		ae_class = AU_CLOSE; break;
	case AUE_CHDIR:
	case AUE_CHROOT:
	case AUE_EXIT:
	case AUE_FCHDIR:
	case AUE_FORK:
	case AUE_KILL:
	case AUE_SETEGID:
	case AUE_SETEUID:
	case AUE_SETGID:
	case AUE_SETGROUPS:
	case AUE_SETPGRP:
	case AUE_SETUID:
	case AUE_VFORK:
	case AUE_UMASK:
		ae_class = AU_PROCESS; break;
	case AUE_ACCEPT:
	case AUE_BIND:
	case AUE_CONNECT:
	case AUE_RECVFROM:
	case AUE_RECVMSG:
	case AUE_SENDMSG:
	case AUE_SENDTO:
	case AUE_SETSOCKOPT:
	case AUE_SHUTDOWN:
	case AUE_SOCKET:
	case AUE_SOCKETPAIR:
		ae_class = AU_NET; break;
	case AUE_MSGCTL:
	case AUE_MSGGET:
	case AUE_MSGRCV:
	case AUE_MSGSND:
	case AUE_SEMCTL:
	case AUE_SEMGET:
	case AUE_SEMOP:
	case AUE_SHMAT:
	case AUE_SHMCTL:
	case AUE_SHMDT:
	case AUE_SHMGET:
		ae_class = AU_IPC; break;
	case AUE_ACCT:
	case AUE_ADJTIME:
	case AUE_GETAUID:
	case AUE_MOUNT:
	case AUE_SETAUID:
	case AUE_SETRLIMIT:
	case AUE_UMOUNT:
		ae_class = AU_ADMIN; break;
	case AUE_IOCTL:
		ae_class = AU_IOCTL; break;
	case AUE_EXECVE:
		ae_class = AU_PROCESS|AU_EXEC; break;
	case AUE_OPEN_R:
		ae_class = AU_FREAD; break;
        case AUE_OPEN_RC:
		ae_class = AU_FREAD|AU_FCREATE; break;
        case AUE_OPEN_RTC:
		ae_class = AU_FREAD|AU_FCREATE|AU_FDELETE; break;
        case AUE_OPEN_RT:
		ae_class = AU_FREAD|AU_FDELETE; break;
        case AUE_OPEN_RW:
		ae_class = AU_FREAD|AU_FWRITE; break;
        case AUE_OPEN_RWC:
		ae_class = AU_FREAD|AU_FWRITE|AU_FCREATE; break;
        case AUE_OPEN_RWTC:
		ae_class = AU_FREAD|AU_FWRITE|AU_FCREATE|AU_FDELETE; break;
        case AUE_OPEN_RWT:
		ae_class = AU_FREAD|AU_FWRITE|AU_FDELETE; break;
        case AUE_OPEN_W:
		ae_class = AU_FWRITE; break;
        case AUE_OPEN_WC:
		ae_class = AU_FWRITE|AU_FCREATE; break;
        case AUE_OPEN_WTC:
		ae_class = AU_FWRITE|AU_FCREATE|AU_FDELETE; break;
        case AUE_OPEN_WT:
		ae_class = AU_FWRITE|AU_FDELETE; break;
	case AUE_RENAME:
		ae_class = AU_FCREATE|AU_FDELETE; break;
	default:	/* Assign the event to all classes */
		ae_class = AU_ALL; break;
	}

	/* 
	 * Perform the actual check of the masks against the event.
	 */
	/*
	 * XXX Need to compare against the kernel mask??? Or do we not do
	 * that by default and let the client code just call this function
	 * with the kernel preselection mask as the mask parameter?
	 */
	if(sorf & AU_PRS_SUCCESS) {
		effmask |= (mask_p->am_success & ae_class);
	}
                        
	if(sorf & AU_PRS_FAILURE) {
		effmask |= (mask_p->am_failure & ae_class);
	}
        
	if(effmask)
		return (1);
	else 
		return (0);
}

/*
 * Convert an open flags specifier into a specific type of open event for 
 * auditing purposes.
 */
au_event_t flags_to_openevent(int oflags) {

	/* Need to check only those flags we care about. */
	oflags = oflags & (O_RDONLY | O_CREAT | O_TRUNC | O_RDWR | O_WRONLY);

	/* These checks determine what flags are on with the condition
	 * that ONLY that combination is on, and no other flags are on.
	 */
	if (!(oflags ^ O_RDONLY))
		return AUE_OPEN_R;
	if (!(oflags ^ (O_RDONLY | O_CREAT)))
		return AUE_OPEN_RC;
	if (!(oflags ^ (O_RDONLY | O_CREAT | O_TRUNC)))
		return AUE_OPEN_RTC;
	if (!(oflags ^ (O_RDONLY | O_TRUNC)))
		return AUE_OPEN_RT;
	if (!(oflags ^ O_RDWR))
		return AUE_OPEN_RW;
	if (!(oflags ^ (O_RDWR | O_CREAT)))
		return AUE_OPEN_RWC;
	if (!(oflags ^ (O_RDWR | O_CREAT | O_TRUNC)))
		return AUE_OPEN_RWTC;
	if (!(oflags ^ (O_RDWR | O_TRUNC)))
		return AUE_OPEN_RWT;
	if (!(oflags ^ O_WRONLY))
		return AUE_OPEN_W;
	if (!(oflags ^ (O_WRONLY | O_CREAT)))
		return AUE_OPEN_WC;
	if (!(oflags ^ (O_WRONLY | O_CREAT | O_TRUNC)))
		return AUE_OPEN_WTC;
	if (!(oflags ^ (O_WRONLY | O_TRUNC)))
		return AUE_OPEN_WT;

	return AUE_OPEN_R;
}

/*
 * Fill in a vattr struct from kernel audit record fields. This function
 * would be unecessary if we store a vattr in the kernel audit record
 * directly.
*/
void fill_vattr(struct vattr *v, struct vnode_au_info *vn_info)
{
	v->va_mode = vn_info->vn_mode;
	v->va_uid = vn_info->vn_uid;
	v->va_gid = vn_info->vn_gid;
	v->va_fsid = vn_info->vn_fsid;
	v->va_fileid = vn_info->vn_fileid;
	v->va_rdev = vn_info->vn_dev;
}

/* Convert a MSGCTL command to a specific event. */
int msgctl_to_event(int cmd)
{
	switch (cmd) {
	case IPC_RMID:
		return AUE_MSGCTL_RMID;
	case IPC_SET:
		return AUE_MSGCTL_SET;
	case IPC_STAT:
		return AUE_MSGCTL_STAT;
	default:
		return AUE_MSGCTL;
			/* We will audit a bad command */
	}
}

/* Convert a SEMCTL command to a specific event. */
int semctl_to_event(int cmd)
{
	switch (cmd) {
	case GETALL:
		return AUE_SEMCTL_GETALL;
	case GETNCNT:
		return AUE_SEMCTL_GETNCNT;
	case GETPID:
		return AUE_SEMCTL_GETPID;
	case GETVAL:
		return AUE_SEMCTL_GETVAL;
	case GETZCNT:
		return AUE_SEMCTL_GETZCNT;
	case IPC_RMID:
		return AUE_SEMCTL_RMID;
	case IPC_SET:
		return AUE_SEMCTL_SET;
	case SETALL:
		return AUE_SEMCTL_SETALL;
	case SETVAL:
		return AUE_SEMCTL_SETVAL;
	case IPC_STAT:
		return AUE_SEMCTL_STAT;
	default:
		return AUE_SEMCTL;
				/* We will audit a bad command */
	}
}

/* 
 * Create a canonical path from given path by prefixing either the
 * root directory, or the current working directory.
 * If the process working directory is NULL, we could use 'rootvnode'
 * to obtain the root directoty, but this results in a volfs name
 * written to the audit log. So we will leave the filename starting
 * with '/' in the audit log in this case.
 */
void canon_path(struct proc *p, char *path, char *cpath)
{
	char *bufp;
	int len;
	struct vnode *vnp;
	struct filedesc *fdp;

	fdp = p->p_fd;
	bufp = path;
	if (*(path) == '/') {
		while (*(bufp) == '/') 
			bufp++;			/* skip leading '/'s	     */
		/* If no process root, or it is the same as the system root,
		 * audit the path as passed in with a single '/'.
		 */
		if ((fdp->fd_rdir == NULL) ||
		    (fdp->fd_rdir == rootvnode)) {	
			vnp = NULL;
			bufp--;			/* restore one '/'	     */
		} else {
			vnp = fdp->fd_rdir;	/* use process root	     */
		}
	} else {
		vnp = fdp->fd_cdir;	/* prepend the current dir  */
		bufp = path;
	}
	if (vnp != NULL) {
		len = MAXPATHLEN;
		vn_getpath(vnp, cpath, &len);
		/* The length returned by vn_getpath() is two greater than the 
		 * number of characters in the string.
		 */
		if (len < MAXPATHLEN)
			cpath[len-2] = '/';	
		strncpy(cpath + len-1, bufp, MAXPATHLEN - len);
	} else {
		strncpy(cpath, bufp, MAXPATHLEN);
	}
}
