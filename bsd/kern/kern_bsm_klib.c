/*
 * Copyright (c) 2006 Apple Computer, Inc. All Rights Reserved.
 * 
 * @APPLE_LICENSE_OSREFERENCE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code 
 * as defined in and that are subject to the Apple Public Source License 
 * Version 2.0 (the 'License'). You may not use this file except in 
 * compliance with the License.  The rights granted to you under the 
 * License may not be used to create, or enable the creation or 
 * redistribution of, unlawful or unlicensed copies of an Apple operating 
 * system, or to circumvent, violate, or enable the circumvention or 
 * violation of, any terms of an Apple operating system software license 
 * agreement.
 *
 * Please obtain a copy of the License at 
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
 * @APPLE_LICENSE_OSREFERENCE_HEADER_END@
 */

#include <sys/systm.h>
#include <sys/types.h>
#include <sys/proc_internal.h>
#include <sys/vnode_internal.h>
#include <sys/fcntl.h>
#include <sys/filedesc.h>
#include <sys/sem.h>

#include <bsm/audit.h>
#include <bsm/audit_kernel.h>
#include <bsm/audit_kevents.h>
#include <bsm/audit_klib.h>

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
	AUE_FORK,			/*   2 = fork */
	AUE_NULL,			/*   3 = read */
	AUE_NULL,			/*   4 = write */
	AUE_OPEN_RWTC,			/*   5 = open */
	AUE_CLOSE,			/*   6 = close */
	AUE_NULL,			/*   7 = wait4 */
	AUE_O_CREAT,			/*   8 = old creat */
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
	AUE_GETFSSTAT,			/*  18 = getfsstat */
#else
	AUE_NULL,			/*  18 = ogetfsstat */
#endif
	AUE_NULL,			/*  19 = old lseek */
	AUE_NULL,			/*  20 = getpid */
	AUE_NULL,			/*  21 was obsolete mount */
	AUE_NULL,			/*  22 was obsolete umount */
	AUE_SETUID,			/*  23 = setuid */
	AUE_NULL,			/*  24 = getuid */
	AUE_NULL,			/*  25 = geteuid */
	AUE_PTRACE,			/*  26 = ptrace */
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
	AUE_KILL,			/*  37 = kill */
	AUE_O_STAT,			/*  38 = old stat */
	AUE_NULL,			/*  39 = getppid */
	AUE_O_LSTAT,			/*  40 = old lstat */
	AUE_NULL,			/*  41 = dup */
	AUE_PIPE,			/*  42 = pipe */
	AUE_NULL,			/*  43 = getegid */
	AUE_NULL,			/*  44 = profil */
	AUE_KTRACE,			/*  45 = ktrace */
	AUE_NULL,			/*  46 = sigaction */
	AUE_NULL,			/*  47 = getgid */
	AUE_NULL,			/*  48 = sigprocmask */
	AUE_NULL,			/*  49 = getlogin */
	AUE_SETLOGIN,			/*  50 = setlogin */
	AUE_ACCT,			/*  51 = turn acct off/on */
	AUE_NULL,			/*  52 = sigpending */
	AUE_NULL,			/*  53 = sigaltstack */
	AUE_IOCTL,			/*  54 = ioctl */
	AUE_REBOOT,			/*  55 = reboot */
	AUE_REVOKE,			/*  56 = revoke */
	AUE_SYMLINK,			/*  57 = symlink */
	AUE_READLINK,			/*  58 = readlink */
	AUE_EXECVE,			/*  59 = execve */
	AUE_UMASK,			/*  60 = umask */
	AUE_CHROOT,			/*  61 = chroot */
	AUE_O_FSTAT,			/*  62 = old fstat */
	AUE_NULL,			/*  63 = used internally, reserved */
	AUE_NULL,			/*  64 = old getpagesize */
	AUE_NULL,			/*  65 = msync */
	AUE_VFORK,			/*  66 = vfork */
	AUE_NULL,			/*  67 was obsolete vread */
	AUE_NULL,			/*  68 was obsolete vwrite */
	AUE_NULL,			/*  69 = sbrk */
	AUE_NULL,			/*  70 = sstk */
	AUE_O_MMAP,			/*  71 = old mmap */
	AUE_NULL,			/*  72 = old vadvise */
	AUE_MUNMAP,			/*  73 = munmap */
	AUE_MPROTECT,			/*  74 = mprotect */
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
	AUE_O_SETHOSTNAME,		/*  88 = old sethostname */
	AUE_NULL,			/* 89 getdtablesize */
	AUE_NULL,			/*  90 = dup2 */
	AUE_NULL,			/*  91 was obsolete getdopt */
	AUE_FCNTL,			/*  92 = fcntl */
	AUE_NULL,			/*  93 = select */
	AUE_NULL,			/*  94 was obsolete setdopt */
	AUE_NULL,			/*  95 = fsync */
	AUE_SETPRIORITY,		/*  96 = setpriority */
	AUE_SOCKET,			/*  97 = socket */
	AUE_CONNECT,			/*  98 = connect */
	AUE_NULL,			/*  99 = accept */
	AUE_NULL,			/* 100 = getpriority */
	AUE_O_SEND,			/* 101 = old send */
	AUE_O_RECV,			/* 102 = old recv */
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
	AUE_O_RECVMSG,			/* 113 = recvmsg */
	AUE_O_SENDMSG,			/* 114 = sendmsg */
	AUE_NULL,			/* 115 = old vtrace */
	AUE_NULL,			/* 116 = gettimeofday */
	AUE_NULL,			/* 117 = getrusage */
	AUE_NULL,			/* 118 = getsockopt */
	AUE_NULL,			/* 119 = old resuba */
	AUE_NULL,			/* 120 = readv */
	AUE_NULL,			/* 121 = writev */
	AUE_SETTIMEOFDAY,		/* 122 = settimeofday */
	AUE_FCHOWN,			/* 123 = fchown */
	AUE_FCHMOD,			/* 124 = fchmod */
	AUE_O_RECVFROM,			/* 125 = recvfrom */
	AUE_NULL,			/* 126 = setreuid */
	AUE_NULL,			/* 127 = setregid */
	AUE_RENAME,			/* 128 = rename */
	AUE_O_TRUNCATE,			/* 129 = old truncate */
	AUE_O_FTRUNCATE,		/* 130 = old ftruncate */
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
	AUE_O_SETRLIMIT,		/* 145 = old setrlimit */
	AUE_O_KILLPG,			/* 146 = old killpg */
	AUE_SETSID,			/* 147 = setsid */
	AUE_NULL,			/* 148 was setquota */
	AUE_NULL,			/* 149 was qquota */
	AUE_NULL,			/* 150 = getsockname */
	AUE_NULL,			/* 151 = getpgid */
	AUE_SETPRIVEXEC,		/* 152 = setprivexec */
	AUE_NULL,			/* 153 = pread */
	AUE_NULL,			/* 154 = pwrite */
	AUE_NFSSVC,			/* 155 = nfs_svc */
	AUE_O_GETDIRENTRIES,		/* 156 = old getdirentries */
	AUE_STATFS,			/* 157 = statfs */
	AUE_FSTATFS,			/* 158 = fstatfs */
	AUE_UNMOUNT,			/* 159 = unmount */
	AUE_NULL,			/* 160 was async_daemon */
	AUE_GETFH,			/* 161 = get file handle */
	AUE_NULL,			/* 162 = getdomainname */
	AUE_O_SETDOMAINNAME,		/* 163 = setdomainname */
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
	AUE_MMAP,			/* 197 = mmap */
	AUE_NULL,			/* 198 = __syscall */
	AUE_NULL,			/* 199 = lseek */
	AUE_TRUNCATE,			/* 200 = truncate */
	AUE_FTRUNCATE,			/* 201 = ftruncate */
	AUE_SYSCTL,			/* 202 = __sysctl */
	AUE_MLOCK,			/* 203 = mlock */
	AUE_MUNLOCK,			/* 204 = munlock */
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
	AUE_CHECKUSERACCESS,/* 224 = HFS checkuseraccess check access to file */
	AUE_SEARCHFS,	/* 225 = HFS searchfs to implement catalog searching */
	AUE_DELETE,	/* 226 = private delete (Carbon semantics) */
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
	AUE_MINHERIT,			/* 250 = minherit */
	AUE_NULL,			/* 251 = semsys */
	AUE_NULL,			/* 252 = msgsys */
	AUE_NULL,			/* 253 = shmsys */
	AUE_SEMCTL,			/* 254 = semctl */
	AUE_SEMGET,			/* 255 = semget */
	AUE_SEMOP,			/* 256 = semop */
	AUE_NULL,			/* 257 = */
	AUE_MSGCTL,			/* 258 = msgctl */
	AUE_MSGGET,			/* 259 = msgget */
	AUE_MSGSND,			/* 260 = msgsnd */
	AUE_MSGRCV,			/* 261 = msgrcv */
	AUE_SHMAT,			/* 262 = shmat */
	AUE_SHMCTL,			/* 263 = shmctl */
	AUE_SHMDT,			/* 264 = shmdt */
	AUE_SHMGET,			/* 265 = shmget */
	AUE_SHMOPEN,			/* 266 = shm_open */
	AUE_SHMUNLINK,			/* 267 = shm_unlink */
	AUE_SEMOPEN,			/* 268 = sem_open */
	AUE_SEMCLOSE,			/* 269 = sem_close */
	AUE_SEMUNLINK,			/* 270 = sem_unlink */
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
	AUE_LOADSHFILE,			/* 296 = load_shared_file */
	AUE_RESETSHFILE,		/* 297 = reset_shared_file */
	AUE_NEWSYSTEMSHREG,		/* 298 = new_system_shared_regions */
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
	AUE_AUDITON,			/* 351 */
	AUE_NULL,			/* 352 */
	AUE_GETAUID,			/* 353 */
	AUE_SETAUID,			/* 354 */
	AUE_GETAUDIT,			/* 355 */
	AUE_SETAUDIT,			/* 356 */
	AUE_GETAUDIT_ADDR,		/* 357 */
	AUE_SETAUDIT_ADDR,		/* 358 */
	AUE_AUDITCTL,			/* 359 */
	AUE_NULL,			/* 360 */
	AUE_NULL,			/* 361 */
	AUE_NULL,			/* 362 = kqueue */
	AUE_NULL,			/* 363 = kevent */
	AUE_LCHOWN,			/* 364 = lchown */
	AUE_NULL,			/* 365 */
	AUE_NULL,			/* 366 */
	AUE_NULL,			/* 367 */
	AUE_NULL,			/* 368 */
	AUE_NULL			/* 369 */
};
int	nsys_au_event = sizeof(sys_au_event) / sizeof(sys_au_event[0]);

/*
 * Hash table functions for the audit event number to event class mask mapping.
 */

#define EVCLASSMAP_HASH_TABLE_SIZE 251
struct evclass_elem {
	au_event_t event;
	au_class_t class;
	LIST_ENTRY(evclass_elem) entry;
};
struct evclass_list {
	LIST_HEAD(, evclass_elem) head;
};

struct evclass_list evclass_hash[EVCLASSMAP_HASH_TABLE_SIZE];

au_class_t au_event_class(au_event_t event)
{

	struct evclass_list *evcl;
	struct evclass_elem *evc;

	evcl = &evclass_hash[event % EVCLASSMAP_HASH_TABLE_SIZE];

	/* If an entry at our hash location matches the event, just return */
	LIST_FOREACH(evc, &evcl->head, entry) {
		if (evc->event == event)
			return (evc->class);
	}
	return (AU_NULL);
}

	/*
 * Insert a event to class mapping. If the event already exists in the
 * mapping, then replace the mapping with the new one.
 * XXX There is currently no constraints placed on the number of mappings.
 *     May want to either limit to a number, or in terms of memory usage.
		 */
void au_evclassmap_insert(au_event_t event, au_class_t class) 
{
	struct evclass_list *evcl;
	struct evclass_elem *evc;

	evcl = &evclass_hash[event % EVCLASSMAP_HASH_TABLE_SIZE];

	LIST_FOREACH(evc, &evcl->head, entry) {
		if (evc->event == event) {
			evc->class = class;
			return;
		}
	}
	kmem_alloc(kernel_map, (vm_offset_t *)&evc, sizeof(*evc));
	if (evc == NULL) {
		return;
	}
	evc->event = event;
	evc->class = class;
	LIST_INSERT_HEAD(&evcl->head, evc, entry);
}

void au_evclassmap_init() 
{
	int i;
	for (i = 0; i < EVCLASSMAP_HASH_TABLE_SIZE; i++) {
		LIST_INIT(&evclass_hash[i].head);
	}

	/* Set up the initial event to class mapping for system calls.  */ 
	for (i = 0; i < nsys_au_event; i++) {
		if (sys_au_event[i] != AUE_NULL) {
			au_evclassmap_insert(sys_au_event[i], AU_NULL);
	}
	}
	/* Add the Mach system call events */
	au_evclassmap_insert(AUE_TASKFORPID, AU_NULL);
	au_evclassmap_insert(AUE_PIDFORTASK, AU_NULL);
	au_evclassmap_insert(AUE_SWAPON, AU_NULL);
	au_evclassmap_insert(AUE_SWAPOFF, AU_NULL);
	au_evclassmap_insert(AUE_MAPFD, AU_NULL);
	au_evclassmap_insert(AUE_INITPROCESS, AU_NULL);

	/* Add the specific open events to the mapping. */
	au_evclassmap_insert(AUE_OPEN_R, AU_FREAD);
	au_evclassmap_insert(AUE_OPEN_RC, AU_FREAD|AU_FCREATE);
	au_evclassmap_insert(AUE_OPEN_RTC, AU_FREAD|AU_FCREATE|AU_FDELETE);
	au_evclassmap_insert(AUE_OPEN_RT, AU_FREAD|AU_FDELETE);
	au_evclassmap_insert(AUE_OPEN_RW, AU_FREAD|AU_FWRITE);
	au_evclassmap_insert(AUE_OPEN_RWC, AU_FREAD|AU_FWRITE|AU_FCREATE);
	au_evclassmap_insert(AUE_OPEN_RWTC, AU_FREAD|AU_FWRITE|AU_FCREATE|AU_FDELETE);
	au_evclassmap_insert(AUE_OPEN_RWT, AU_FREAD|AU_FWRITE|AU_FDELETE);
	au_evclassmap_insert(AUE_OPEN_W, AU_FWRITE);
	au_evclassmap_insert(AUE_OPEN_WC, AU_FWRITE|AU_FCREATE);
	au_evclassmap_insert(AUE_OPEN_WTC, AU_FWRITE|AU_FCREATE|AU_FDELETE);
	au_evclassmap_insert(AUE_OPEN_WT, AU_FWRITE|AU_FDELETE);
}

	/* 
 * Check whether an event is aditable by comparing the mask of classes this
 * event is part of against the given mask.
	 */
int au_preselect(au_event_t event, au_mask_t *mask_p, int sorf)
{
	au_class_t effmask = 0;
	au_class_t ae_class;

	if(mask_p == NULL)
		return (-1);

	ae_class = au_event_class(event);
	/*
	 * Perform the actual check of the masks against the event.
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
 * Convert sysctl names and present arguments to events
 */
au_event_t ctlname_to_sysctlevent(int name[], uint64_t valid_arg) {

	/* can't parse it - so return the worst case */
	if ((valid_arg & (ARG_CTLNAME | ARG_LEN)) != 
	                 (ARG_CTLNAME | ARG_LEN))
		return AUE_SYSCTL;

	switch (name[0]) {
	/* non-admin "lookups" treat them special */
	case KERN_OSTYPE:
	case KERN_OSRELEASE:
	case KERN_OSREV:
	case KERN_VERSION:
	case KERN_ARGMAX:
	case KERN_CLOCKRATE:
	case KERN_BOOTTIME:
	case KERN_POSIX1:
	case KERN_NGROUPS:
	case KERN_JOB_CONTROL:
	case KERN_SAVED_IDS:
	case KERN_NETBOOT:
	case KERN_SYMFILE:
	case KERN_SHREG_PRIVATIZABLE:
		return AUE_SYSCTL_NONADMIN;

	/* only treat the sets as admin */
	case KERN_MAXVNODES:
	case KERN_MAXPROC:
	case KERN_MAXFILES:
	case KERN_MAXPROCPERUID:
	case KERN_MAXFILESPERPROC:
	case KERN_HOSTID:
	case KERN_AIOMAX:
	case KERN_AIOPROCMAX:
	case KERN_AIOTHREADS:
	case KERN_COREDUMP:
	case KERN_SUGID_COREDUMP:
		return (valid_arg & ARG_VALUE) ?
			AUE_SYSCTL : AUE_SYSCTL_NONADMIN;

	default:
		return AUE_SYSCTL;
	}
	/* NOTREACHED */
}

/*
 * Convert an open flags specifier into a specific type of open event for 
 * auditing purposes.
 */
au_event_t flags_and_error_to_openevent(int oflags, int error) {
	au_event_t aevent;

	/* Need to check only those flags we care about. */
	oflags = oflags & (O_RDONLY | O_CREAT | O_TRUNC | O_RDWR | O_WRONLY);

	/* These checks determine what flags are on with the condition
	 * that ONLY that combination is on, and no other flags are on.
	 */
	switch (oflags) {
	case O_RDONLY:
		aevent = AUE_OPEN_R;
		break;
	case (O_RDONLY | O_CREAT):
		aevent = AUE_OPEN_RC;
		break;
	case (O_RDONLY | O_CREAT | O_TRUNC):
		aevent = AUE_OPEN_RTC;
		break;
	case (O_RDONLY | O_TRUNC):
		aevent = AUE_OPEN_RT;
		break;
	case O_RDWR:
		aevent = AUE_OPEN_RW;
		break;
	case (O_RDWR | O_CREAT):
		aevent = AUE_OPEN_RWC;
		break;
	case (O_RDWR | O_CREAT | O_TRUNC):
		aevent = AUE_OPEN_RWTC;
		break;
	case (O_RDWR | O_TRUNC):
		aevent = AUE_OPEN_RWT;
		break;
	case O_WRONLY:
		aevent = AUE_OPEN_W;
		break;
	case (O_WRONLY | O_CREAT):
		aevent = AUE_OPEN_WC;
		break;
	case (O_WRONLY | O_CREAT | O_TRUNC):
		aevent = AUE_OPEN_WTC;
		break;
	case (O_WRONLY | O_TRUNC):
		aevent = AUE_OPEN_WT;
		break;
	default:
		aevent = AUE_OPEN;
		break;
}

/*
	 * Convert chatty errors to better matching events.
	 * Failures to find a file are really just attribute
	 * events - so recast them as such.
*/
	switch (aevent) {
	case AUE_OPEN_R:
	case AUE_OPEN_RT:
	case AUE_OPEN_RW:
	case AUE_OPEN_RWT:
	case AUE_OPEN_W:
	case AUE_OPEN_WT:
		if (error == ENOENT)
			aevent = AUE_OPEN;
}
	return aevent;
}

/* Convert a MSGCTL command to a specific event. */
au_event_t msgctl_to_event(int cmd)
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
au_event_t semctl_to_event(int cmd)
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

/* Convert a command for the auditon() system call to a audit event. */
int auditon_command_event(int cmd)
{
	switch(cmd) {
	case A_GETPOLICY:
		return AUE_AUDITON_GPOLICY;
		break;
	case A_SETPOLICY:
		return AUE_AUDITON_SPOLICY;
		break;
	case A_GETKMASK:
		return AUE_AUDITON_GETKMASK;
		break;
	case A_SETKMASK:
		return AUE_AUDITON_SETKMASK;
		break;
	case A_GETQCTRL:
		return AUE_AUDITON_GQCTRL;
		break;
	case A_SETQCTRL:
		return AUE_AUDITON_SQCTRL;
		break;
	case A_GETCWD:
		return AUE_AUDITON_GETCWD;
		break;
	case A_GETCAR:
		return AUE_AUDITON_GETCAR;
		break;
	case A_GETSTAT:
		return AUE_AUDITON_GETSTAT;
		break;
	case A_SETSTAT:
		return AUE_AUDITON_SETSTAT;
		break;
	case A_SETUMASK:
		return AUE_AUDITON_SETUMASK;
		break;
	case A_SETSMASK:
		return AUE_AUDITON_SETSMASK;
		break;
	case A_GETCOND:
		return AUE_AUDITON_GETCOND;
		break;
	case A_SETCOND:
		return AUE_AUDITON_SETCOND;
		break;
	case A_GETCLASS:
		return AUE_AUDITON_GETCLASS;
		break;
	case A_SETCLASS:
		return AUE_AUDITON_SETCLASS;
		break;
	case A_GETPINFO:
	case A_SETPMASK:
	case A_SETFSIZE:
	case A_GETFSIZE:
	case A_GETPINFO_ADDR:
	case A_GETKAUDIT:
	case A_SETKAUDIT:
	default:
		return AUE_AUDITON;	/* No special record */
		break;
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
int canon_path(struct proc *p, char *path, char *cpath)
{
	char *bufp;
	int len;
	struct vnode *vnp;
	struct filedesc *fdp;
	int ret;

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
		ret = vn_getpath(vnp, cpath, &len);
		if (ret != 0) {
			cpath[0] = '\0';
			return (ret);
		}
		if (len < MAXPATHLEN)
			cpath[len-1] = '/';	
		strncpy(cpath + len, bufp, MAXPATHLEN - len);
	} else {
		strncpy(cpath, bufp, MAXPATHLEN);
	}
	return (0);
}
