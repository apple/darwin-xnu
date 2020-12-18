/*
 * Copyright (c) 2005-2020 Apple Inc. All rights reserved.
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
 * sysctl system call.
 */

#include <sys/param.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/malloc.h>
#include <sys/proc_internal.h>
#include <sys/kauth.h>
#include <sys/file_internal.h>
#include <sys/vnode_internal.h>
#include <sys/unistd.h>
#include <sys/buf.h>
#include <sys/ioctl.h>
#include <sys/namei.h>
#include <sys/tty.h>
#include <sys/disklabel.h>
#include <sys/vm.h>
#include <sys/reason.h>
#include <sys/sysctl.h>
#include <sys/user.h>
#include <sys/aio_kern.h>
#include <sys/kern_memorystatus.h>

#include <security/audit/audit.h>

#include <mach/machine.h>
#include <mach/mach_types.h>
#include <mach/vm_param.h>
#include <kern/task.h>
#include <kern/kalloc.h>
#include <kern/assert.h>
#include <kern/policy_internal.h>

#include <vm/vm_kern.h>
#include <vm/vm_map.h>
#include <mach/host_info.h>
#include <mach/task_info.h>
#include <mach/thread_info.h>
#include <mach/vm_region.h>
#include <mach/vm_types.h>

#include <sys/mount_internal.h>
#include <sys/proc_info.h>
#include <sys/bsdtask_info.h>
#include <sys/kdebug.h>
#include <sys/sysproto.h>
#include <sys/msgbuf.h>
#include <sys/priv.h>

#include <sys/guarded.h>

#include <machine/machine_routines.h>

#include <kern/ipc_misc.h>

#include <vm/vm_protos.h>

/* Needed by proc_pidnoteexit(), proc_pidlistuptrs() */
#include <sys/event.h>
#include <sys/codesign.h>

/* Needed by proc_listcoalitions() */
#ifdef CONFIG_COALITIONS
#include <sys/coalition.h>
#endif

#if CONFIG_MACF
#include <security/mac_framework.h>
#endif

struct pshmnode;
struct psemnode;
struct pipe;
struct kqueue;
struct atalk;

uint64_t get_dispatchqueue_offset_from_proc(void *);
uint64_t get_dispatchqueue_serialno_offset_from_proc(void *);
uint64_t get_dispatchqueue_label_offset_from_proc(void *p);
uint64_t get_return_to_kernel_offset_from_proc(void *p);
int proc_info_internal(int callnum, int pid, uint32_t flags, uint64_t ext_id, int flavor, uint64_t arg, user_addr_t buffer, uint32_t buffersize, int32_t * retval);

/*
 * TODO: Replace the noinline attribute below.  Currently, it serves
 * to avoid stack bloat caused by inlining multiple functions that
 * have large stack footprints; when the functions are independent
 * of each other (will not both be called in any given call to the
 * caller), this only serves to bloat the stack, as we allocate
 * space for both functions, despite the fact that we only need a
 * fraction of that space.
 *
 * Long term, these functions should not be allocating everything on
 * the stack, and should move large allocations (the huge structs
 * that proc info deals in) to the heap, or eliminate them if
 * possible.
 *
 * The functions that most desperately need to improve stack usage
 * (starting with the worst offenders):
 *   proc_pidvnodepathinfo
 *   proc_pidinfo
 *   proc_pidregionpathinfo
 *   pid_vnodeinfopath
 *   pid_pshminfo
 *   pid_pseminfo
 *   pid_socketinfo
 *   proc_pid_rusage
 *   proc_pidoriginatorinfo
 */

/* protos for proc_info calls */
static int __attribute__ ((noinline)) proc_listpids(uint32_t type, uint32_t tyoneinfo, user_addr_t buffer, uint32_t buffersize, int32_t * retval);
static int __attribute__ ((noinline)) proc_pidinfo(int pid, uint32_t flags, uint64_t ext_id, int flavor, uint64_t arg, user_addr_t buffer, uint32_t buffersize, int32_t * retval);
static int __attribute__ ((noinline)) proc_pidfdinfo(int pid, int flavor, int fd, user_addr_t buffer, uint32_t buffersize, int32_t * retval);
static int __attribute__ ((noinline)) proc_kernmsgbuf(user_addr_t buffer, uint32_t buffersize, int32_t * retval);
static int __attribute__ ((noinline)) proc_setcontrol(int pid, int flavor, uint64_t arg, user_addr_t buffer, uint32_t buffersize, int32_t * retval);
static int __attribute__ ((noinline)) proc_pidfileportinfo(int pid, int flavor, mach_port_name_t name, user_addr_t buffer, uint32_t buffersize, int32_t *retval);
static int __attribute__ ((noinline)) proc_dirtycontrol(int pid, int flavor, uint64_t arg, int32_t * retval);
static int __attribute__ ((noinline)) proc_terminate(int pid, int32_t * retval);
static int __attribute__ ((noinline)) proc_pid_rusage(int pid, int flavor, user_addr_t buffer, int32_t * retval);
static int __attribute__ ((noinline)) proc_pidoriginatorinfo(int pid, int flavor, user_addr_t buffer, uint32_t buffersize, int32_t * retval);
static int __attribute__ ((noinline)) proc_listcoalitions(int flavor, int coaltype, user_addr_t buffer, uint32_t buffersize, int32_t *retval);
static int __attribute__ ((noinline)) proc_can_use_foreground_hw(int pid, user_addr_t reason, uint32_t resonsize, int32_t *retval);

/* protos for procpidinfo calls */
static int __attribute__ ((noinline)) proc_pidfdlist(proc_t p, user_addr_t buffer, uint32_t buffersize, int32_t *retval);
static int __attribute__ ((noinline)) proc_pidbsdinfo(proc_t p, struct proc_bsdinfo *pbsd, int zombie);
static int __attribute__ ((noinline)) proc_pidshortbsdinfo(proc_t p, struct proc_bsdshortinfo *pbsd_shortp, int zombie);
static int __attribute__ ((noinline)) proc_pidtaskinfo(proc_t p, struct proc_taskinfo *ptinfo);
static int __attribute__ ((noinline)) proc_pidthreadinfo(proc_t p, uint64_t arg, bool thuniqueid, struct proc_threadinfo *pthinfo);
static int __attribute__ ((noinline)) proc_pidthreadpathinfo(proc_t p, uint64_t arg, struct proc_threadwithpathinfo *pinfo);
static int __attribute__ ((noinline)) proc_pidlistthreads(proc_t p, bool thuniqueid, user_addr_t buffer, uint32_t buffersize, int32_t *retval);
static int __attribute__ ((noinline)) proc_pidregioninfo(proc_t p, uint64_t arg, user_addr_t buffer, uint32_t buffersize, int32_t *retval);
static int __attribute__ ((noinline)) proc_pidregionpathinfo(proc_t p, uint64_t arg, user_addr_t buffer, uint32_t buffersize, int32_t *retval);
static int __attribute__ ((noinline)) proc_pidregionpathinfo2(proc_t p, uint64_t arg, user_addr_t buffer, uint32_t buffersize, int32_t *retval);
static int __attribute__ ((noinline)) proc_pidregionpathinfo3(proc_t p, uint64_t arg, user_addr_t buffer, uint32_t buffersize, int32_t *retval);
static int __attribute__ ((noinline)) proc_pidvnodepathinfo(proc_t p, uint64_t arg, user_addr_t buffer, uint32_t buffersize, int32_t *retval);
static int __attribute__ ((noinline)) proc_pidpathinfo(proc_t p, uint64_t arg, user_addr_t buffer, uint32_t buffersize, int32_t *retval);
static int __attribute__ ((noinline)) proc_pidworkqueueinfo(proc_t p, struct proc_workqueueinfo *pwqinfo);
static int __attribute__ ((noinline)) proc_pidfileportlist(proc_t p, user_addr_t buffer, size_t buffersize, int32_t *retval);
extern void __attribute__ ((noinline)) proc_piduniqidentifierinfo(proc_t p, struct proc_uniqidentifierinfo *p_uniqidinfo);
static void __attribute__ ((noinline)) proc_archinfo(proc_t p, struct proc_archinfo *pai);
static void __attribute__ ((noinline)) proc_pidcoalitioninfo(proc_t p, struct proc_pidcoalitioninfo *pci);
static int __attribute__ ((noinline)) proc_pidnoteexit(proc_t p, uint64_t arg, uint32_t *data);
static int __attribute__ ((noinline)) proc_pidexitreasoninfo(proc_t p, struct proc_exitreasoninfo *peri, struct proc_exitreasonbasicinfo *pberi);
static int __attribute__ ((noinline)) proc_pidoriginatorpid_uuid(uuid_t uuid, uint32_t buffersize, pid_t *pid);
static int __attribute__ ((noinline)) proc_pidlistuptrs(proc_t p, user_addr_t buffer, uint32_t buffersize, int32_t *retval);
static int __attribute__ ((noinline)) proc_piddynkqueueinfo(pid_t pid, int flavor, kqueue_id_t id, user_addr_t buffer, uint32_t buffersize, int32_t *retval);
static int __attribute__ ((noinline)) proc_pidregionpath(proc_t p, uint64_t arg, user_addr_t buffer, __unused uint32_t buffersize, int32_t *retval);
static int __attribute__ ((noinline)) proc_pidipctableinfo(proc_t p, struct proc_ipctableinfo *table_info);

#if CONFIG_PROC_UDATA_STORAGE
int __attribute__ ((noinline)) proc_udata_info(pid_t pid, int flavor, user_addr_t buffer, uint32_t buffersize, int32_t *retval);
#endif

/* protos for proc_pidfdinfo calls */
static int __attribute__ ((noinline)) pid_vnodeinfo(vnode_t vp, struct fileproc * fp, proc_t proc, int fd, user_addr_t  buffer, uint32_t buffersize, int32_t * retval);
static int __attribute__ ((noinline)) pid_vnodeinfopath(vnode_t vp, struct fileproc * fp, proc_t proc, int fd, user_addr_t  buffer, uint32_t buffersize, int32_t * retval);
static int __attribute__ ((noinline)) pid_socketinfo(socket_t so, struct fileproc *fp, proc_t proc, int fd, user_addr_t  buffer, uint32_t buffersize, int32_t * retval);
static int __attribute__ ((noinline)) pid_pseminfo(struct psemnode * psem, struct fileproc * fp, proc_t proc, int fd, user_addr_t  buffer, uint32_t buffersize, int32_t * retval);
static int __attribute__ ((noinline)) pid_pshminfo(struct pshmnode * pshm, struct fileproc * fp, proc_t proc, int fd, user_addr_t  buffer, uint32_t buffersize, int32_t * retval);
static int __attribute__ ((noinline)) pid_pipeinfo(struct pipe * p, struct fileproc * fp, proc_t proc, int fd, user_addr_t  buffer, uint32_t buffersize, int32_t * retval);
static int __attribute__ ((noinline)) pid_kqueueinfo(struct kqueue * kq, struct fileproc * fp, proc_t proc, int fd, user_addr_t  buffer, uint32_t buffersize, int32_t * retval);


/* protos for misc */

static int fill_vnodeinfo(vnode_t vp, struct vnode_info *vinfo, boolean_t check_fsgetpath);
static void fill_fileinfo(struct fileproc *fp, proc_t proc, int fd, struct proc_fileinfo * finfo);
static int proc_security_policy(proc_t targetp, int callnum, int flavor, boolean_t check_same_user);
static void munge_vinfo_stat(struct stat64 *sbp, struct vinfo_stat *vsbp);
static int proc_piduuidinfo(pid_t pid, uuid_t uuid_buf, uint32_t buffersize);

extern int proc_pidpathinfo_internal(proc_t p, __unused uint64_t arg, char *buf, uint32_t buffersize, __unused int32_t *retval);
extern int cansignal(struct proc *, kauth_cred_t, struct proc *, int);
extern int proc_get_rusage(proc_t proc, int flavor, user_addr_t buffer, int is_zombie);

#define CHECK_SAME_USER         TRUE
#define NO_CHECK_SAME_USER      FALSE

uint64_t
get_dispatchqueue_offset_from_proc(void *p)
{
	if (p != NULL) {
		proc_t pself = (proc_t)p;
		return pself->p_dispatchqueue_offset;
	} else {
		return (uint64_t)0;
	}
}

uint64_t
get_dispatchqueue_serialno_offset_from_proc(void *p)
{
	if (p != NULL) {
		proc_t pself = (proc_t)p;
		return pself->p_dispatchqueue_serialno_offset;
	} else {
		return (uint64_t)0;
	}
}

uint64_t
get_dispatchqueue_label_offset_from_proc(void *p)
{
	if (p != NULL) {
		proc_t pself = (proc_t)p;
		return pself->p_dispatchqueue_label_offset;
	} else {
		return (uint64_t)0;
	}
}

uint64_t
get_return_to_kernel_offset_from_proc(void *p)
{
	if (p != NULL) {
		proc_t pself = (proc_t)p;
		return pself->p_return_to_kernel_offset;
	} else {
		return (uint64_t)0;
	}
}

/***************************** proc_info ********************/

int
proc_info(__unused struct proc *p, struct proc_info_args * uap, int32_t *retval)
{
	return proc_info_internal(uap->callnum, uap->pid, 0, 0, uap->flavor, uap->arg, uap->buffer, uap->buffersize, retval);
}

int
proc_info_extended_id(__unused struct proc *p, struct proc_info_extended_id_args *uap, int32_t *retval)
{
	uint32_t flags = uap->flags;

	if ((flags & (PIF_COMPARE_IDVERSION | PIF_COMPARE_UNIQUEID)) == (PIF_COMPARE_IDVERSION | PIF_COMPARE_UNIQUEID)) {
		return EINVAL;
	}

	return proc_info_internal(uap->callnum, uap->pid, flags, uap->ext_id, uap->flavor, uap->arg, uap->buffer, uap->buffersize, retval);
}

int
proc_info_internal(int callnum, int pid, uint32_t flags, uint64_t ext_id, int flavor, uint64_t arg, user_addr_t buffer, uint32_t  buffersize, int32_t * retval)
{
	switch (callnum) {
	case PROC_INFO_CALL_LISTPIDS:
		/* pid contains type and flavor contains typeinfo */
		return proc_listpids(pid, flavor, buffer, buffersize, retval);
	case PROC_INFO_CALL_PIDINFO:
		return proc_pidinfo(pid, flags, ext_id, flavor, arg, buffer, buffersize, retval);
	case PROC_INFO_CALL_PIDFDINFO:
		return proc_pidfdinfo(pid, flavor, (int)arg, buffer, buffersize, retval);
	case PROC_INFO_CALL_KERNMSGBUF:
		return proc_kernmsgbuf(buffer, buffersize, retval);
	case PROC_INFO_CALL_SETCONTROL:
		return proc_setcontrol(pid, flavor, arg, buffer, buffersize, retval);
	case PROC_INFO_CALL_PIDFILEPORTINFO:
		return proc_pidfileportinfo(pid, flavor, (mach_port_name_t)arg, buffer, buffersize, retval);
	case PROC_INFO_CALL_TERMINATE:
		return proc_terminate(pid, retval);
	case PROC_INFO_CALL_DIRTYCONTROL:
		return proc_dirtycontrol(pid, flavor, arg, retval);
	case PROC_INFO_CALL_PIDRUSAGE:
		return proc_pid_rusage(pid, flavor, buffer, retval);
	case PROC_INFO_CALL_PIDORIGINATORINFO:
		return proc_pidoriginatorinfo(pid, flavor, buffer, buffersize, retval);
	case PROC_INFO_CALL_LISTCOALITIONS:
		return proc_listcoalitions(pid /* flavor */, flavor /* coaltype */, buffer,
		           buffersize, retval);
	case PROC_INFO_CALL_CANUSEFGHW:
		return proc_can_use_foreground_hw(pid, buffer, buffersize, retval);
	case PROC_INFO_CALL_PIDDYNKQUEUEINFO:
		return proc_piddynkqueueinfo(pid, flavor, (kqueue_id_t)arg, buffer, buffersize, retval);
#if CONFIG_PROC_UDATA_STORAGE
	case PROC_INFO_CALL_UDATA_INFO:
		return proc_udata_info(pid, flavor, buffer, buffersize, retval);
#endif /* CONFIG_PROC_UDATA_STORAGE */
	default:
		return EINVAL;
	}

	return EINVAL;
}

/******************* proc_listpids routine ****************/
int
proc_listpids(uint32_t type, uint32_t typeinfo, user_addr_t buffer, uint32_t  buffersize, int32_t * retval)
{
	uint32_t numprocs = 0;
	uint32_t wantpids;
	int *kbuf;
	int *ptr;
	uint32_t n;
	int skip;
	struct proc * p;
	struct tty * tp;
	int error = 0;
	struct proclist *current_list;

	/* Do we have permission to look into this? */
	if ((error = proc_security_policy(PROC_NULL, PROC_INFO_CALL_LISTPIDS, type, NO_CHECK_SAME_USER))) {
		return error;
	}

	/* if the buffer is null, return num of procs */
	if (buffer == (user_addr_t)0) {
		*retval = ((nprocs + 20) * sizeof(int));
		return 0;
	}

	if (buffersize < sizeof(int)) {
		return ENOMEM;
	}
	wantpids = buffersize / sizeof(int);
	if ((nprocs + 20) > 0) {
		numprocs = (uint32_t)(nprocs + 20);
	}
	if (numprocs > wantpids) {
		numprocs = wantpids;
	}

	kbuf = kheap_alloc(KHEAP_TEMP, numprocs * sizeof(int),
	    Z_WAITOK | Z_ZERO);
	if (kbuf == NULL) {
		return ENOMEM;
	}

	proc_list_lock();

	n = 0;
	ptr = kbuf;
	current_list = &allproc;
proc_loop:
	LIST_FOREACH(p, current_list, p_list) {
		skip = 0;
		switch (type) {
		case PROC_PGRP_ONLY:
			if (p->p_pgrpid != (pid_t)typeinfo) {
				skip = 1;
			}
			break;
		case PROC_PPID_ONLY:
			if ((p->p_ppid != (pid_t)typeinfo) && (((p->p_lflag & P_LTRACED) == 0) || (p->p_oppid != (pid_t)typeinfo))) {
				skip = 1;
			}
			break;

		case PROC_ALL_PIDS:
			skip = 0;
			break;
		case PROC_TTY_ONLY:
			/* racy but list lock is held */
			if ((p->p_flag & P_CONTROLT) == 0 ||
			    (p->p_pgrp == NULL) || (p->p_pgrp->pg_session == NULL) ||
			    (tp = SESSION_TP(p->p_pgrp->pg_session)) == TTY_NULL ||
			    tp->t_dev != (dev_t)typeinfo) {
				skip = 1;
			}
			break;
		case PROC_UID_ONLY:
			if (p->p_ucred == NULL) {
				skip = 1;
			} else {
				kauth_cred_t my_cred;
				uid_t uid;

				my_cred = kauth_cred_proc_ref(p);
				uid = kauth_cred_getuid(my_cred);
				kauth_cred_unref(&my_cred);
				if (uid != (uid_t)typeinfo) {
					skip = 1;
				}
			}
			break;
		case PROC_RUID_ONLY:
			if (p->p_ucred == NULL) {
				skip = 1;
			} else {
				kauth_cred_t my_cred;
				uid_t uid;

				my_cred = kauth_cred_proc_ref(p);
				uid = kauth_cred_getruid(my_cred);
				kauth_cred_unref(&my_cred);
				if (uid != (uid_t)typeinfo) {
					skip = 1;
				}
			}
			break;
		case PROC_KDBG_ONLY:
			if (p->p_kdebug == 0) {
				skip = 1;
			}
			break;
		default:
			skip = 1;
			break;
		}
		;

		if (skip == 0) {
			*ptr++ = p->p_pid;
			n++;
		}
		if (n >= numprocs) {
			break;
		}
	}

	if ((n < numprocs) && (current_list == &allproc)) {
		current_list = &zombproc;
		goto proc_loop;
	}

	proc_list_unlock();

	ptr = kbuf;
	error = copyout((caddr_t)ptr, buffer, n * sizeof(int));
	if (error == 0) {
		*retval = (n * sizeof(int));
	}
	kheap_free(KHEAP_TEMP, kbuf, numprocs * sizeof(int));

	return error;
}


/********************************** proc_pidfdlist routines ********************************/

static size_t
proc_fdlist_internal(proc_t p, struct proc_fdinfo *pfd, size_t numfds)
{
	struct fileproc *fp;
	size_t count = 0;

	proc_fdlock(p);

	fdt_foreach(fp, p) {
		if (count >= numfds) {
			break;
		}
		file_type_t fdtype = FILEGLOB_DTYPE(fp->fp_glob);
		pfd[count].proc_fd = fdt_foreach_fd();
		pfd[count].proc_fdtype = (fdtype != DTYPE_ATALK) ?
		    fdtype : PROX_FDTYPE_ATALK;
		count++;
	}

	proc_fdunlock(p);
	return count;
}

int
proc_pidfdlist(proc_t p, user_addr_t buffer, uint32_t  buffersize, int32_t *retval)
{
	uint32_t numfds = 0;
	uint32_t needfds;
	char * kbuf;
	uint32_t count = 0;
	int error = 0;

	if (p->p_fd->fd_nfiles > 0) {
		numfds = (uint32_t)p->p_fd->fd_nfiles;
	}

	if (buffer == (user_addr_t) 0) {
		numfds += 20;
		*retval = (numfds * sizeof(struct proc_fdinfo));
		return 0;
	}

	/* buffersize is big enough atleast for one struct */
	needfds = buffersize / sizeof(struct proc_fdinfo);

	if (numfds > needfds) {
		numfds = needfds;
	}

	kbuf = kheap_alloc(KHEAP_TEMP, numfds * sizeof(struct proc_fdinfo),
	    Z_WAITOK | Z_ZERO);
	if (kbuf == NULL) {
		return ENOMEM;
	}

	/* cannot overflow due to count <= numfds */
	count = (uint32_t)proc_fdlist_internal(p, (struct proc_fdinfo *)kbuf, (size_t)numfds);

	error = copyout(kbuf, buffer, count * sizeof(struct proc_fdinfo));
	kheap_free(KHEAP_TEMP, kbuf, numfds * sizeof(struct proc_fdinfo));
	if (error == 0) {
		*retval = count * sizeof(struct proc_fdinfo);
	}
	return error;
}

/*
 * KPI variant of proc_pidfdlist.
 *
 * Caller is responsible for adding margin to *count when calling this in
 * circumstances where file descriptors can appear/disappear between the
 * two calls to this function.
 */
int
proc_fdlist(proc_t p, struct proc_fdinfo *buf, size_t *count)
{
	if (p == NULL || count == NULL) {
		return EINVAL;
	}

	if (buf == NULL) {
		proc_fdlock(p);
		*count = (size_t)max(min(p->p_fd->fd_lastfile + 1, p->p_fd->fd_nfiles), 0);
		proc_fdunlock(p);
		return 0;
	}

	*count = proc_fdlist_internal(p, buf, *count);
	return 0;
}

/*
 * Helper functions for proc_pidfileportlist.
 */
static int
proc_fileport_count(__unused mach_port_name_t name,
    __unused struct fileglob *fg, void *arg)
{
	size_t *counter = arg;

	*counter += 1;
	return 0;
}

struct fileport_fdtype_args {
	struct proc_fileportinfo *ffa_pfi;
	struct proc_fileportinfo *ffa_pfi_end;
};

static int
proc_fileport_fdtype(mach_port_name_t name, struct fileglob *fg, void *arg)
{
	struct fileport_fdtype_args *ffa = arg;

	if (ffa->ffa_pfi != ffa->ffa_pfi_end) {
		file_type_t fdtype = FILEGLOB_DTYPE(fg);

		ffa->ffa_pfi->proc_fdtype = (fdtype != DTYPE_ATALK) ?
		    fdtype : PROX_FDTYPE_ATALK;
		ffa->ffa_pfi->proc_fileport = name;
		ffa->ffa_pfi++;
		return 0;             /* keep walking */
	} else {
		return -1;            /* stop the walk! */
	}
}

int
proc_pidfileportlist(proc_t p,
    user_addr_t buffer, size_t buffersize, int32_t *retval)
{
	void *kbuf;
	size_t kbufsize;
	struct proc_fileportinfo *pfi;
	size_t needfileports, numfileports;
	struct fileport_fdtype_args ffa;
	int error;

	needfileports = buffersize / sizeof(*pfi);
	if ((user_addr_t)0 == buffer || needfileports > (size_t)maxfilesperproc) {
		/*
		 * Either (i) the user is asking for a fileport count,
		 * or (ii) the number of fileports they're asking for is
		 * larger than the maximum number of open files (!); count
		 * them to bound subsequent heap allocations.
		 */
		numfileports = 0;
		switch (fileport_walk(p->task,
		    proc_fileport_count, &numfileports)) {
		case KERN_SUCCESS:
			break;
		case KERN_RESOURCE_SHORTAGE:
			return ENOMEM;
		case KERN_INVALID_TASK:
			return ESRCH;
		default:
			return EINVAL;
		}

		if (numfileports == 0) {
			*retval = 0;            /* none at all, bail */
			return 0;
		}
		if ((user_addr_t)0 == buffer) {
			numfileports += 20;     /* accelerate convergence */
			*retval = (int32_t)MIN(numfileports * sizeof(*pfi), INT32_MAX);
			return 0;
		}
		if (needfileports > numfileports) {
			needfileports = numfileports;
		}
	}

	assert(buffersize >= PROC_PIDLISTFILEPORTS_SIZE);

	kbufsize = needfileports * sizeof(*pfi);
	pfi = kbuf = kheap_alloc(KHEAP_TEMP, kbufsize, Z_WAITOK | Z_ZERO);
	if (kbuf == NULL) {
		return ENOMEM;
	}

	ffa.ffa_pfi = pfi;
	ffa.ffa_pfi_end = pfi + needfileports;

	switch (fileport_walk(p->task, proc_fileport_fdtype, &ffa)) {
	case KERN_SUCCESS:
		error = 0;
		pfi = ffa.ffa_pfi;
		if ((numfileports = (size_t)(pfi - (typeof(pfi))kbuf)) == 0) {
			break;
		}
		if (numfileports > needfileports) {
			panic("more fileports returned than requested");
		}
		error = copyout(kbuf, buffer, numfileports * sizeof(*pfi));
		break;
	case KERN_RESOURCE_SHORTAGE:
		error = ENOMEM;
		break;
	case KERN_INVALID_TASK:
		error = ESRCH;
		break;
	default:
		error = EINVAL;
		break;
	}
	kheap_free(KHEAP_TEMP, kbuf, kbufsize);
	if (error == 0) {
		*retval = (int32_t)MIN(numfileports * sizeof(*pfi), INT32_MAX);
	}
	return error;
}

int
proc_pidbsdinfo(proc_t p, struct proc_bsdinfo * pbsd, int zombie)
{
	struct tty *tp;
	struct  session *sessionp = NULL;
	struct pgrp * pg;
	kauth_cred_t my_cred;

	pg = proc_pgrp(p);
	sessionp = proc_session(p);

	my_cred = kauth_cred_proc_ref(p);
	bzero(pbsd, sizeof(struct proc_bsdinfo));
	pbsd->pbi_status = p->p_stat;
	pbsd->pbi_xstatus = p->p_xstat;
	pbsd->pbi_pid = p->p_pid;
	pbsd->pbi_ppid = p->p_ppid;
	pbsd->pbi_uid = kauth_cred_getuid(my_cred);
	pbsd->pbi_gid = kauth_cred_getgid(my_cred);
	pbsd->pbi_ruid =  kauth_cred_getruid(my_cred);
	pbsd->pbi_rgid = kauth_cred_getrgid(my_cred);
	pbsd->pbi_svuid =  kauth_cred_getsvuid(my_cred);
	pbsd->pbi_svgid = kauth_cred_getsvgid(my_cred);
	kauth_cred_unref(&my_cred);

	pbsd->pbi_nice = p->p_nice;
	pbsd->pbi_start_tvsec = p->p_start.tv_sec;
	pbsd->pbi_start_tvusec = p->p_start.tv_usec;
	bcopy(&p->p_comm, &pbsd->pbi_comm[0], MAXCOMLEN);
	pbsd->pbi_comm[MAXCOMLEN - 1] = '\0';
	bcopy(&p->p_name, &pbsd->pbi_name[0], 2 * MAXCOMLEN);
	pbsd->pbi_name[(2 * MAXCOMLEN) - 1] = '\0';

	pbsd->pbi_flags = 0;
	if ((p->p_flag & P_SYSTEM) == P_SYSTEM) {
		pbsd->pbi_flags |= PROC_FLAG_SYSTEM;
	}
	if ((p->p_lflag & P_LTRACED) == P_LTRACED) {
		pbsd->pbi_flags |= PROC_FLAG_TRACED;
	}
	if ((p->p_lflag & P_LEXIT) == P_LEXIT) {
		pbsd->pbi_flags |= PROC_FLAG_INEXIT;
	}
	if ((p->p_lflag & P_LPPWAIT) == P_LPPWAIT) {
		pbsd->pbi_flags |= PROC_FLAG_PPWAIT;
	}
	if ((p->p_flag & P_LP64) == P_LP64) {
		pbsd->pbi_flags |= PROC_FLAG_LP64;
	}
	if ((p->p_flag & P_CONTROLT) == P_CONTROLT) {
		pbsd->pbi_flags |= PROC_FLAG_CONTROLT;
	}
	if ((p->p_flag & P_THCWD) == P_THCWD) {
		pbsd->pbi_flags |= PROC_FLAG_THCWD;
	}
	if ((p->p_flag & P_SUGID) == P_SUGID) {
		pbsd->pbi_flags |= PROC_FLAG_PSUGID;
	}
	if ((p->p_flag & P_EXEC) == P_EXEC) {
		pbsd->pbi_flags |= PROC_FLAG_EXEC;
	}

	if (sessionp != SESSION_NULL) {
		if (SESS_LEADER(p, sessionp)) {
			pbsd->pbi_flags |= PROC_FLAG_SLEADER;
		}
		if (sessionp->s_ttyvp) {
			pbsd->pbi_flags |= PROC_FLAG_CTTY;
		}
	}

#if CONFIG_DELAY_IDLE_SLEEP
	if ((p->p_flag & P_DELAYIDLESLEEP) == P_DELAYIDLESLEEP) {
		pbsd->pbi_flags |= PROC_FLAG_DELAYIDLESLEEP;
	}
#endif /* CONFIG_DELAY_IDLE_SLEEP */

	switch (PROC_CONTROL_STATE(p)) {
	case P_PCTHROTTLE:
		pbsd->pbi_flags |= PROC_FLAG_PC_THROTTLE;
		break;
	case P_PCSUSP:
		pbsd->pbi_flags |= PROC_FLAG_PC_SUSP;
		break;
	case P_PCKILL:
		pbsd->pbi_flags |= PROC_FLAG_PC_KILL;
		break;
	}
	;

	switch (PROC_ACTION_STATE(p)) {
	case P_PCTHROTTLE:
		pbsd->pbi_flags |= PROC_FLAG_PA_THROTTLE;
		break;
	case P_PCSUSP:
		pbsd->pbi_flags |= PROC_FLAG_PA_SUSP;
		break;
	}
	;

	/* if process is a zombie skip bg state */
	if ((zombie == 0) && (p->p_stat != SZOMB) && (p->task != TASK_NULL)) {
		proc_get_darwinbgstate(p->task, &pbsd->pbi_flags);
	}

	if (zombie == 0) {
		pbsd->pbi_nfiles = p->p_fd->fd_nfiles;
	}

	pbsd->e_tdev = NODEV;
	if (pg != PGRP_NULL) {
		pbsd->pbi_pgid = p->p_pgrpid;
		pbsd->pbi_pjobc = pg->pg_jobc;
		if ((p->p_flag & P_CONTROLT) && (sessionp != SESSION_NULL) && (tp = SESSION_TP(sessionp))) {
			pbsd->e_tdev = tp->t_dev;
			pbsd->e_tpgid = sessionp->s_ttypgrpid;
		}
	}
	if (sessionp != SESSION_NULL) {
		session_rele(sessionp);
	}
	if (pg != PGRP_NULL) {
		pg_rele(pg);
	}

	return 0;
}


int
proc_pidshortbsdinfo(proc_t p, struct proc_bsdshortinfo * pbsd_shortp, int zombie)
{
	bzero(pbsd_shortp, sizeof(struct proc_bsdshortinfo));
	pbsd_shortp->pbsi_pid = p->p_pid;
	pbsd_shortp->pbsi_ppid = p->p_ppid;
	pbsd_shortp->pbsi_pgid = p->p_pgrpid;
	pbsd_shortp->pbsi_status = p->p_stat;
	bcopy(&p->p_comm, &pbsd_shortp->pbsi_comm[0], MAXCOMLEN);
	pbsd_shortp->pbsi_comm[MAXCOMLEN - 1] = '\0';

	pbsd_shortp->pbsi_flags = 0;
	if ((p->p_flag & P_SYSTEM) == P_SYSTEM) {
		pbsd_shortp->pbsi_flags |= PROC_FLAG_SYSTEM;
	}
	if ((p->p_lflag & P_LTRACED) == P_LTRACED) {
		pbsd_shortp->pbsi_flags |= PROC_FLAG_TRACED;
	}
	if ((p->p_lflag & P_LEXIT) == P_LEXIT) {
		pbsd_shortp->pbsi_flags |= PROC_FLAG_INEXIT;
	}
	if ((p->p_lflag & P_LPPWAIT) == P_LPPWAIT) {
		pbsd_shortp->pbsi_flags |= PROC_FLAG_PPWAIT;
	}
	if ((p->p_flag & P_LP64) == P_LP64) {
		pbsd_shortp->pbsi_flags |= PROC_FLAG_LP64;
	}
	if ((p->p_flag & P_CONTROLT) == P_CONTROLT) {
		pbsd_shortp->pbsi_flags |= PROC_FLAG_CONTROLT;
	}
	if ((p->p_flag & P_THCWD) == P_THCWD) {
		pbsd_shortp->pbsi_flags |= PROC_FLAG_THCWD;
	}
	if ((p->p_flag & P_SUGID) == P_SUGID) {
		pbsd_shortp->pbsi_flags |= PROC_FLAG_PSUGID;
	}
	if ((p->p_flag & P_EXEC) == P_EXEC) {
		pbsd_shortp->pbsi_flags |= PROC_FLAG_EXEC;
	}
#if CONFIG_DELAY_IDLE_SLEEP
	if ((p->p_flag & P_DELAYIDLESLEEP) == P_DELAYIDLESLEEP) {
		pbsd_shortp->pbsi_flags |= PROC_FLAG_DELAYIDLESLEEP;
	}
#endif /* CONFIG_DELAY_IDLE_SLEEP */

	switch (PROC_CONTROL_STATE(p)) {
	case P_PCTHROTTLE:
		pbsd_shortp->pbsi_flags |= PROC_FLAG_PC_THROTTLE;
		break;
	case P_PCSUSP:
		pbsd_shortp->pbsi_flags |= PROC_FLAG_PC_SUSP;
		break;
	case P_PCKILL:
		pbsd_shortp->pbsi_flags |= PROC_FLAG_PC_KILL;
		break;
	}
	;

	switch (PROC_ACTION_STATE(p)) {
	case P_PCTHROTTLE:
		pbsd_shortp->pbsi_flags |= PROC_FLAG_PA_THROTTLE;
		break;
	case P_PCSUSP:
		pbsd_shortp->pbsi_flags |= PROC_FLAG_PA_SUSP;
		break;
	}
	;

	/* if process is a zombie skip bg state */
	if ((zombie == 0) && (p->p_stat != SZOMB) && (p->task != TASK_NULL)) {
		proc_get_darwinbgstate(p->task, &pbsd_shortp->pbsi_flags);
	}

	pbsd_shortp->pbsi_uid = p->p_uid;
	pbsd_shortp->pbsi_gid = p->p_gid;
	pbsd_shortp->pbsi_ruid =  p->p_ruid;
	pbsd_shortp->pbsi_rgid = p->p_rgid;
	pbsd_shortp->pbsi_svuid =  p->p_svuid;
	pbsd_shortp->pbsi_svgid = p->p_svgid;

	return 0;
}

int
proc_pidtaskinfo(proc_t p, struct proc_taskinfo * ptinfo)
{
	task_t task;

	task = p->task;

	bzero(ptinfo, sizeof(struct proc_taskinfo));
	fill_taskprocinfo(task, (struct proc_taskinfo_internal *)ptinfo);

	return 0;
}



int
proc_pidthreadinfo(proc_t p, uint64_t arg, bool thuniqueid, struct proc_threadinfo *pthinfo)
{
	int error = 0;
	uint64_t threadaddr = (uint64_t)arg;

	bzero(pthinfo, sizeof(struct proc_threadinfo));

	error = fill_taskthreadinfo(p->task, threadaddr, thuniqueid, (struct proc_threadinfo_internal *)pthinfo, NULL, NULL);
	if (error) {
		return ESRCH;
	} else {
		return 0;
	}
}

boolean_t
bsd_hasthreadname(void *uth)
{
	struct uthread *ut = (struct uthread*)uth;

	/* This doesn't check for the empty string; do we care? */
	if (ut->pth_name) {
		return TRUE;
	} else {
		return FALSE;
	}
}

void
bsd_getthreadname(void *uth, char *buffer)
{
	struct uthread *ut = (struct uthread *)uth;
	if (ut->pth_name) {
		bcopy(ut->pth_name, buffer, MAXTHREADNAMESIZE);
	} else {
		*buffer = '\0';
	}
}

/*
 * This is known to race with regards to the contents of the thread name; concurrent
 * callers may result in a garbled name.
 */
void
bsd_setthreadname(void *uth, const char *name)
{
	struct uthread *ut = (struct uthread *)uth;
	char * name_buf = NULL;

	if (!ut->pth_name) {
		/* If there is no existing thread name, allocate a buffer for one. */
		name_buf = kalloc(MAXTHREADNAMESIZE);
		assert(name_buf);
		bzero(name_buf, MAXTHREADNAMESIZE);

		/* Someone could conceivably have named the thread at the same time we did. */
		if (!OSCompareAndSwapPtr(NULL, name_buf, &ut->pth_name)) {
			kfree(name_buf, MAXTHREADNAMESIZE);
		}
	} else {
		kernel_debug_string_simple(TRACE_STRING_THREADNAME_PREV, ut->pth_name);
	}

	strncpy(ut->pth_name, name, MAXTHREADNAMESIZE - 1);
	kernel_debug_string_simple(TRACE_STRING_THREADNAME, ut->pth_name);
}

void
bsd_copythreadname(void *dst_uth, void *src_uth)
{
	struct uthread *dst_ut = (struct uthread *)dst_uth;
	struct uthread *src_ut = (struct uthread *)src_uth;

	if (src_ut->pth_name == NULL) {
		return;
	}

	if (dst_ut->pth_name == NULL) {
		dst_ut->pth_name = (char *)kalloc(MAXTHREADNAMESIZE);
		if (dst_ut->pth_name == NULL) {
			return;
		}
	}

	bcopy(src_ut->pth_name, dst_ut->pth_name, MAXTHREADNAMESIZE);
	return;
}

void
bsd_threadcdir(void * uth, void *vptr, int *vidp)
{
	struct uthread * ut = (struct uthread *)uth;
	vnode_t vp;
	vnode_t *vpp = (vnode_t *)vptr;

	vp = ut->uu_cdir;
	if (vp != NULLVP) {
		if (vpp != NULL) {
			*vpp = vp;
			if (vidp != NULL) {
				*vidp = vp->v_id;
			}
		}
	}
}


int
proc_pidthreadpathinfo(proc_t p, uint64_t arg, struct proc_threadwithpathinfo *pinfo)
{
	vnode_t vp = NULLVP;
	int vid;
	int error = 0;
	uint64_t threadaddr = (uint64_t)arg;
	int count;

	bzero(pinfo, sizeof(struct proc_threadwithpathinfo));

	error = fill_taskthreadinfo(p->task, threadaddr, 0, (struct proc_threadinfo_internal *)&pinfo->pt, (void *)&vp, &vid);
	if (error) {
		return ESRCH;
	}

	if ((vp != NULLVP) && ((vnode_getwithvid(vp, vid)) == 0)) {
		error = fill_vnodeinfo(vp, &pinfo->pvip.vip_vi, FALSE);
		if (error == 0) {
			count = MAXPATHLEN;
			vn_getpath(vp, &pinfo->pvip.vip_path[0], &count);
			pinfo->pvip.vip_path[MAXPATHLEN - 1] = 0;
		}
		vnode_put(vp);
	}
	return error;
}



int
proc_pidlistthreads(proc_t p, bool thuniqueid, user_addr_t buffer, uint32_t  buffersize, int32_t *retval)
{
	uint32_t count = 0;
	int ret = 0;
	int error = 0;
	void * kbuf;
	uint32_t numthreads = 0;

	int num = get_numthreads(p->task) + 10;
	if (num > 0) {
		numthreads = (uint32_t)num;
	}

	count = buffersize / (sizeof(uint64_t));

	if (numthreads > count) {
		numthreads = count;
	}

	kbuf = kheap_alloc(KHEAP_TEMP,
	    numthreads * sizeof(uint64_t), Z_WAITOK | Z_ZERO);
	if (kbuf == NULL) {
		return ENOMEM;
	}

	ret = fill_taskthreadlist(p->task, kbuf, numthreads, thuniqueid);

	error = copyout(kbuf, buffer, ret);
	kheap_free(KHEAP_TEMP, kbuf, numthreads * sizeof(uint64_t));
	if (error == 0) {
		*retval = ret;
	}
	return error;
}


int
proc_pidregioninfo(proc_t p, uint64_t arg, user_addr_t buffer, __unused uint32_t  buffersize, int32_t *retval)
{
	struct proc_regioninfo preginfo;
	int ret, error = 0;

	bzero(&preginfo, sizeof(struct proc_regioninfo));
	ret = fill_procregioninfo( p->task, arg, (struct proc_regioninfo_internal *)&preginfo, (uintptr_t *)0, (uint32_t *)0);
	if (ret == 0) {
		return EINVAL;
	}
	error = copyout(&preginfo, buffer, sizeof(struct proc_regioninfo));
	if (error == 0) {
		*retval = sizeof(struct proc_regioninfo);
	}
	return error;
}


int
proc_pidregionpathinfo(proc_t p, uint64_t arg, user_addr_t buffer, __unused uint32_t  buffersize, int32_t *retval)
{
	struct proc_regionwithpathinfo preginfo;
	int ret, error = 0;
	uintptr_t vnodeaddr = 0;
	uint32_t vnodeid = 0;
	vnode_t vp;
	int count;

	bzero(&preginfo, sizeof(struct proc_regionwithpathinfo));

	ret = fill_procregioninfo( p->task, arg, (struct proc_regioninfo_internal *)&preginfo.prp_prinfo, (uintptr_t *)&vnodeaddr, (uint32_t *)&vnodeid);
	if (ret == 0) {
		return EINVAL;
	}
	if (vnodeaddr) {
		vp = (vnode_t)vnodeaddr;
		if ((vnode_getwithvid(vp, vnodeid)) == 0) {
			/* FILL THE VNODEINFO */
			error = fill_vnodeinfo(vp, &preginfo.prp_vip.vip_vi, FALSE);
			count = MAXPATHLEN;
			vn_getpath(vp, &preginfo.prp_vip.vip_path[0], &count);
			/* Always make sure it is null terminated */
			preginfo.prp_vip.vip_path[MAXPATHLEN - 1] = 0;
			vnode_put(vp);
		}
	}
	error = copyout(&preginfo, buffer, sizeof(struct proc_regionwithpathinfo));
	if (error == 0) {
		*retval = sizeof(struct proc_regionwithpathinfo);
	}
	return error;
}

int
proc_pidregionpathinfo2(proc_t p, uint64_t arg, user_addr_t buffer, __unused uint32_t buffersize, int32_t *retval)
{
	struct proc_regionwithpathinfo preginfo;
	int ret, error = 0;
	uintptr_t vnodeaddr = 0;
	uint32_t vnodeid = 0;
	vnode_t vp;
	int count;

	bzero(&preginfo, sizeof(struct proc_regionwithpathinfo));

	ret = fill_procregioninfo_onlymappedvnodes( p->task, arg, (struct proc_regioninfo_internal *)&preginfo.prp_prinfo, (uintptr_t *)&vnodeaddr, (uint32_t *)&vnodeid);
	if (ret == 0) {
		return EINVAL;
	}
	if (!vnodeaddr) {
		return EINVAL;
	}

	vp = (vnode_t)vnodeaddr;
	if ((vnode_getwithvid(vp, vnodeid)) == 0) {
		/* FILL THE VNODEINFO */
		error = fill_vnodeinfo(vp, &preginfo.prp_vip.vip_vi, FALSE);
		count = MAXPATHLEN;
		vn_getpath(vp, &preginfo.prp_vip.vip_path[0], &count);
		/* Always make sure it is null terminated */
		preginfo.prp_vip.vip_path[MAXPATHLEN - 1] = 0;
		vnode_put(vp);
	} else {
		return EINVAL;
	}

	error = copyout(&preginfo, buffer, sizeof(struct proc_regionwithpathinfo));
	if (error == 0) {
		*retval = sizeof(struct proc_regionwithpathinfo);
	}
	return error;
}

int
proc_pidregionpath(proc_t p, uint64_t arg, user_addr_t buffer, __unused uint32_t buffersize, int32_t *retval)
{
	struct proc_regionpath path = {};
	int ret, error = 0;
	uintptr_t vnodeaddr = 0;
	uint32_t vnodeid = 0;
	vnode_t vp;

	ret = find_region_details(p->task, (vm_map_offset_t) arg,
	    (uintptr_t *)&vnodeaddr, (uint32_t *)&vnodeid,
	    &path.prpo_addr, &path.prpo_regionlength);
	if (ret == 0) {
		return EINVAL;
	}
	if (!vnodeaddr) {
		return EINVAL;
	}

	vp = (vnode_t)vnodeaddr;
	if ((vnode_getwithvid(vp, vnodeid)) == 0) {
		int count = MAXPATHLEN;
		vn_getpath(vp, &path.prpo_path[0], &count);
		/* Always make sure it is null terminated */
		path.prpo_path[MAXPATHLEN - 1] = 0;
		vnode_put(vp);
	} else {
		return EINVAL;
	}

	error = copyout(&path, buffer, sizeof(struct proc_regionpath));
	if (error == 0) {
		*retval = sizeof(struct proc_regionpath);
	}
	return error;
}

int
proc_pidregionpathinfo3(proc_t p, uint64_t arg, user_addr_t buffer, __unused uint32_t buffersize, int32_t *retval)
{
	struct proc_regionwithpathinfo preginfo;
	int ret, error = 0;
	uintptr_t vnodeaddr;
	uint32_t vnodeid;
	vnode_t vp;
	int count;
	uint64_t addr = 0;

	/* Loop while looking for vnodes that match dev_t filter */
	do {
		bzero(&preginfo, sizeof(struct proc_regionwithpathinfo));
		vnodeaddr = 0;
		vnodeid = 0;

		ret = fill_procregioninfo_onlymappedvnodes( p->task, addr, (struct proc_regioninfo_internal *)&preginfo.prp_prinfo, (uintptr_t *)&vnodeaddr, (uint32_t *)&vnodeid);
		if (ret == 0) {
			return EINVAL;
		}
		if (!vnodeaddr) {
			return EINVAL;
		}

		vp = (vnode_t)vnodeaddr;
		if ((vnode_getwithvid(vp, vnodeid)) == 0) {
			/* Check if the vnode matches the filter, otherwise loop looking for the next memory region backed by a vnode */
			struct vnode_attr va;

			memset(&va, 0, sizeof(va));
			VATTR_INIT(&va);
			VATTR_WANTED(&va, va_fsid);
			VATTR_WANTED(&va, va_fsid64);

			ret = vnode_getattr(vp, &va, vfs_context_current());
			if (ret) {
				vnode_put(vp);
				return EINVAL;
			}

			if (vnode_get_va_fsid(&va) == arg) {
				/* FILL THE VNODEINFO */
				error = fill_vnodeinfo(vp, &preginfo.prp_vip.vip_vi, FALSE);
				count = MAXPATHLEN;
				vn_getpath(vp, &preginfo.prp_vip.vip_path[0], &count);
				/* Always make sure it is null terminated */
				preginfo.prp_vip.vip_path[MAXPATHLEN - 1] = 0;
				vnode_put(vp);
				break;
			}
			vnode_put(vp);
		} else {
			return EINVAL;
		}

		addr = preginfo.prp_prinfo.pri_address + preginfo.prp_prinfo.pri_size;
	} while (1);

	error = copyout(&preginfo, buffer, sizeof(struct proc_regionwithpathinfo));
	if (error == 0) {
		*retval = sizeof(struct proc_regionwithpathinfo);
	}
	return error;
}

/*
 * Path is relative to current process directory; may different from current
 * thread directory.
 */
int
proc_pidvnodepathinfo(proc_t p, __unused uint64_t arg, user_addr_t buffer, __unused uint32_t  buffersize, int32_t *retval)
{
	struct proc_vnodepathinfo pvninfo;
	int error = 0;
	vnode_t vncdirvp = NULLVP;
	uint32_t vncdirid = 0;
	vnode_t vnrdirvp = NULLVP;
	uint32_t vnrdirid = 0;
	int count;

	bzero(&pvninfo, sizeof(struct proc_vnodepathinfo));

	proc_fdlock(p);
	if (p->p_fd->fd_cdir) {
		vncdirvp = p->p_fd->fd_cdir;
		vncdirid = p->p_fd->fd_cdir->v_id;
	}
	if (p->p_fd->fd_rdir) {
		vnrdirvp = p->p_fd->fd_rdir;
		vnrdirid = p->p_fd->fd_rdir->v_id;
	}
	proc_fdunlock(p);

	if (vncdirvp != NULLVP) {
		if ((error = vnode_getwithvid(vncdirvp, vncdirid)) == 0) {
			/* FILL THE VNODEINFO */
			error = fill_vnodeinfo(vncdirvp, &pvninfo.pvi_cdir.vip_vi, TRUE);
			if (error == 0) {
				count = MAXPATHLEN;
				vn_getpath(vncdirvp, &pvninfo.pvi_cdir.vip_path[0], &count);
				pvninfo.pvi_cdir.vip_path[MAXPATHLEN - 1] = 0;
			}
			vnode_put(vncdirvp);
		} else {
			goto out;
		}
	}

	if ((error == 0) && (vnrdirvp != NULLVP)) {
		if ((error = vnode_getwithvid(vnrdirvp, vnrdirid)) == 0) {
			/* FILL THE VNODEINFO */
			error = fill_vnodeinfo(vnrdirvp, &pvninfo.pvi_rdir.vip_vi, TRUE);
			if (error == 0) {
				count = MAXPATHLEN;
				vn_getpath(vnrdirvp, &pvninfo.pvi_rdir.vip_path[0], &count);
				pvninfo.pvi_rdir.vip_path[MAXPATHLEN - 1] = 0;
			}
			vnode_put(vnrdirvp);
		} else {
			goto out;
		}
	}
	if (error == 0) {
		error = copyout(&pvninfo, buffer, sizeof(struct proc_vnodepathinfo));
		if (error == 0) {
			*retval = sizeof(struct proc_vnodepathinfo);
		}
	}
out:
	return error;
}

int
proc_pidpathinfo(proc_t p, __unused uint64_t arg, user_addr_t buffer, uint32_t buffersize, __unused int32_t *retval)
{
	int error;
	vnode_t tvp;
	int len = buffersize;
	char * buf;

	tvp = p->p_textvp;

	if (tvp == NULLVP) {
		return ESRCH;
	}

	buf = kheap_alloc(KHEAP_TEMP, buffersize, Z_WAITOK | Z_ZERO);
	if (buf == NULL) {
		return ENOMEM;
	}

	error = proc_pidpathinfo_internal(p, arg, buf, buffersize, retval);
	if (error == 0) {
		error = copyout(buf, buffer, len);
	}
	kheap_free(KHEAP_TEMP, buf, buffersize);
	return error;
}

int
proc_pidpathinfo_internal(proc_t p, __unused uint64_t arg, char *buf, uint32_t buffersize, __unused int32_t *retval)
{
	int vid, error;
	vnode_t tvp;
	vnode_t nvp = NULLVP;
	int len = buffersize;

	tvp = p->p_textvp;

	if (tvp == NULLVP) {
		return ESRCH;
	}

	vid = vnode_vid(tvp);
	error = vnode_getwithvid(tvp, vid);
	if (error == 0) {
		error = vn_getpath_fsenter(tvp, buf, &len);
		vnode_put(tvp);
		if (error == 0) {
			error = vnode_lookup(buf, 0, &nvp, vfs_context_current());
			if ((error == 0) && (nvp != NULLVP)) {
				vnode_put(nvp);
			}
		}
	}
	return error;
}


int
proc_pidworkqueueinfo(proc_t p, struct proc_workqueueinfo *pwqinfo)
{
	int error = 0;

	bzero(pwqinfo, sizeof(struct proc_workqueueinfo));

	error = fill_procworkqueue(p, pwqinfo);
	if (error) {
		return ESRCH;
	} else {
		return 0;
	}
}


void
proc_piduniqidentifierinfo(proc_t p, struct proc_uniqidentifierinfo *p_uniqidinfo)
{
	p_uniqidinfo->p_uniqueid = proc_uniqueid(p);
	proc_getexecutableuuid(p, (unsigned char *)&p_uniqidinfo->p_uuid, sizeof(p_uniqidinfo->p_uuid));
	p_uniqidinfo->p_puniqueid = proc_puniqueid(p);
	p_uniqidinfo->p_idversion = proc_pidversion(p);
	p_uniqidinfo->p_reserve2 = 0;
	p_uniqidinfo->p_reserve3 = 0;
	p_uniqidinfo->p_reserve4 = 0;
}


static int
proc_piduuidinfo(pid_t pid, uuid_t uuid_buf, uint32_t buffersize)
{
	struct proc * p = PROC_NULL;
	int zombref = 0;

	if (buffersize < sizeof(uuid_t)) {
		return EINVAL;
	}

	if ((p = proc_find(pid)) == PROC_NULL) {
		p = proc_find_zombref(pid);
		zombref = 1;
	}
	if (p == PROC_NULL) {
		return ESRCH;
	}

	proc_getexecutableuuid(p, (unsigned char *)uuid_buf, buffersize);

	if (zombref) {
		proc_drop_zombref(p);
	} else {
		proc_rele(p);
	}

	return 0;
}

/*
 * Function to get the uuid and pid of the originator of the voucher.
 */
int
proc_pidoriginatorpid_uuid(uuid_t uuid, uint32_t buffersize, pid_t *pid)
{
	pid_t originator_pid;
	kern_return_t kr;
	int error;

	/*
	 * Get the current voucher origin pid. The pid returned here
	 * might not be valid or may have been recycled.
	 */
	kr = thread_get_current_voucher_origin_pid(&originator_pid);
	/* If errors, convert errors to appropriate format */
	if (kr) {
		if (kr == KERN_INVALID_TASK) {
			error = ESRCH;
		} else if (kr == KERN_INVALID_VALUE) {
			error = ENOATTR;
		} else {
			error = EINVAL;
		}
		return error;
	}

	*pid = originator_pid;
	error = proc_piduuidinfo(originator_pid, uuid, buffersize);
	return error;
}

/*
 * Function to get the uuid of the originator of the voucher.
 */
int
proc_pidoriginatoruuid(uuid_t uuid, uint32_t buffersize)
{
	pid_t originator_pid;
	return proc_pidoriginatorpid_uuid(uuid, buffersize, &originator_pid);
}

/*
 * Function to get the task ipc table size.
 */
int
proc_pidipctableinfo(proc_t p, struct proc_ipctableinfo *table_info)
{
	task_t task;
	int error = 0;

	task = p->task;

	bzero(table_info, sizeof(struct proc_ipctableinfo));
	error = fill_taskipctableinfo(task, &(table_info->table_size), &(table_info->table_free));

	if (error) {
		error = EINVAL;
	}

	return error;
}

/***************************** proc_pidoriginatorinfo ***************************/

int
proc_pidoriginatorinfo(int pid, int flavor, user_addr_t buffer, uint32_t  buffersize, int32_t * retval)
{
	int error = ENOTSUP;
	uint32_t size;

	switch (flavor) {
	case PROC_PIDORIGINATOR_UUID:
		size = PROC_PIDORIGINATOR_UUID_SIZE;
		break;
	case PROC_PIDORIGINATOR_BGSTATE:
		size = PROC_PIDORIGINATOR_BGSTATE_SIZE;
		break;
	case PROC_PIDORIGINATOR_PID_UUID:
		size = PROC_PIDORIGINATOR_PID_UUID_SIZE;
		break;
	default:
		return EINVAL;
	}

	if (buffersize < size) {
		return ENOMEM;
	}

	if (pid != 0 && pid != proc_selfpid()) {
		return EINVAL;
	}

	switch (flavor) {
	case PROC_PIDORIGINATOR_UUID: {
		uuid_t uuid = {};

		error = proc_pidoriginatoruuid(uuid, sizeof(uuid));
		if (error != 0) {
			goto out;
		}

		error = copyout(uuid, buffer, size);
		if (error == 0) {
			*retval = size;
		}
	}
	break;

	case PROC_PIDORIGINATOR_PID_UUID: {
		struct proc_originatorinfo originator_info;
		bzero(&originator_info, sizeof(originator_info));

		error = proc_pidoriginatorpid_uuid(originator_info.originator_uuid,
		    sizeof(uuid_t), &originator_info.originator_pid);
		if (error != 0) {
			goto out;
		}

		error = copyout(&originator_info, buffer, size);
		if (error == 0) {
			*retval = size;
		}
	}
	break;

	case PROC_PIDORIGINATOR_BGSTATE: {
		uint32_t is_backgrounded = 0;
		error = proc_get_originatorbgstate(&is_backgrounded);
		if (error) {
			goto out;
		}

		error = copyout(&is_backgrounded, buffer, size);
		if (error == 0) {
			*retval = size;
		}
	}
	break;

	default:
		error = ENOTSUP;
	}
out:
	return error;
}

/***************************** proc_listcoalitions ***************************/
int
proc_listcoalitions(int flavor, int type, user_addr_t buffer,
    uint32_t buffersize, int32_t *retval)
{
#if CONFIG_COALITIONS
	int error = ENOTSUP;
	int coal_type;
	uint32_t elem_size;
	void *coalinfo = NULL;
	uint32_t k_buffersize = 0, copyout_sz = 0;
	int ncoals = 0, ncoals_ = 0;

	/* struct procinfo_coalinfo; */

	switch (flavor) {
	case LISTCOALITIONS_ALL_COALS:
		elem_size = LISTCOALITIONS_ALL_COALS_SIZE;
		coal_type = -1;
		break;
	case LISTCOALITIONS_SINGLE_TYPE:
		elem_size = LISTCOALITIONS_SINGLE_TYPE_SIZE;
		coal_type = type;
		break;
	default:
		return EINVAL;
	}

	/* find the total number of coalitions */
	ncoals = coalitions_get_list(coal_type, NULL, 0);

	if (ncoals == 0 || buffer == 0 || buffersize == 0) {
		/*
		 * user just wants buffer size
		 * or there are no coalitions
		 */
		error = 0;
		*retval = (int)(ncoals * elem_size);
		goto out;
	}

	k_buffersize = ncoals * elem_size;
	coalinfo = kheap_alloc(KHEAP_TEMP, k_buffersize, Z_WAITOK | Z_ZERO);
	if (!coalinfo) {
		error = ENOMEM;
		goto out;
	}

	switch (flavor) {
	case LISTCOALITIONS_ALL_COALS:
	case LISTCOALITIONS_SINGLE_TYPE:
		ncoals_ = coalitions_get_list(coal_type, coalinfo, ncoals);
		break;
	default:
		panic("memory corruption?!");
	}

	if (ncoals_ == 0) {
		/* all the coalitions disappeared... weird but valid */
		error = 0;
		*retval = 0;
		goto out;
	}

	/*
	 * Some coalitions may have disappeared between our initial check,
	 * and the the actual list acquisition.
	 * Only copy out what we really need.
	 */
	copyout_sz = k_buffersize;
	if (ncoals_ < ncoals) {
		copyout_sz = ncoals_ * elem_size;
	}

	/*
	 * copy the list up to user space
	 * (we're guaranteed to have a non-null pointer/size here)
	 */
	error = copyout(coalinfo, buffer,
	    copyout_sz < buffersize ? copyout_sz : buffersize);

	if (error == 0) {
		*retval = (int)copyout_sz;
	}

out:
	if (coalinfo) {
		kheap_free(KHEAP_TEMP, coalinfo, k_buffersize);
	}

	return error;
#else
	/* no coalition support */
	(void)flavor;
	(void)type;
	(void)buffer;
	(void)buffersize;
	(void)retval;
	return ENOTSUP;
#endif
}


/*************************** proc_can_use_forgeound_hw **************************/
int
proc_can_use_foreground_hw(int pid, user_addr_t u_reason, uint32_t reasonsize, int32_t *retval)
{
	proc_t p = PROC_NULL;
	int error = 0;
	uint32_t reason = PROC_FGHW_ERROR;
	uint32_t isBG = 0;
	task_t task = TASK_NULL;
#if CONFIG_COALITIONS
	coalition_t coal = COALITION_NULL;
#endif

	*retval = 0;

	if (pid <= 0) {
		error = EINVAL;
		reason = PROC_FGHW_ERROR;
		goto out;
	}

	p = proc_find(pid);
	if (p == PROC_NULL) {
		error = ESRCH;
		reason = PROC_FGHW_ERROR;
		goto out;
	}

#if CONFIG_COALITIONS
	if (p != current_proc() &&
	    !kauth_cred_issuser(kauth_cred_get())) {
		error = EPERM;
		reason = PROC_FGHW_ERROR;
		goto out;
	}

	task = p->task;
	if (coalition_is_leader(task, task_get_coalition(task, COALITION_TYPE_JETSAM))) {
		task_reference(task);
	} else {
		/* current task is not a coalition leader: find the leader */
		task = coalition_get_leader(coal);
	}

	if (task != TASK_NULL) {
		/*
		 * If task is non-null, then it is the coalition leader of the
		 * current process' coalition. This could be the same task as
		 * the current_task, and that's OK.
		 */
		uint32_t flags = 0;
		int role;

		proc_get_darwinbgstate(task, &flags);
		if ((flags & PROC_FLAG_APPLICATION) != PROC_FLAG_APPLICATION) {
			/*
			 * Coalition leader is not an application, continue
			 * searching for other ways this task could gain
			 * access to HW
			 */
			reason = PROC_FGHW_DAEMON_LEADER;
			goto no_leader;
		}

		if (proc_get_effective_task_policy(task, TASK_POLICY_DARWIN_BG)) {
			/*
			 * If the leader of the current process' coalition has
			 * been marked as DARWIN_BG, then it definitely should
			 * not be using foreground hardware resources.
			 */
			reason = PROC_FGHW_LEADER_BACKGROUND;
			goto out;
		}

		role = proc_get_effective_task_policy(task, TASK_POLICY_ROLE);
		switch (role) {
		case TASK_FOREGROUND_APPLICATION: /* DARWIN_ROLE_UI_FOCAL */
		case TASK_BACKGROUND_APPLICATION: /* DARWIN_ROLE_UI */
			/*
			 * The leader of this coalition is a focal, UI app:
			 * access granted
			 * TODO: should extensions/plugins be allowed to use
			 *       this hardware?
			 */
			*retval = 1;
			reason = PROC_FGHW_OK;
			goto out;
		case TASK_DEFAULT_APPLICATION: /* DARWIN_ROLE_UI_NON_FOCAL */
		case TASK_NONUI_APPLICATION: /* DARWIN_ROLE_NON_UI */
		case TASK_THROTTLE_APPLICATION:
		case TASK_UNSPECIFIED:
		default:
			/* non-focal, non-ui apps don't get access */
			reason = PROC_FGHW_LEADER_NONUI;
			goto out;
		}
	}

no_leader:
	if (task != TASK_NULL) {
		task_deallocate(task);
		task = TASK_NULL;
	}
#endif /* CONFIG_COALITIONS */

	/*
	 * There is no reasonable semantic to investigate the currently
	 * adopted voucher of an arbitrary thread in a non-current process.
	 * We return '0'
	 */
	if (p != current_proc()) {
		error = EINVAL;
		goto out;
	}

	/*
	 * In the absence of coalitions, fall back to a voucher-based lookup
	 * where a daemon can used foreground HW if it's operating on behalf
	 * of a foreground application.
	 * NOTE: this is equivalent to a call to
	 *       proc_pidoriginatorinfo(PROC_PIDORIGINATOR_BGSTATE, &isBG, sizeof(isBG))
	 */
	isBG = 1;
	error = proc_get_originatorbgstate(&isBG);
	switch (error) {
	case 0:
		break;
	case ESRCH:
		reason = PROC_FGHW_NO_ORIGINATOR;
		error = 0;
		goto out;
	case ENOATTR:
		reason = PROC_FGHW_NO_VOUCHER_ATTR;
		error = 0;
		goto out;
	case EINVAL:
		reason = PROC_FGHW_DAEMON_NO_VOUCHER;
		error = 0;
		goto out;
	default:
		/* some other error occurred: report that to the caller */
		reason = PROC_FGHW_VOUCHER_ERROR;
		goto out;
	}

	if (isBG) {
		reason = PROC_FGHW_ORIGINATOR_BACKGROUND;
		error = 0;
	} else {
		/*
		 * The process itself is either a foreground app, or has
		 * adopted a voucher originating from an app that's still in
		 * the foreground
		 */
		reason = PROC_FGHW_DAEMON_OK;
		*retval = 1;
	}

out:
	if (task != TASK_NULL) {
		task_deallocate(task);
	}
	if (p != PROC_NULL) {
		proc_rele(p);
	}
	if (reasonsize >= sizeof(reason) && u_reason != (user_addr_t)0) {
		(void)copyout(&reason, u_reason, sizeof(reason));
	}
	return error;
}


/********************************** proc_pidinfo ********************************/


int
proc_pidinfo(int pid, uint32_t flags, uint64_t ext_id, int flavor, uint64_t arg, user_addr_t buffer, uint32_t  buffersize, int32_t * retval)
{
	struct proc * p = PROC_NULL;
	int error = ENOTSUP;
	int gotref = 0;
	int findzomb = 0;
	int shortversion = 0;
	uint32_t size;
	int zombie = 0;
	bool thuniqueid = false;
	int uniqidversion = 0;
	bool check_same_user;

	switch (flavor) {
	case PROC_PIDLISTFDS:
		size = PROC_PIDLISTFD_SIZE;
		if (buffer == USER_ADDR_NULL) {
			size = 0;
		}
		break;
	case PROC_PIDTBSDINFO:
		size = PROC_PIDTBSDINFO_SIZE;
		break;
	case PROC_PIDTASKINFO:
		size = PROC_PIDTASKINFO_SIZE;
		break;
	case PROC_PIDTASKALLINFO:
		size = PROC_PIDTASKALLINFO_SIZE;
		break;
	case PROC_PIDTHREADINFO:
		size = PROC_PIDTHREADINFO_SIZE;
		break;
	case PROC_PIDLISTTHREADIDS:
		size = PROC_PIDLISTTHREADIDS_SIZE;
		break;
	case PROC_PIDLISTTHREADS:
		size = PROC_PIDLISTTHREADS_SIZE;
		break;
	case PROC_PIDREGIONINFO:
		size = PROC_PIDREGIONINFO_SIZE;
		break;
	case PROC_PIDREGIONPATHINFO:
		size = PROC_PIDREGIONPATHINFO_SIZE;
		break;
	case PROC_PIDVNODEPATHINFO:
		size = PROC_PIDVNODEPATHINFO_SIZE;
		break;
	case PROC_PIDTHREADPATHINFO:
		size = PROC_PIDTHREADPATHINFO_SIZE;
		break;
	case PROC_PIDPATHINFO:
		size = MAXPATHLEN;
		break;
	case PROC_PIDWORKQUEUEINFO:
		/* kernel does not have workq info */
		if (pid == 0) {
			return EINVAL;
		} else {
			size = PROC_PIDWORKQUEUEINFO_SIZE;
		}
		break;
	case PROC_PIDT_SHORTBSDINFO:
		size = PROC_PIDT_SHORTBSDINFO_SIZE;
		break;
	case PROC_PIDLISTFILEPORTS:
		size = PROC_PIDLISTFILEPORTS_SIZE;
		if (buffer == (user_addr_t)0) {
			size = 0;
		}
		break;
	case PROC_PIDTHREADID64INFO:
		size = PROC_PIDTHREADID64INFO_SIZE;
		break;
	case PROC_PIDUNIQIDENTIFIERINFO:
		size = PROC_PIDUNIQIDENTIFIERINFO_SIZE;
		break;
	case PROC_PIDT_BSDINFOWITHUNIQID:
		size = PROC_PIDT_BSDINFOWITHUNIQID_SIZE;
		break;
	case PROC_PIDARCHINFO:
		size = PROC_PIDARCHINFO_SIZE;
		break;
	case PROC_PIDCOALITIONINFO:
		size = PROC_PIDCOALITIONINFO_SIZE;
		break;
	case PROC_PIDNOTEEXIT:
		/*
		 * Set findzomb explicitly because arg passed
		 * in is used as note exit status bits.
		 */
		size = PROC_PIDNOTEEXIT_SIZE;
		findzomb = 1;
		break;
	case PROC_PIDEXITREASONINFO:
		size = PROC_PIDEXITREASONINFO_SIZE;
		findzomb = 1;
		break;
	case PROC_PIDEXITREASONBASICINFO:
		size = PROC_PIDEXITREASONBASICINFOSIZE;
		findzomb = 1;
		break;
	case PROC_PIDREGIONPATHINFO2:
		size = PROC_PIDREGIONPATHINFO2_SIZE;
		break;
	case PROC_PIDREGIONPATHINFO3:
		size = PROC_PIDREGIONPATHINFO3_SIZE;
		break;
	case PROC_PIDLISTUPTRS:
		size = PROC_PIDLISTUPTRS_SIZE;
		if (buffer == USER_ADDR_NULL) {
			size = 0;
		}
		break;
	case PROC_PIDLISTDYNKQUEUES:
		size = PROC_PIDLISTDYNKQUEUES_SIZE;
		if (buffer == USER_ADDR_NULL) {
			size = 0;
		}
		break;
	case PROC_PIDVMRTFAULTINFO:
		size = sizeof(vm_rtfault_record_t);
		if (buffer == USER_ADDR_NULL) {
			size = 0;
		}
		break;
	case PROC_PIDPLATFORMINFO:
		size = PROC_PIDPLATFORMINFO_SIZE;
		findzomb = 1;
		break;
	case PROC_PIDREGIONPATH:
		size = PROC_PIDREGIONPATH_SIZE;
		break;
	case PROC_PIDIPCTABLEINFO:
		size = PROC_PIDIPCTABLEINFO_SIZE;
		break;
	default:
		return EINVAL;
	}

	if (buffersize < size) {
		return ENOMEM;
	}

	if ((flavor == PROC_PIDPATHINFO) && (buffersize > PROC_PIDPATHINFO_MAXSIZE)) {
		return EOVERFLOW;
	}

	/* Check if we need to look for zombies */
	if ((flavor == PROC_PIDTBSDINFO) || (flavor == PROC_PIDT_SHORTBSDINFO) || (flavor == PROC_PIDT_BSDINFOWITHUNIQID)
	    || (flavor == PROC_PIDUNIQIDENTIFIERINFO)) {
		if (arg) {
			findzomb = 1;
		}
	}

	if ((p = proc_find(pid)) == PROC_NULL) {
		if (findzomb) {
			p = proc_find_zombref(pid);
		}
		if (p == PROC_NULL) {
			error = ESRCH;
			goto out;
		}
		zombie = 1;
	} else {
		gotref = 1;
	}

	if ((flags & PIF_COMPARE_IDVERSION) && (ext_id != p->p_idversion)) {
		error = ESRCH;
		goto out;
	}
	if ((flags & PIF_COMPARE_UNIQUEID) && (ext_id != p->p_uniqueid)) {
		error = ESRCH;
		goto out;
	}

	/* Certain operations don't require privileges */
	switch (flavor) {
	case PROC_PIDT_SHORTBSDINFO:
	case PROC_PIDUNIQIDENTIFIERINFO:
	case PROC_PIDPATHINFO:
	case PROC_PIDCOALITIONINFO:
	case PROC_PIDPLATFORMINFO:
		check_same_user = NO_CHECK_SAME_USER;
		break;
	default:
		check_same_user = CHECK_SAME_USER;
		break;
	}

	/* Do we have permission to look into this? */
	if ((error = proc_security_policy(p, PROC_INFO_CALL_PIDINFO, flavor, check_same_user))) {
		goto out;
	}

	switch (flavor) {
	case PROC_PIDLISTFDS: {
		error = proc_pidfdlist(p, buffer, buffersize, retval);
	}
	break;

	case PROC_PIDUNIQIDENTIFIERINFO: {
		struct proc_uniqidentifierinfo p_uniqidinfo;
		bzero(&p_uniqidinfo, sizeof(p_uniqidinfo));
		proc_piduniqidentifierinfo(p, &p_uniqidinfo);
		error = copyout(&p_uniqidinfo, buffer, sizeof(struct proc_uniqidentifierinfo));
		if (error == 0) {
			*retval = sizeof(struct proc_uniqidentifierinfo);
		}
	}
	break;

	case PROC_PIDT_SHORTBSDINFO:
		shortversion = 1;
		OS_FALLTHROUGH;
	case PROC_PIDT_BSDINFOWITHUNIQID:
	case PROC_PIDTBSDINFO: {
		struct proc_bsdinfo pbsd;
		struct proc_bsdshortinfo pbsd_short;
		struct proc_bsdinfowithuniqid pbsd_uniqid;

		if (flavor == PROC_PIDT_BSDINFOWITHUNIQID) {
			uniqidversion = 1;
		}

		if (shortversion != 0) {
			error = proc_pidshortbsdinfo(p, &pbsd_short, zombie);
		} else {
			error = proc_pidbsdinfo(p, &pbsd, zombie);
			if (uniqidversion != 0) {
				bzero(&pbsd_uniqid, sizeof(pbsd_uniqid));
				proc_piduniqidentifierinfo(p, &pbsd_uniqid.p_uniqidentifier);
				pbsd_uniqid.pbsd = pbsd;
			}
		}

		if (error == 0) {
			if (shortversion != 0) {
				error = copyout(&pbsd_short, buffer, sizeof(struct proc_bsdshortinfo));
				if (error == 0) {
					*retval = sizeof(struct proc_bsdshortinfo);
				}
			} else if (uniqidversion != 0) {
				error = copyout(&pbsd_uniqid, buffer, sizeof(struct proc_bsdinfowithuniqid));
				if (error == 0) {
					*retval = sizeof(struct proc_bsdinfowithuniqid);
				}
			} else {
				error = copyout(&pbsd, buffer, sizeof(struct proc_bsdinfo));
				if (error == 0) {
					*retval = sizeof(struct proc_bsdinfo);
				}
			}
		}
	}
	break;

	case PROC_PIDTASKINFO: {
		struct proc_taskinfo ptinfo;

		error =  proc_pidtaskinfo(p, &ptinfo);
		if (error == 0) {
			error = copyout(&ptinfo, buffer, sizeof(struct proc_taskinfo));
			if (error == 0) {
				*retval = sizeof(struct proc_taskinfo);
			}
		}
	}
	break;

	case PROC_PIDTASKALLINFO: {
		struct proc_taskallinfo pall;
		bzero(&pall, sizeof(pall));
		error = proc_pidbsdinfo(p, &pall.pbsd, 0);
		error =  proc_pidtaskinfo(p, &pall.ptinfo);
		if (error == 0) {
			error = copyout(&pall, buffer, sizeof(struct proc_taskallinfo));
			if (error == 0) {
				*retval = sizeof(struct proc_taskallinfo);
			}
		}
	}
	break;

	case PROC_PIDTHREADID64INFO:
		thuniqueid = true;
		OS_FALLTHROUGH;
	case PROC_PIDTHREADINFO:{
		struct proc_threadinfo pthinfo;

		error  = proc_pidthreadinfo(p, arg, thuniqueid, &pthinfo);
		if (error == 0) {
			error = copyout(&pthinfo, buffer, sizeof(struct proc_threadinfo));
			if (error == 0) {
				*retval = sizeof(struct proc_threadinfo);
			}
		}
	}
	break;

	case PROC_PIDLISTTHREADIDS:
		thuniqueid = true;
		OS_FALLTHROUGH;
	case PROC_PIDLISTTHREADS:{
		error =  proc_pidlistthreads(p, thuniqueid, buffer, buffersize, retval);
	}
	break;

	case PROC_PIDREGIONINFO:{
		error =  proc_pidregioninfo(p, arg, buffer, buffersize, retval);
	}
	break;


	case PROC_PIDREGIONPATHINFO:{
		error =  proc_pidregionpathinfo(p, arg, buffer, buffersize, retval);
	}
	break;

	case PROC_PIDREGIONPATHINFO2:{
		error =  proc_pidregionpathinfo2(p, arg, buffer, buffersize, retval);
	}
	break;

	case PROC_PIDREGIONPATHINFO3:{
		error =  proc_pidregionpathinfo3(p, arg, buffer, buffersize, retval);
	}
	break;

	case PROC_PIDVNODEPATHINFO:{
		error =  proc_pidvnodepathinfo(p, arg, buffer, buffersize, retval);
	}
	break;


	case PROC_PIDTHREADPATHINFO:{
		struct proc_threadwithpathinfo pinfo;

		error  = proc_pidthreadpathinfo(p, arg, &pinfo);
		if (error == 0) {
			error = copyout((caddr_t)&pinfo, buffer, sizeof(struct proc_threadwithpathinfo));
			if (error == 0) {
				*retval = sizeof(struct proc_threadwithpathinfo);
			}
		}
	}
	break;

	case PROC_PIDPATHINFO: {
		error =  proc_pidpathinfo(p, arg, buffer, buffersize, retval);
	}
	break;


	case PROC_PIDWORKQUEUEINFO:{
		struct proc_workqueueinfo pwqinfo;

		error  = proc_pidworkqueueinfo(p, &pwqinfo);
		if (error == 0) {
			error = copyout(&pwqinfo, buffer, sizeof(struct proc_workqueueinfo));
			if (error == 0) {
				*retval = sizeof(struct proc_workqueueinfo);
			}
		}
	}
	break;

	case PROC_PIDLISTFILEPORTS: {
		error = proc_pidfileportlist(p, buffer, buffersize, retval);
	}
	break;

	case PROC_PIDARCHINFO: {
		struct proc_archinfo pai;
		bzero(&pai, sizeof(pai));
		proc_archinfo(p, &pai);
		error = copyout(&pai, buffer, sizeof(struct proc_archinfo));
		if (error == 0) {
			*retval = sizeof(struct proc_archinfo);
		}
	}
	break;

	case PROC_PIDCOALITIONINFO: {
		struct proc_pidcoalitioninfo pci;
		proc_pidcoalitioninfo(p, &pci);
		error = copyout(&pci, buffer, sizeof(struct proc_pidcoalitioninfo));
		if (error == 0) {
			*retval = sizeof(struct proc_pidcoalitioninfo);
		}
	}
	break;

	case PROC_PIDNOTEEXIT: {
		uint32_t data;
		error = proc_pidnoteexit(p, arg, &data);
		if (error == 0) {
			error = copyout(&data, buffer, sizeof(data));
			if (error == 0) {
				*retval = sizeof(data);
			}
		}
	}
	break;

	case PROC_PIDEXITREASONINFO: {
		struct proc_exitreasoninfo eri;

		error = copyin(buffer, &eri, sizeof(eri));
		if (error != 0) {
			break;
		}

		error = proc_pidexitreasoninfo(p, &eri, NULL);
		if (error == 0) {
			error = copyout(&eri, buffer, sizeof(eri));
			if (error == 0) {
				*retval =  sizeof(eri);
			}
		}
	}
	break;

	case PROC_PIDEXITREASONBASICINFO: {
		struct proc_exitreasonbasicinfo beri;

		bzero(&beri, sizeof(struct proc_exitreasonbasicinfo));

		error = proc_pidexitreasoninfo(p, NULL, &beri);
		if (error == 0) {
			error = copyout(&beri, buffer, sizeof(beri));
			if (error == 0) {
				*retval =  sizeof(beri);
			}
		}
	}
	break;

	case PROC_PIDLISTUPTRS:
		error = proc_pidlistuptrs(p, buffer, buffersize, retval);
		break;

	case PROC_PIDLISTDYNKQUEUES:
		error = kevent_copyout_proc_dynkqids(p, buffer, buffersize, retval);
		break;
	case PROC_PIDVMRTFAULTINFO: {
		/* This interface can only be employed on the current
		 * process. We will eventually enforce an entitlement.
		 */
		*retval = 0;

		if (p != current_proc()) {
			error = EINVAL;
			break;
		}

		size_t kbufsz = MIN(buffersize, vmrtfaultinfo_bufsz());
		void *vmrtfbuf = kheap_alloc(KHEAP_TEMP, kbufsz, Z_WAITOK | Z_ZERO);

		if (vmrtfbuf == NULL) {
			error = ENOMEM;
			break;
		}

		uint64_t effpid = get_current_unique_pid();
		/* The VM may choose to provide more comprehensive records
		 * for root-privileged users on internal configurations.
		 */
		boolean_t isroot = (suser(kauth_cred_get(), (u_short *)0) == 0);
		size_t num_extracted = 0;
		int vmf_residue = vmrtf_extract(effpid, isroot, kbufsz, vmrtfbuf, &num_extracted);
		size_t vmfsz = num_extracted * sizeof(vm_rtfault_record_t);

		*retval = (int32_t)MIN(num_extracted, INT32_MAX);

		error = 0;
		if (vmfsz) {
			error = copyout(vmrtfbuf, buffer, vmfsz);
		}

		if (error == 0) {
			if (vmf_residue) {
				error = ENOMEM;
			}
		}
		kheap_free(KHEAP_TEMP, vmrtfbuf, kbufsz);
	}
	break;
	case PROC_PIDPLATFORMINFO: {
		proc_lock(p);
		uint32_t platform = p->p_platform;
		proc_unlock(p);
		error = copyout(&platform, buffer, sizeof(uint32_t));
		if (error == 0) {
			*retval = sizeof(uint32_t);
		}
	} break;
	case PROC_PIDREGIONPATH: {
		error = proc_pidregionpath(p, arg, buffer, buffersize, retval);
	}
	break;
	case PROC_PIDIPCTABLEINFO: {
		struct proc_ipctableinfo table_info;

		error = proc_pidipctableinfo(p, &table_info);
		if (error == 0) {
			error = copyout(&table_info, buffer, sizeof(struct proc_ipctableinfo));
			if (error == 0) {
				*retval = sizeof(struct proc_ipctableinfo);
			}
		}
	}
	break;
	default:
		error = ENOTSUP;
		break;
	}

out:
	if (gotref) {
		proc_rele(p);
	} else if (zombie) {
		proc_drop_zombref(p);
	}
	return error;
}


int
pid_vnodeinfo(vnode_t vp, struct fileproc * fp, proc_t proc, int fd, user_addr_t  buffer, __unused uint32_t buffersize, int32_t * retval)
{
	struct vnode_fdinfo vfi;
	uint32_t vid = vnode_vid(vp);
	int error = 0;

	if ((error = vnode_getwithvid(vp, vid)) != 0) {
		return error;
	}
	bzero(&vfi, sizeof(struct vnode_fdinfo));
	fill_fileinfo(fp, proc, fd, &vfi.pfi);
	error = fill_vnodeinfo(vp, &vfi.pvi, FALSE);
	vnode_put(vp);
	if (error == 0) {
		error = copyout((caddr_t)&vfi, buffer, sizeof(struct vnode_fdinfo));
		if (error == 0) {
			*retval = sizeof(struct vnode_fdinfo);
		}
	}
	return error;
}

int
pid_vnodeinfopath(vnode_t vp, struct fileproc * fp, proc_t proc, int fd, user_addr_t  buffer, __unused uint32_t buffersize, int32_t * retval)
{
	struct vnode_fdinfowithpath vfip;
	uint32_t vid = vnode_vid(vp);
	int count, error = 0;

	if ((error = vnode_getwithvid(vp, vid)) != 0) {
		return error;
	}
	bzero(&vfip, sizeof(struct vnode_fdinfowithpath));
	fill_fileinfo(fp, proc, fd, &vfip.pfi);
	error = fill_vnodeinfo(vp, &vfip.pvip.vip_vi, TRUE);
	if (error == 0) {
		count = MAXPATHLEN;
		vn_getpath(vp, &vfip.pvip.vip_path[0], &count);
		vfip.pvip.vip_path[MAXPATHLEN - 1] = 0;
		vnode_put(vp);
		error = copyout((caddr_t)&vfip, buffer, sizeof(struct vnode_fdinfowithpath));
		if (error == 0) {
			*retval = sizeof(struct vnode_fdinfowithpath);
		}
	} else {
		vnode_put(vp);
	}
	return error;
}

void
fill_fileinfo(struct fileproc * fp, proc_t proc, int fd, struct proc_fileinfo * fproc)
{
	fproc->fi_openflags = fp->fp_glob->fg_flag;
	fproc->fi_status = 0;
	fproc->fi_offset = fp->fp_glob->fg_offset;
	fproc->fi_type = FILEGLOB_DTYPE(fp->fp_glob);
	if (os_ref_get_count_raw(&fp->fp_glob->fg_count) > 1) {
		fproc->fi_status |= PROC_FP_SHARED;
	}
	if (proc != PROC_NULL) {
		if ((FDFLAGS_GET(proc, fd) & UF_EXCLOSE) != 0) {
			fproc->fi_status |= PROC_FP_CLEXEC;
		}
		if ((FDFLAGS_GET(proc, fd) & UF_FORKCLOSE) != 0) {
			fproc->fi_status |= PROC_FP_CLFORK;
		}
	}
	if (FILEPROC_TYPE(fp) == FTYPE_GUARDED) {
		fproc->fi_status |= PROC_FP_GUARDED;
		fproc->fi_guardflags = 0;
		if (fp_isguarded(fp, GUARD_CLOSE)) {
			fproc->fi_guardflags |= PROC_FI_GUARD_CLOSE;
		}
		if (fp_isguarded(fp, GUARD_DUP)) {
			fproc->fi_guardflags |= PROC_FI_GUARD_DUP;
		}
		if (fp_isguarded(fp, GUARD_SOCKET_IPC)) {
			fproc->fi_guardflags |= PROC_FI_GUARD_SOCKET_IPC;
		}
		if (fp_isguarded(fp, GUARD_FILEPORT)) {
			fproc->fi_guardflags |= PROC_FI_GUARD_FILEPORT;
		}
	}
}



int
fill_vnodeinfo(vnode_t vp, struct vnode_info *vinfo, __unused boolean_t check_fsgetpath)
{
	vfs_context_t context;
	struct stat64 sb;
	int error = 0;

	bzero(&sb, sizeof(struct stat64));
	context = vfs_context_create((vfs_context_t)0);
#if CONFIG_MACF
	/* Called when vnode info is used by the caller to get vnode's path */
	if (check_fsgetpath) {
		error = mac_vnode_check_fsgetpath(context, vp);
	}
#endif
	if (!error) {
		error = vn_stat(vp, &sb, NULL, 1, 0, context);
		munge_vinfo_stat(&sb, &vinfo->vi_stat);
	}
	(void)vfs_context_rele(context);
	if (error != 0) {
		goto out;
	}

	if (vp->v_mount != dead_mountp) {
		vinfo->vi_fsid = vp->v_mount->mnt_vfsstat.f_fsid;
	} else {
		vinfo->vi_fsid.val[0] = 0;
		vinfo->vi_fsid.val[1] = 0;
	}
	vinfo->vi_type = vp->v_type;
out:
	return error;
}

int
pid_socketinfo(socket_t so, struct fileproc *fp, proc_t proc, int fd, user_addr_t  buffer, __unused uint32_t buffersize, int32_t * retval)
{
#if SOCKETS
	struct socket_fdinfo s;
	int error = 0;

	bzero(&s, sizeof(struct socket_fdinfo));
	fill_fileinfo(fp, proc, fd, &s.pfi);
	if ((error = fill_socketinfo(so, &s.psi)) == 0) {
		if ((error = copyout(&s, buffer, sizeof(struct socket_fdinfo))) == 0) {
			*retval = sizeof(struct socket_fdinfo);
		}
	}
	return error;
#else
#pragma unused(so, fp, proc, fd, buffer)
	*retval = 0;
	return ENOTSUP;
#endif
}

int
pid_pseminfo(struct psemnode *psem, struct fileproc *fp, proc_t proc, int fd, user_addr_t  buffer, __unused uint32_t buffersize, int32_t * retval)
{
	struct psem_fdinfo pseminfo;
	int error = 0;

	bzero(&pseminfo, sizeof(struct psem_fdinfo));
	fill_fileinfo(fp, proc, fd, &pseminfo.pfi);

	if ((error = fill_pseminfo(psem, &pseminfo.pseminfo)) == 0) {
		if ((error = copyout(&pseminfo, buffer, sizeof(struct psem_fdinfo))) == 0) {
			*retval = sizeof(struct psem_fdinfo);
		}
	}

	return error;
}

int
pid_pshminfo(struct pshmnode *pshm, struct fileproc *fp, proc_t proc, int fd, user_addr_t  buffer, __unused uint32_t buffersize, int32_t * retval)
{
	struct pshm_fdinfo pshminfo;
	int error = 0;

	bzero(&pshminfo, sizeof(struct pshm_fdinfo));
	fill_fileinfo(fp, proc, fd, &pshminfo.pfi);

	if ((error = fill_pshminfo(pshm, &pshminfo.pshminfo)) == 0) {
		if ((error = copyout(&pshminfo, buffer, sizeof(struct pshm_fdinfo))) == 0) {
			*retval = sizeof(struct pshm_fdinfo);
		}
	}

	return error;
}

int
pid_pipeinfo(struct pipe *  p, struct fileproc *fp, proc_t proc, int fd, user_addr_t  buffer, __unused uint32_t buffersize, int32_t * retval)
{
	struct pipe_fdinfo pipeinfo;
	int error = 0;

	bzero(&pipeinfo, sizeof(struct pipe_fdinfo));
	fill_fileinfo(fp, proc, fd, &pipeinfo.pfi);
	if ((error = fill_pipeinfo(p, &pipeinfo.pipeinfo)) == 0) {
		if ((error = copyout(&pipeinfo, buffer, sizeof(struct pipe_fdinfo))) == 0) {
			*retval = sizeof(struct pipe_fdinfo);
		}
	}

	return error;
}

int
pid_kqueueinfo(struct kqueue * kq, struct fileproc *fp, proc_t proc, int fd, user_addr_t  buffer, __unused uint32_t buffersize, int32_t * retval)
{
	struct kqueue_fdinfo kqinfo;
	int error = 0;

	bzero(&kqinfo, sizeof(struct kqueue_fdinfo));

	/* not all kq's are associated with a file (e.g. workqkq) */
	if (fp) {
		assert(fd >= 0);
		fill_fileinfo(fp, proc, fd, &kqinfo.pfi);
	}

	if ((error = fill_kqueueinfo(kq, &kqinfo.kqueueinfo)) == 0) {
		if ((error = copyout(&kqinfo, buffer, sizeof(struct kqueue_fdinfo))) == 0) {
			*retval = sizeof(struct kqueue_fdinfo);
		}
	}

	return error;
}


/************************** proc_pidfdinfo routine ***************************/
int
proc_pidfdinfo(int pid, int flavor, int fd, user_addr_t buffer, uint32_t buffersize, int32_t * retval)
{
	proc_t p;
	int error = ENOTSUP;
	struct fileproc *fp = NULL;
	uint32_t size;

	switch (flavor) {
	case PROC_PIDFDVNODEINFO:
		size = PROC_PIDFDVNODEINFO_SIZE;
		break;
	case PROC_PIDFDVNODEPATHINFO:
		size = PROC_PIDFDVNODEPATHINFO_SIZE;
		break;
	case PROC_PIDFDSOCKETINFO:
		size = PROC_PIDFDSOCKETINFO_SIZE;
		break;
	case PROC_PIDFDPSEMINFO:
		size = PROC_PIDFDPSEMINFO_SIZE;
		break;
	case PROC_PIDFDPSHMINFO:
		size = PROC_PIDFDPSHMINFO_SIZE;
		break;
	case PROC_PIDFDPIPEINFO:
		size = PROC_PIDFDPIPEINFO_SIZE;
		break;
	case PROC_PIDFDKQUEUEINFO:
		size = PROC_PIDFDKQUEUEINFO_SIZE;
		break;
	case PROC_PIDFDKQUEUE_EXTINFO:
		size = PROC_PIDFDKQUEUE_EXTINFO_SIZE;
		if (buffer == (user_addr_t)0) {
			size = 0;
		}
		break;
	case PROC_PIDFDATALKINFO:
		size = PROC_PIDFDATALKINFO_SIZE;
		break;

	default:
		return EINVAL;
	}

	if (buffersize < size) {
		return ENOMEM;
	}

	if ((p = proc_find(pid)) == PROC_NULL) {
		error = ESRCH;
		goto out;
	}

	/* Do we have permission to look into this? */
	if ((error = proc_security_policy(p, PROC_INFO_CALL_PIDFDINFO, flavor, CHECK_SAME_USER))) {
		goto out1;
	}

	switch (flavor) {
	case PROC_PIDFDVNODEINFO: {
		if ((error = fp_get_ftype(p, fd, DTYPE_VNODE, EBADF, &fp)) != 0) {
			goto out1;
		}
		error = pid_vnodeinfo(fp->fp_glob->fg_data, fp, p, fd, buffer, buffersize, retval);
	}
	break;

	case PROC_PIDFDVNODEPATHINFO: {
		if ((error = fp_get_ftype(p, fd, DTYPE_VNODE, EBADF, &fp)) != 0) {
			goto out1;
		}
		error = pid_vnodeinfopath(fp->fp_glob->fg_data, fp, p, fd, buffer, buffersize, retval);
	}
	break;

	case PROC_PIDFDSOCKETINFO: {
		if ((error = fp_get_ftype(p, fd, DTYPE_SOCKET, ENOTSOCK, &fp)) != 0) {
			goto out1;
		}
		error = pid_socketinfo(fp->fp_glob->fg_data, fp, p, fd, buffer, buffersize, retval);
	}
	break;

	case PROC_PIDFDPSEMINFO: {
		if ((error = fp_get_ftype(p, fd, DTYPE_PSXSEM, EBADF, &fp)) != 0) {
			goto out1;
		}
		error = pid_pseminfo(fp->fp_glob->fg_data, fp, p, fd, buffer, buffersize, retval);
	}
	break;

	case PROC_PIDFDPSHMINFO: {
		if ((error = fp_get_ftype(p, fd, DTYPE_PSXSHM, EBADF, &fp)) != 0) {
			goto out1;
		}
		error = pid_pshminfo(fp->fp_glob->fg_data, fp, p, fd, buffer, buffersize, retval);
	}
	break;

	case PROC_PIDFDPIPEINFO: {
		if ((error = fp_get_ftype(p, fd, DTYPE_PIPE, EBADF, &fp)) != 0) {
			goto out1;
		}
		error = pid_pipeinfo(fp->fp_glob->fg_data, fp, p, fd, buffer, buffersize, retval);
	}
	break;

	case PROC_PIDFDKQUEUEINFO: {
		kqueue_t kqu;

		if (fd == -1) {
			if ((kqu.kqwq = p->p_fd->fd_wqkqueue) == NULL) {
				/* wqkqueue is initialized on-demand */
				error = 0;
				break;
			}
		} else if ((error = fp_get_ftype(p, fd, DTYPE_KQUEUE, EBADF, &fp)) != 0) {
			goto out1;
		} else {
			kqu.kq = fp->fp_glob->fg_data;
		}

		error = pid_kqueueinfo(kqu.kq, fp, p, fd, buffer, buffersize, retval);
	}
	break;

	case PROC_PIDFDKQUEUE_EXTINFO: {
		kqueue_t kqu;

		if (fd == -1) {
			if ((kqu.kqwq = p->p_fd->fd_wqkqueue) == NULL) {
				/* wqkqueue is initialized on-demand */
				error = 0;
				break;
			}
		} else if ((error = fp_get_ftype(p, fd, DTYPE_KQUEUE, EBADF, &fp)) != 0) {
			goto out1;
		} else {
			kqu.kq = fp->fp_glob->fg_data;
		}
		error = pid_kqueue_extinfo(p, kqu.kq, buffer, buffersize, retval);
	}
	break;

	default: {
		error = EINVAL;
		goto out1;
	}
	}

	if (fp) {
		fp_drop(p, fd, fp, 0);
	}
out1:
	proc_rele(p);
out:
	return error;
}

#define MAX_UPTRS 16392

int
proc_pidlistuptrs(proc_t p, user_addr_t buffer, uint32_t buffersize, int32_t *retval)
{
	uint32_t count = 0;
	int error = 0;
	void *kbuf = NULL;
	int32_t nuptrs = 0;

	if (buffer == USER_ADDR_NULL || buffersize < sizeof(uint64_t)) {
		buffersize = 0;
	} else {
		count = MIN(buffersize / sizeof(uint64_t), MAX_UPTRS);
		buffersize = count * sizeof(uint64_t);
		kbuf = kheap_alloc(KHEAP_TEMP, buffersize, Z_WAITOK);
	}

	nuptrs = kevent_proc_copy_uptrs(p, kbuf, buffersize);

	if (kbuf) {
		size_t copysize;
		if (os_mul_overflow(nuptrs, sizeof(uint64_t), &copysize)) {
			error = ERANGE;
			goto out;
		}
		if (copysize > buffersize) {
			copysize = buffersize;
		}
		error = copyout(kbuf, buffer, copysize);
	}

out:
	*retval = nuptrs;

	if (kbuf) {
		kheap_free(KHEAP_TEMP, kbuf, buffersize);
		kbuf = NULL;
	}

	return error;
}

/*
 * Helper function for proc_pidfileportinfo
 */

struct fileport_info_args {
	int             fia_flavor;
	user_addr_t     fia_buffer;
	uint32_t        fia_buffersize;
	int32_t         *fia_retval;
};

static kern_return_t
proc_fileport_info(__unused mach_port_name_t name,
    struct fileglob *fg, void *arg)
{
	struct fileport_info_args *fia = arg;
	struct fileproc __fileproc, *fp = &__fileproc;
	int error;

	bzero(fp, sizeof(*fp));
	fp->fp_glob = fg;

	switch (fia->fia_flavor) {
	case PROC_PIDFILEPORTVNODEPATHINFO: {
		vnode_t vp;

		if (FILEGLOB_DTYPE(fg) != DTYPE_VNODE) {
			error = ENOTSUP;
			break;
		}
		vp = (struct vnode *)fg->fg_data;
		error = pid_vnodeinfopath(vp, fp, PROC_NULL, 0,
		    fia->fia_buffer, fia->fia_buffersize, fia->fia_retval);
	}       break;

	case PROC_PIDFILEPORTSOCKETINFO: {
		socket_t so;

		if (FILEGLOB_DTYPE(fg) != DTYPE_SOCKET) {
			error = EOPNOTSUPP;
			break;
		}
		so = (socket_t)fg->fg_data;
		error = pid_socketinfo(so, fp, PROC_NULL, 0,
		    fia->fia_buffer, fia->fia_buffersize, fia->fia_retval);
	}       break;

	case PROC_PIDFILEPORTPSHMINFO: {
		struct pshmnode *pshm;

		if (FILEGLOB_DTYPE(fg) != DTYPE_PSXSHM) {
			error = EBADF;          /* ick - mirror fp_getfpshm */
			break;
		}
		pshm = (struct pshmnode *)fg->fg_data;
		error = pid_pshminfo(pshm, fp, PROC_NULL, 0,
		    fia->fia_buffer, fia->fia_buffersize, fia->fia_retval);
	}       break;

	case PROC_PIDFILEPORTPIPEINFO: {
		struct pipe *cpipe;

		if (FILEGLOB_DTYPE(fg) != DTYPE_PIPE) {
			error = EBADF;          /* ick - mirror fp_getfpipe */
			break;
		}
		cpipe = (struct pipe *)fg->fg_data;
		error = pid_pipeinfo(cpipe, fp, PROC_NULL, 0,
		    fia->fia_buffer, fia->fia_buffersize, fia->fia_retval);
	}       break;

	default:
		error = EINVAL;
		break;
	}

	return error;
}

/************************* proc_pidfileportinfo routine *********************/
int
proc_pidfileportinfo(int pid, int flavor, mach_port_name_t name,
    user_addr_t buffer, uint32_t buffersize, int32_t *retval)
{
	proc_t p;
	int error = ENOTSUP;
	uint32_t size;
	struct fileport_info_args fia;

	/* fileport types are restricted by file_issendable() */

	switch (flavor) {
	case PROC_PIDFILEPORTVNODEPATHINFO:
		size = PROC_PIDFILEPORTVNODEPATHINFO_SIZE;
		break;
	case PROC_PIDFILEPORTSOCKETINFO:
		size = PROC_PIDFILEPORTSOCKETINFO_SIZE;
		break;
	case PROC_PIDFILEPORTPSHMINFO:
		size = PROC_PIDFILEPORTPSHMINFO_SIZE;
		break;
	case PROC_PIDFILEPORTPIPEINFO:
		size = PROC_PIDFILEPORTPIPEINFO_SIZE;
		break;
	default:
		return EINVAL;
	}

	if (buffersize < size) {
		return ENOMEM;
	}
	if ((p = proc_find(pid)) == PROC_NULL) {
		error = ESRCH;
		goto out;
	}

	/* Do we have permission to look into this? */
	if ((error = proc_security_policy(p, PROC_INFO_CALL_PIDFILEPORTINFO, flavor, CHECK_SAME_USER))) {
		goto out1;
	}

	fia.fia_flavor = flavor;
	fia.fia_buffer = buffer;
	fia.fia_buffersize = buffersize;
	fia.fia_retval = retval;

	if (fileport_invoke(p->task, name,
	    proc_fileport_info, &fia, &error) != KERN_SUCCESS) {
		error = EINVAL;
	}
out1:
	proc_rele(p);
out:
	return error;
}

int
proc_security_policy(proc_t targetp, __unused int callnum, __unused int flavor, boolean_t check_same_user)
{
#if CONFIG_MACF
	int error = 0;

	if ((error = mac_proc_check_proc_info(current_proc(), targetp, callnum, flavor))) {
		return error;
	}
#endif

	/* The 'listpids' call doesn't have a target proc */
	if (targetp == PROC_NULL) {
		assert(callnum == PROC_INFO_CALL_LISTPIDS && check_same_user == NO_CHECK_SAME_USER);
		return 0;
	}

	/*
	 * Check for 'get information for processes owned by other users' privilege
	 * root has this privilege by default
	 */
	if (priv_check_cred(kauth_cred_get(), PRIV_GLOBAL_PROC_INFO, 0) == 0) {
		check_same_user = FALSE;
	}

	if (check_same_user) {
		kauth_cred_t target_cred;
		uid_t        target_uid;

		target_cred = kauth_cred_proc_ref(targetp);
		target_uid  = kauth_cred_getuid(target_cred);
		kauth_cred_unref(&target_cred);

		if (kauth_getuid() != target_uid) {
			return EPERM;
		}
	}

	return 0;
}

int
proc_kernmsgbuf(user_addr_t buffer, uint32_t buffersize, int32_t * retval)
{
#if CONFIG_MACF
	int error = 0;

	if ((error = mac_system_check_info(kauth_cred_get(), "kern.msgbuf"))) {
		return error;
	}
#endif

	if (suser(kauth_cred_get(), (u_short *)0) == 0) {
		return log_dmesg(buffer, buffersize, retval);
	} else {
		return EPERM;
	}
}

/* ********* process control sets on self only */
int
proc_setcontrol(int pid, int flavor, uint64_t arg, user_addr_t buffer, uint32_t buffersize, __unused int32_t * retval)
{
	struct proc * pself = PROC_NULL;
	int error = 0;
	uint32_t pcontrol = (uint32_t)arg;
	struct uthread *ut = NULL;
	char name_buf[MAXTHREADNAMESIZE];

	pself = current_proc();
	if (pid != pself->p_pid) {
		return EINVAL;
	}

	/* Do we have permission to look into this? */
	if ((error = proc_security_policy(pself, PROC_INFO_CALL_SETCONTROL, flavor, NO_CHECK_SAME_USER))) {
		goto out;
	}

	switch (flavor) {
	case PROC_SELFSET_PCONTROL: {
		if (pcontrol > P_PCMAX) {
			return EINVAL;
		}
		proc_lock(pself);
		/* reset existing control setting while retaining action state */
		pself->p_pcaction &= PROC_ACTION_MASK;
		/* set new control state */
		pself->p_pcaction |= pcontrol;
		proc_unlock(pself);
	}
	break;

	case PROC_SELFSET_THREADNAME: {
		/*
		 * This is a bit ugly, as it copies the name into the kernel, and then
		 * invokes bsd_setthreadname again to copy it into the uthread name
		 * buffer.  Hopefully this isn't such a hot codepath that an additional
		 * MAXTHREADNAMESIZE copy is a big issue.
		 */
		if (buffersize > (MAXTHREADNAMESIZE - 1)) {
			return ENAMETOOLONG;
		}

		ut = current_uthread();

		bzero(name_buf, MAXTHREADNAMESIZE);
		error = copyin(buffer, name_buf, buffersize);

		if (!error) {
			bsd_setthreadname(ut, name_buf);
		}
	}
	break;

	case PROC_SELFSET_VMRSRCOWNER: {
		/* need to to be superuser */
		if (suser(kauth_cred_get(), (u_short *)0) != 0) {
			error = EPERM;
			goto out;
		}

		proc_lock(pself);
		/* reset existing control setting while retaining action state */
		pself->p_lflag |= P_LVMRSRCOWNER;
		proc_unlock(pself);
	}
	break;

	case PROC_SELFSET_DELAYIDLESLEEP: {
#if CONFIG_DELAY_IDLE_SLEEP
		/* mark or clear the process property to delay idle sleep disk IO */
		if (pcontrol != 0) {
			OSBitOrAtomic(P_DELAYIDLESLEEP, &pself->p_flag);
		} else {
			OSBitAndAtomic(~((uint32_t)P_DELAYIDLESLEEP), &pself->p_flag);
		}
	}
	break;
#else
		error = ENOTSUP;
		goto out;
	}
#endif

	default:
		error = ENOTSUP;
	}

out:
	return error;
}

#if CONFIG_MEMORYSTATUS

int
proc_dirtycontrol(int pid, int flavor, uint64_t arg, int32_t *retval)
{
	struct proc *target_p;
	int error = 0;
	uint32_t pcontrol = (uint32_t)arg;
	kauth_cred_t my_cred, target_cred;
	boolean_t self = FALSE;
	boolean_t child = FALSE;
	boolean_t zombref = FALSE;
	pid_t selfpid;

	target_p = proc_find(pid);

	if (target_p == PROC_NULL) {
		if (flavor == PROC_DIRTYCONTROL_GET) {
			target_p = proc_find_zombref(pid);
			zombref = 1;
		}

		if (target_p == PROC_NULL) {
			return ESRCH;
		}
	}

	my_cred = kauth_cred_get();
	target_cred = kauth_cred_proc_ref(target_p);

	/* Do we have permission to look into this? */
	if ((error = proc_security_policy(target_p, PROC_INFO_CALL_DIRTYCONTROL, flavor, NO_CHECK_SAME_USER))) {
		goto out;
	}

	selfpid = proc_selfpid();
	if (pid == selfpid) {
		self = TRUE;
	} else if (target_p->p_ppid == selfpid) {
		child = TRUE;
	}

	switch (flavor) {
	case PROC_DIRTYCONTROL_TRACK: {
		/* Only allow the process itself, its parent, or root */
		if ((self == FALSE) && (child == FALSE) && kauth_cred_issuser(kauth_cred_get()) != TRUE) {
			error = EPERM;
			goto out;
		}

		error = memorystatus_dirty_track(target_p, pcontrol);
	}
	break;

	case PROC_DIRTYCONTROL_SET: {
		/* Check privileges; use cansignal() here since the process could be terminated */
		if (!cansignal(current_proc(), my_cred, target_p, SIGKILL)) {
			error = EPERM;
			goto out;
		}

		error = memorystatus_dirty_set(target_p, self, pcontrol);
	}
	break;

	case PROC_DIRTYCONTROL_GET: {
		/* No permissions check - dirty state is freely available */
		if (retval) {
			*retval = memorystatus_dirty_get(target_p, FALSE);
		} else {
			error = EINVAL;
		}
	}
	break;

	case PROC_DIRTYCONTROL_CLEAR: {
		/* Check privileges; use cansignal() here since the process could be terminated */
		if (!cansignal(current_proc(), my_cred, target_p, SIGKILL)) {
			error = EPERM;
			goto out;
		}

		error = memorystatus_dirty_clear(target_p, pcontrol);
	}
	break;
	}

out:
	if (zombref) {
		proc_drop_zombref(target_p);
	} else {
		proc_rele(target_p);
	}

	kauth_cred_unref(&target_cred);

	return error;
}
#else

int
proc_dirtycontrol(__unused int pid, __unused int flavor, __unused uint64_t arg, __unused int32_t *retval)
{
	return ENOTSUP;
}

#endif /* CONFIG_MEMORYSTATUS */

/*
 * proc_terminate() provides support for sudden termination.
 * SIGKILL is issued to tracked, clean processes; otherwise,
 * SIGTERM is sent.
 */

int
proc_terminate(int pid, int32_t *retval)
{
	int error = 0;
	proc_t p;
	kauth_cred_t uc = kauth_cred_get();
	int sig;

#if 0
	/* XXX: Check if these are necessary */
	AUDIT_ARG(pid, pid);
	AUDIT_ARG(signum, sig);
#endif

	if (pid <= 0 || retval == NULL) {
		return EINVAL;
	}

	if ((p = proc_find(pid)) == NULL) {
		return ESRCH;
	}

#if 0
	/* XXX: Check if these are necessary */
	AUDIT_ARG(process, p);
#endif

	/* Check privileges; if SIGKILL can be issued, then SIGTERM is also OK */
	if (!cansignal(current_proc(), uc, p, SIGKILL)) {
		error = EPERM;
		goto out;
	}

	/* Not allowed to sudden terminate yourself */
	if (p == current_proc()) {
		error = EPERM;
		goto out;
	}

#if CONFIG_MEMORYSTATUS
	/* Determine requisite signal to issue */
	sig = memorystatus_on_terminate(p);
#else
	sig = SIGTERM;
#endif

	proc_set_task_policy(p->task, TASK_POLICY_ATTRIBUTE,
	    TASK_POLICY_TERMINATED, TASK_POLICY_ENABLE);

	psignal(p, sig);
	*retval = sig;

out:
	proc_rele(p);

	return error;
}

/*
 * copy stat64 structure into vinfo_stat structure.
 */
static void
munge_vinfo_stat(struct stat64 *sbp, struct vinfo_stat *vsbp)
{
	bzero(vsbp, sizeof(struct vinfo_stat));

	vsbp->vst_dev = sbp->st_dev;
	vsbp->vst_mode = sbp->st_mode;
	vsbp->vst_nlink = sbp->st_nlink;
	vsbp->vst_ino = sbp->st_ino;
	vsbp->vst_uid = sbp->st_uid;
	vsbp->vst_gid = sbp->st_gid;
	vsbp->vst_atime = sbp->st_atimespec.tv_sec;
	vsbp->vst_atimensec = sbp->st_atimespec.tv_nsec;
	vsbp->vst_mtime = sbp->st_mtimespec.tv_sec;
	vsbp->vst_mtimensec = sbp->st_mtimespec.tv_nsec;
	vsbp->vst_ctime = sbp->st_ctimespec.tv_sec;
	vsbp->vst_ctimensec = sbp->st_ctimespec.tv_nsec;
	vsbp->vst_birthtime = sbp->st_birthtimespec.tv_sec;
	vsbp->vst_birthtimensec = sbp->st_birthtimespec.tv_nsec;
	vsbp->vst_size = sbp->st_size;
	vsbp->vst_blocks = sbp->st_blocks;
	vsbp->vst_blksize = sbp->st_blksize;
	vsbp->vst_flags = sbp->st_flags;
	vsbp->vst_gen = sbp->st_gen;
	vsbp->vst_rdev = sbp->st_rdev;
	vsbp->vst_qspare[0] = sbp->st_qspare[0];
	vsbp->vst_qspare[1] = sbp->st_qspare[1];
}

int
proc_pid_rusage(int pid, int flavor, user_addr_t buffer, __unused int32_t *retval)
{
	proc_t          p;
	int             error;
	int             zombie = 0;

	if ((p = proc_find(pid)) == PROC_NULL) {
		if ((p = proc_find_zombref(pid)) == PROC_NULL) {
			return ESRCH;
		}
		zombie = 1;
	}

	/* Do we have permission to look into this? */
	if ((error = proc_security_policy(p, PROC_INFO_CALL_PIDRUSAGE, flavor, CHECK_SAME_USER))) {
		goto out;
	}

	error = proc_get_rusage(p, flavor, buffer, zombie);

out:
	if (zombie) {
		proc_drop_zombref(p);
	} else {
		proc_rele(p);
	}

	return error;
}

void
proc_archinfo(proc_t p, struct proc_archinfo *pai)
{
	proc_lock(p);
	{
		pai->p_cputype = p->p_cputype;
		pai->p_cpusubtype = p->p_cpusubtype;
	}
	proc_unlock(p);
}

void
proc_pidcoalitioninfo(proc_t p, struct proc_pidcoalitioninfo *ppci)
{
	bzero(ppci, sizeof(*ppci));
	proc_coalitionids(p, ppci->coalition_id);
}

int
proc_pidexitreasoninfo(proc_t p, struct proc_exitreasoninfo *peri, struct proc_exitreasonbasicinfo *pberi)
{
	uint32_t reason_data_size = 0;
	int error = 0;
	pid_t selfpid = proc_selfpid();

	proc_lock(p);

	/*
	 * One (and only one) of peri and pberi must be non-NULL.
	 */
	assert((peri != NULL) || (pberi != NULL));
	assert((peri == NULL) || (pberi == NULL));

	/*
	 * Allow access to the parent of the exiting
	 * child or the parent debugger only.
	 */
	do {
		if (p->p_ppid == selfpid) {
			break;  /* parent => ok */
		}
		if ((p->p_lflag & P_LTRACED) != 0 &&
		    (p->p_oppid == selfpid)) {
			break;  /* parent-in-waiting => ok */
		}
		proc_unlock(p);
		return EACCES;
	} while (0);

	if (p->p_exit_reason == OS_REASON_NULL) {
		proc_unlock(p);
		return ENOENT;
	}

	if (p->p_exit_reason->osr_kcd_buf != NULL) {
		reason_data_size = (uint32_t)kcdata_memory_get_used_bytes(&p->p_exit_reason->osr_kcd_descriptor);
	}

	if (peri != NULL) {
		peri->eri_namespace = p->p_exit_reason->osr_namespace;
		peri->eri_code = p->p_exit_reason->osr_code;
		peri->eri_flags = p->p_exit_reason->osr_flags;

		if ((peri->eri_kcd_buf == 0) || (peri->eri_reason_buf_size < reason_data_size)) {
			proc_unlock(p);
			return ENOMEM;
		}

		peri->eri_reason_buf_size = reason_data_size;
		if (reason_data_size != 0) {
			error = copyout(p->p_exit_reason->osr_kcd_buf, (user_addr_t)peri->eri_kcd_buf, reason_data_size);
		}
	} else {
		pberi->beri_namespace =  p->p_exit_reason->osr_namespace;
		pberi->beri_code = p->p_exit_reason->osr_code;
		pberi->beri_flags = p->p_exit_reason->osr_flags;
		pberi->beri_reason_buf_size = reason_data_size;
	}

	proc_unlock(p);

	return error;
}

/*
 * Wrapper to provide NOTE_EXIT_DETAIL and NOTE_EXITSTATUS
 * It mimics the data that is typically captured by the
 * EVFILT_PROC, NOTE_EXIT event mechanism.
 * See filt_proc() in kern_event.c.
 */
int
proc_pidnoteexit(proc_t p, uint64_t flags, uint32_t *data)
{
	uint32_t exit_data = 0;
	uint32_t exit_flags = (uint32_t)flags;

	proc_lock(p);

	/*
	 * Allow access to the parent of the exiting
	 * child or the parent debugger only.
	 */
	do {
		pid_t selfpid = proc_selfpid();

		if (p->p_ppid == selfpid) {
			break;  /* parent => ok */
		}
		if ((p->p_lflag & P_LTRACED) != 0 &&
		    (p->p_oppid == selfpid)) {
			break;  /* parent-in-waiting => ok */
		}
		proc_unlock(p);
		return EACCES;
	} while (0);

	if ((exit_flags & NOTE_EXITSTATUS) != 0) {
		/* The signal and exit status */
		exit_data |= (p->p_xstat & NOTE_PDATAMASK);
	}

	if ((exit_flags & NOTE_EXIT_DETAIL) != 0) {
		/* The exit detail */
		if ((p->p_lflag & P_LTERM_DECRYPTFAIL) != 0) {
			exit_data |= NOTE_EXIT_DECRYPTFAIL;
		}

		if ((p->p_lflag & P_LTERM_JETSAM) != 0) {
			exit_data |= NOTE_EXIT_MEMORY;

			switch (p->p_lflag & P_JETSAM_MASK) {
			case P_JETSAM_VMPAGESHORTAGE:
				exit_data |= NOTE_EXIT_MEMORY_VMPAGESHORTAGE;
				break;
			case P_JETSAM_VMTHRASHING:
				exit_data |= NOTE_EXIT_MEMORY_VMTHRASHING;
				break;
			case P_JETSAM_FCTHRASHING:
				exit_data |= NOTE_EXIT_MEMORY_FCTHRASHING;
				break;
			case P_JETSAM_VNODE:
				exit_data |= NOTE_EXIT_MEMORY_VNODE;
				break;
			case P_JETSAM_HIWAT:
				exit_data |= NOTE_EXIT_MEMORY_HIWAT;
				break;
			case P_JETSAM_PID:
				exit_data |= NOTE_EXIT_MEMORY_PID;
				break;
			case P_JETSAM_IDLEEXIT:
				exit_data |= NOTE_EXIT_MEMORY_IDLE;
				break;
			}
		}

		if ((p->p_csflags & CS_KILLED) != 0) {
			exit_data |= NOTE_EXIT_CSERROR;
		}
	}

	proc_unlock(p);

	*data = exit_data;

	return 0;
}

int
proc_piddynkqueueinfo(int pid, int flavor, kqueue_id_t kq_id,
    user_addr_t ubuf, uint32_t bufsize, int32_t *retval)
{
	proc_t p;
	int err;

	if (ubuf == USER_ADDR_NULL) {
		return EFAULT;
	}

	p = proc_find(pid);
	if (p == PROC_NULL) {
		return ESRCH;
	}

	err = proc_security_policy(p, PROC_INFO_CALL_PIDDYNKQUEUEINFO, 0, CHECK_SAME_USER);
	if (err) {
		goto out;
	}

	switch (flavor) {
	case PROC_PIDDYNKQUEUE_INFO:
		err = kevent_copyout_dynkqinfo(p, kq_id, ubuf, bufsize, retval);
		break;
	case PROC_PIDDYNKQUEUE_EXTINFO:
		err = kevent_copyout_dynkqextinfo(p, kq_id, ubuf, bufsize, retval);
		break;
	default:
		err = ENOTSUP;
		break;
	}

out:
	proc_rele(p);

	return err;
}

#if CONFIG_PROC_UDATA_STORAGE
int
proc_udata_info(int pid, int flavor, user_addr_t buffer, uint32_t bufsize, int32_t *retval)
{
	int err = 0;
	proc_t p;

	p = proc_find(pid);
	if (p == PROC_NULL) {
		return ESRCH;
	}

	/*
	 * Only support calls against oneself for the moment.
	 */
	if (p->p_pid != proc_selfpid()) {
		err = EACCES;
		goto out;
	}

	if (bufsize != sizeof(p->p_user_data)) {
		err = EINVAL;
		goto out;
	}

	switch (flavor) {
	case PROC_UDATA_INFO_SET:
		err = copyin(buffer, &p->p_user_data, sizeof(p->p_user_data));
		break;
	case PROC_UDATA_INFO_GET:
		err = copyout(&p->p_user_data, buffer, sizeof(p->p_user_data));
		break;
	default:
		err = ENOTSUP;
		break;
	}

out:
	proc_rele(p);

	if (err == 0) {
		*retval = 0;
	}

	return err;
}
#endif /* CONFIG_PROC_UDATA_STORAGE */
