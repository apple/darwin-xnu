/*
 * Copyright (c) 2005 Apple Computer, Inc. All rights reserved.
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
#include <sys/sysctl.h>
#include <sys/user.h>
#include <sys/aio_kern.h>

#include <bsm/audit_kernel.h>

#include <mach/machine.h>
#include <mach/mach_types.h>
#include <mach/vm_param.h>
#include <kern/task.h>
#include <kern/lock.h>
#include <kern/kalloc.h>
#include <vm/vm_kern.h>
#include <vm/vm_map.h>
#include <mach/host_info.h>
#include <mach/task_info.h>
#include <mach/thread_info.h>
#include <mach/vm_region.h>

#include <sys/mount_internal.h>
#include <sys/proc_info.h>
#include <sys/bsdtask_info.h>
#include <sys/kdebug.h>
#include <sys/sysproto.h>
#include <sys/msgbuf.h>


#include <machine/machine_routines.h>

#include <vm/vm_protos.h>

struct pshmnode;
struct psemnode;
struct pipe;
struct kqueue;
struct atalk;

int proc_info_internal(int callnum, int pid, int flavor, uint64_t arg, user_addr_t buffer, uint32_t buffersize, register_t * retval);

/* protos for proc_info calls */
int proc_listpids(uint32_t type, uint32_t tyoneinfo, user_addr_t buffer, uint32_t buffersize, register_t * retval);
int proc_pidinfo(int pid, int flavor, uint64_t arg, user_addr_t buffer, uint32_t buffersize, register_t * retval);
int proc_pidfdinfo(int pid, int flavor,int fd, user_addr_t buffer, uint32_t buffersize, register_t * retval);
int proc_kernmsgbuf(user_addr_t buffer, uint32_t buffersize, register_t * retval);

/* protos for procpidinfo calls */
int proc_pidfdlist(proc_t p, user_addr_t buffer, uint32_t buffersize, register_t *retval);
int proc_pidbsdinfo(proc_t p, struct proc_bsdinfo *pbsd);
int proc_pidtaskinfo(proc_t p, struct proc_taskinfo *ptinfo);
int proc_pidallinfo(proc_t p, int flavor, uint64_t arg, user_addr_t buffer, uint32_t buffersize, register_t *retval);
int proc_pidthreadinfo(proc_t p, uint64_t arg,  struct proc_threadinfo *pthinfo);
int proc_pidlistthreads(proc_t p,  user_addr_t buffer, uint32_t buffersize, register_t *retval);
int proc_pidregioninfo(proc_t p, uint64_t arg, user_addr_t buffer, uint32_t buffersize, register_t *retval);
int proc_pidregionpathinfo(proc_t p,  uint64_t arg, user_addr_t buffer, uint32_t buffersize, register_t *retval);
int proc_pidvnodepathinfo(proc_t p,  uint64_t arg, user_addr_t buffer, uint32_t buffersize, register_t *retval);


/* protos for proc_pidfdinfo calls */
int pid_vnodeinfo(vnode_t vp, uint32_t vid, struct fileproc * fp, user_addr_t  buffer, uint32_t buffersize, register_t * retval);
int pid_vnodeinfopath(vnode_t vp, uint32_t vid, struct fileproc * fp, user_addr_t  buffer, uint32_t buffersize, register_t * retval);
int pid_socketinfo(socket_t  so, struct fileproc *fp, user_addr_t  buffer, uint32_t buffersize, register_t * retval);
int pid_pseminfo(struct psemnode * psem, struct fileproc * fp,  user_addr_t  buffer, uint32_t buffersize, register_t * retval);
int pid_pshminfo(struct pshmnode * pshm, struct fileproc * fp,  user_addr_t  buffer, uint32_t buffersize, register_t * retval);
int pid_pipeinfo(struct pipe * p, struct fileproc * fp,  user_addr_t  buffer, uint32_t buffersize, register_t * retval);
int pid_kqueueinfo(struct kqueue * kq, struct fileproc * fp,  user_addr_t  buffer, uint32_t buffersize, register_t * retval);
int pid_atalkinfo(struct atalk  * at, struct fileproc * fp,  user_addr_t  buffer, uint32_t buffersize, register_t * retval);


/* protos for misc */

int fill_vnodeinfo(vnode_t vp, struct vnode_info *vinfo);
void  fill_fileinfo(struct fileproc * fp, struct proc_fileinfo * finfo);
static int proc_security_policy(proc_t p);


/***************************** proc_info ********************/

int
proc_info(__unused struct proc *p, struct proc_info_args * uap, register_t *retval)
{
	return(proc_info_internal(uap->callnum, uap->pid, uap->flavor, uap->arg, uap->buffer, uap->buffersize, retval));
}


int 
proc_info_internal(int callnum, int pid, int flavor, uint64_t arg, user_addr_t buffer, uint32_t  buffersize, register_t * retval)
{

	switch(callnum) {
		case 1: /* proc_listpids */
			/* pid contains type and flavor contains typeinfo */
			return(proc_listpids(pid, flavor, buffer, buffersize, retval));
		case 2: /* proc_pidinfo */
			return(proc_pidinfo(pid, flavor, arg, buffer, buffersize, retval));
		case 3: /* proc_pidfdinfo */
			return(proc_pidfdinfo(pid, flavor, (int)arg, buffer, buffersize, retval));
		case 4: /* proc_kernmsgbuf */
			return(proc_kernmsgbuf( buffer, buffersize, retval));
		default:
				return(EINVAL);
	}

	return(EINVAL);
}

/******************* proc_listpids routine ****************/
int
proc_listpids(uint32_t type, uint32_t typeinfo, user_addr_t buffer, uint32_t  buffersize, register_t * retval)
{
	boolean_t funnel_state;
	int numprocs, wantpids;
	char * kbuf;
	int * ptr;
	int n, skip;
	struct proc * p;
	int error = 0;

	/* if the buffer is null, return num of procs */
	if (buffer == (user_addr_t)0) {
		*retval = ((nprocs+20) * sizeof(int));
		return(0);
	}

	if (buffersize < sizeof(int)) {
		return(ENOMEM);
	}
	wantpids = buffersize/sizeof(int);
	numprocs = nprocs+20;
	if (numprocs > wantpids)
		numprocs = wantpids;

	kbuf = (char *)kalloc((vm_size_t)(numprocs * sizeof(int)));
	bzero(kbuf, sizeof(int));

	funnel_state = thread_funnel_set(kernel_flock, TRUE);
	
	n = 0;
	ptr = (int *)kbuf;
	LIST_FOREACH(p, &allproc, p_list) {
		skip = 0;
		switch (type) {
			case PROC_PGRP_ONLY:
				if (p->p_pgrp->pg_id != (pid_t)typeinfo)
					skip = 1;
			  	break;
			case PROC_ALL_PIDS:
				skip = 0;
			  	break;
			case PROC_TTY_ONLY:
				if ((p->p_flag & P_CONTROLT) == 0 ||
					(p->p_session == NULL) ||
			    	p->p_session->s_ttyp == NULL ||
			    	p->p_session->s_ttyp->t_dev != (dev_t)typeinfo)
					skip = 1;
			  	break;
			case PROC_UID_ONLY:
				if ((p->p_ucred == NULL) ||
					(kauth_cred_getuid(p->p_ucred) != (uid_t)typeinfo))
					skip = 1;
			  	break;
			case PROC_RUID_ONLY:
				if ((p->p_ucred == NULL) ||
					(p->p_ucred->cr_ruid != (uid_t)typeinfo))
			  	break;
			default:
			  skip = 1;
			  break;
		};

		/* Do we have permission to look into this ? */
		if (proc_security_policy(p) != 0) {
			skip = 1;
		}

		if(skip == 0) {
			*ptr++ = p->p_pid;
			n++;
		}
		if (n >= numprocs)
			break;
	}
	
	if (n < numprocs) {
		LIST_FOREACH(p, &zombproc, p_list) {
			*ptr++ = p->p_pid;
			n++;
			if (n >= numprocs)
				break;
		}
	}
	
	thread_funnel_set(kernel_flock, funnel_state);

	ptr = (int *)kbuf;
	error = copyout((caddr_t)ptr, buffer, n * sizeof(int));
	if (error == 0)
		*retval = (n * sizeof(int));
	kfree((void *)kbuf, (vm_size_t)(numprocs * sizeof(int)));

	return(error);
}


/********************************** proc_pidinfo routines ********************************/

int 
proc_pidfdlist(proc_t p, user_addr_t buffer, uint32_t  buffersize, register_t *retval)
{
		int numfds, needfds;
		char * kbuf;
		struct proc_fdinfo * pfd;
		struct fileproc * fp;
		int n;
		int count = 0;
		int error = 0;
		
	 	numfds = p->p_fd->fd_nfiles;	

		if (buffer == (user_addr_t) 0) {
			numfds += 20;
			*retval = (numfds * sizeof(struct proc_fdinfo));
			return(0);
		}

		/* buffersize is big enough atleast for one struct */
		needfds = buffersize/sizeof(struct proc_fdinfo);

		if (numfds > needfds)
			numfds = needfds;

		kbuf = (char *)kalloc((vm_size_t)(numfds * sizeof(struct proc_fdinfo)));
		bzero(kbuf, numfds * sizeof(struct proc_fdinfo));

		proc_fdlock(p);

		pfd = (struct proc_fdinfo *)kbuf;

		for (n = 0; ((n < numfds) && (n < p->p_fd->fd_nfiles)); n++) {
			if (((fp = p->p_fd->fd_ofiles[n]) != 0) 
			     && ((p->p_fd->fd_ofileflags[n] & UF_RESERVED) == 0)) {
				pfd->proc_fd = n;
				pfd->proc_fdtype = fp->f_fglob->fg_type;	
				count++;
				pfd++;
			}
		}
		proc_fdunlock(p);

		error = copyout(kbuf, buffer, count * sizeof(struct proc_fdinfo));
		kfree((void *)kbuf, (vm_size_t)(numfds * sizeof(struct proc_fdinfo)));
		if (error == 0)
			*retval = (count * sizeof(struct proc_fdinfo));
		return(error);		
}


int 
proc_pidbsdinfo(proc_t p, struct proc_bsdinfo * pbsd)
{
	register struct tty *tp;
	struct  session *sessionp = NULL;

	bzero(pbsd, sizeof(struct proc_bsdinfo));
	pbsd->pbi_status = p->p_stat;
	pbsd->pbi_xstatus = p->p_xstat;
	pbsd->pbi_pid = p->p_pid;
	pbsd->pbi_ppid = p->p_pptr->p_pid;
	pbsd->pbi_uid = p->p_ucred->cr_uid;
	pbsd->pbi_gid = p->p_ucred->cr_uid; /* XXX */
	pbsd->pbi_ruid =  p->p_ucred->cr_ruid;
	pbsd->pbi_rgid = p->p_ucred->cr_rgid;
	pbsd->pbi_svuid =  p->p_ucred->cr_svuid;
	pbsd->pbi_svgid = p->p_ucred->cr_svgid;
	
	pbsd->pbi_nice = p->p_nice;
	if (p->p_stats)
		pbsd->pbi_start = p->p_stats->p_start;
	bcopy(&p->p_comm, &pbsd->pbi_comm[0], MAXCOMLEN);
	bcopy(&p->p_name, &pbsd->pbi_name[0], 2* MAXCOMLEN);

	pbsd->pbi_flags = 0;	
	if ((p->p_flag & P_SYSTEM) == P_SYSTEM) 
		pbsd->pbi_flags |= PROC_FLAG_SYSTEM;
	if ((p->p_flag & P_TRACED) == P_TRACED) 
		pbsd->pbi_flags |= PROC_FLAG_TRACED;
	if ((p->p_flag & P_WEXIT) == P_WEXIT) 
		pbsd->pbi_flags |= PROC_FLAG_INEXIT;
	if ((p->p_flag & P_PPWAIT) == P_PPWAIT) 
		pbsd->pbi_flags |= PROC_FLAG_PPWAIT;
	if ((p->p_flag & P_LP64) == P_LP64) 
		pbsd->pbi_flags |= PROC_FLAG_LP64;
	if ((p->p_flag & P_CONTROLT) == P_CONTROLT) 
		pbsd->pbi_flags |= PROC_FLAG_CONTROLT;

	if (SESS_LEADER(p))
		pbsd->pbi_flags |= PROC_FLAG_SLEADER;
	if (p->p_pgrp->pg_session && p->p_pgrp->pg_session->s_ttyvp)
		pbsd->pbi_flags |= PROC_FLAG_CTTY;
		
	pbsd->pbi_nfiles = p->p_fd->fd_nfiles;
	if (p->p_pgrp) {
		sessionp = p->p_pgrp->pg_session;
		pbsd->pbi_pgid = p->p_pgrp->pg_id;
		pbsd->pbi_pjobc = p->p_pgrp->pg_jobc;
		if ((p->p_flag & P_CONTROLT) && (sessionp) && (tp = sessionp->s_ttyp)) {
			pbsd->e_tdev = tp->t_dev;
			pbsd->e_tpgid = tp->t_pgrp ? tp->t_pgrp->pg_id : 0;
		}
	} 
	return(0);
}


int 
proc_pidtaskinfo(proc_t p, struct proc_taskinfo * ptinfo)
{
	task_t task;
	
	task = p->task;

	bzero(ptinfo, sizeof(struct proc_taskinfo));
	fill_taskprocinfo(task, (struct proc_taskinfo_internal *)ptinfo);

	return(0);
}



int 
proc_pidthreadinfo(proc_t p, uint64_t arg,  struct proc_threadinfo *pthinfo)
{
	int error = 0;
	uint64_t threadaddr = (uint64_t)arg;

	bzero(pthinfo, sizeof(struct proc_threadinfo));

	error = fill_taskthreadinfo(p->task, threadaddr, (struct proc_threadinfo_internal *)pthinfo);
	if (error)
		return(ESRCH);
	else
		return(0);

}


int 
proc_pidlistthreads(proc_t p,  user_addr_t buffer, uint32_t  buffersize, register_t *retval)
{
	int count = 0;	
	int ret = 0;
	int error = 0;
	void * kbuf;
	int numthreads;

	
	count = buffersize/(sizeof(uint64_t));
	numthreads = get_numthreads(p->task);

	numthreads += 10;

	if (numthreads > count)
		numthreads = count;

	kbuf = (void *)kalloc(numthreads * sizeof(uint64_t));
	bzero(kbuf, numthreads * sizeof(uint64_t));
	
	ret = fill_taskthreadlist(p->task, kbuf, numthreads);
	
	error = copyout(kbuf, buffer, ret);
	kfree(kbuf, numthreads * sizeof(uint64_t));
	if (error == 0)
		*retval = ret;
	return(error);
	
}


int 
proc_pidregioninfo(proc_t p, uint64_t arg, user_addr_t buffer, __unused uint32_t  buffersize, register_t *retval)
{
	struct proc_regioninfo preginfo;
	int ret, error = 0;

	bzero(&preginfo, sizeof(struct proc_regioninfo));
	ret = fill_procregioninfo( p->task, arg, (struct proc_regioninfo_internal *)&preginfo, (uint32_t *)0, (uint32_t *)0);
	if (ret == 0)
		return(EINVAL);
	error = copyout(&preginfo, buffer, sizeof(struct proc_regioninfo));
	if (error == 0)
		*retval = sizeof(struct proc_regioninfo);
	return(error);
}


int 
proc_pidregionpathinfo(proc_t p, uint64_t arg, user_addr_t buffer, __unused uint32_t  buffersize, register_t *retval)
{
	struct proc_regionwithpathinfo preginfo;
	int ret, error = 0;
	uint32_t vnodeaddr= 0;
	uint32_t vnodeid= 0;
	vnode_t vp;
	int count;

	bzero(&preginfo, sizeof(struct proc_regionwithpathinfo));

	ret = fill_procregioninfo( p->task, arg, (struct proc_regioninfo_internal *)&preginfo.prp_prinfo, (uint32_t *)&vnodeaddr, (uint32_t *)&vnodeid);
	if (ret == 0)
		return(EINVAL);
	if (vnodeaddr) {
		vp = (vnode_t)vnodeaddr;
		if ((vnode_getwithvid(vp, vnodeid)) == 0) {
			/* FILL THE VNODEINFO */
			error = fill_vnodeinfo(vp, &preginfo.prp_vip.vip_vi);
			count = MAXPATHLEN;
			vn_getpath(vp, &preginfo.prp_vip.vip_path[0], &count);
			/* Always make sure it is null terminated */
			preginfo.prp_vip.vip_path[MAXPATHLEN-1] = 0;
			vnode_put(vp);
		}
	}
	error = copyout(&preginfo, buffer, sizeof(struct proc_regionwithpathinfo));
	if (error == 0)
		*retval = sizeof(struct proc_regionwithpathinfo);
	return(error);
}

int 
proc_pidvnodepathinfo(proc_t p, __unused uint64_t arg, user_addr_t buffer, __unused uint32_t  buffersize, register_t *retval)
{
	struct proc_vnodepathinfo pvninfo;
	int error = 0;
	vnode_t vncdirvp = NULLVP;
	uint32_t vncdirid=0;
	vnode_t vnrdirvp = NULLVP;
	uint32_t vnrdirid=0;
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
			error = fill_vnodeinfo(vncdirvp, &pvninfo.pvi_cdir.vip_vi);
			if ( error == 0) {
				count = MAXPATHLEN;
				vn_getpath(vncdirvp, &pvninfo.pvi_cdir.vip_path[0], &count);
				pvninfo.pvi_cdir.vip_path[MAXPATHLEN-1] = 0;
			}	
			vnode_put(vncdirvp);
		} else {
			goto out;
		}
	}

	if ((error == 0) && (vnrdirvp != NULLVP)) {
		if ((error = vnode_getwithvid(vnrdirvp, vnrdirid)) == 0) {
			/* FILL THE VNODEINFO */
			error = fill_vnodeinfo(vnrdirvp, &pvninfo.pvi_rdir.vip_vi);
			if ( error == 0) {
				count = MAXPATHLEN;
				vn_getpath(vnrdirvp, &pvninfo.pvi_rdir.vip_path[0], &count);
				pvninfo.pvi_rdir.vip_path[MAXPATHLEN-1] = 0;
			}	
			vnode_put(vnrdirvp);
		} else {
			goto out;
		}
	}
	if (error == 0) {
		error = copyout(&pvninfo, buffer, sizeof(struct proc_vnodepathinfo));
		if (error == 0)
			*retval = sizeof(struct proc_vnodepathinfo);
	}
out:
	return(error);
}

/********************************** proc_pidinfo ********************************/


int
proc_pidinfo(int pid, int flavor, uint64_t arg, user_addr_t buffer, uint32_t  buffersize, register_t * retval)
{
	struct proc * p = PROC_NULL;
	int error = ENOTSUP;
	int gotref = 0;
	int findzomb = 0;
	boolean_t funnel_state;
	uint32_t size;

	switch (flavor) {
		case PROC_PIDLISTFDS:
			size = PROC_PIDLISTFD_SIZE;
			if (buffer == (user_addr_t)0)
				size = 0;
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
		default:
			return(EINVAL);
	}

	if (buffersize < size) 
		return(ENOMEM);

	if (flavor != PROC_PIDTBSDINFO) {
		if ((p = proc_findref(pid)) == PROC_NULL) {
				error = ESRCH;
				goto out;
			} else {
				gotref = 1;

				/* Do we have permission to look into this ? */
				if ((error = proc_security_policy(p)) != 0) {
					goto out;
				}
			}
	}
	switch (flavor) {
		case PROC_PIDLISTFDS: {
			error = proc_pidfdlist(p, buffer, buffersize, retval);
		}
		break;

		case PROC_PIDTBSDINFO: {
			struct proc_bsdinfo pbsd;

			if (arg)
				findzomb = 1;
			funnel_state = thread_funnel_set(kernel_flock, TRUE);
			p = pfind(pid);
			if (p == PROC_NULL) {
				if (findzomb) 
					p = pzfind(pid);
				if (p == NULL) {
					error = ESRCH;
					thread_funnel_set(kernel_flock, funnel_state);
					goto out;	
				}
			}
			/* Do we have permission to look into this ? */
			if ((error = proc_security_policy(p)) != 0) {
				thread_funnel_set(kernel_flock, funnel_state);
				goto out;
			}
			error = proc_pidbsdinfo(p, &pbsd);
			thread_funnel_set(kernel_flock, funnel_state);	
			if (error == 0) {
				error = copyout(&pbsd, buffer, sizeof(struct proc_bsdinfo));
				if (error == 0)
					*retval = sizeof(struct proc_bsdinfo);
			}	
		}
		break;

		case PROC_PIDTASKINFO: {
			struct proc_taskinfo ptinfo;

			error =  proc_pidtaskinfo(p, &ptinfo);
			if (error == 0) {
				error = copyout(&ptinfo, buffer, sizeof(struct proc_taskinfo));
				if (error == 0)
					*retval = sizeof(struct proc_taskinfo);
			}	
		}
		break;

		case PROC_PIDTASKALLINFO: {
		struct proc_taskallinfo pall;

			error = proc_pidbsdinfo(p, &pall.pbsd);
			error =  proc_pidtaskinfo(p, &pall.ptinfo);
			if (error == 0) {
				error = copyout(&pall, buffer, sizeof(struct proc_taskallinfo));
				if (error == 0)
					*retval = sizeof(struct proc_taskallinfo);
			}	
		}
		break;

		case PROC_PIDTHREADINFO:{
		struct proc_threadinfo pthinfo;

			error  = proc_pidthreadinfo(p,  arg, &pthinfo);
			if (error == 0) {
				error = copyout(&pthinfo, buffer, sizeof(struct proc_threadinfo));
				if (error == 0)
					*retval = sizeof(struct proc_threadinfo);
			}	
		}
		break;

		case PROC_PIDLISTTHREADS:{
			error =  proc_pidlistthreads(p,  buffer, buffersize, retval);
		}
		break;

		case PROC_PIDREGIONINFO:{
			error =  proc_pidregioninfo(p,  arg, buffer, buffersize, retval);
		}
		break;


		case PROC_PIDREGIONPATHINFO:{
			error =  proc_pidregionpathinfo(p, arg, buffer, buffersize, retval);
		}
		break;

		case PROC_PIDVNODEPATHINFO:{
			error =  proc_pidvnodepathinfo(p, arg, buffer, buffersize, retval);
		}
		break;

		default:
			error = ENOTSUP;
	}
	
out:
	if (gotref)
		proc_dropref(p);
	return(error);
}


int 
pid_vnodeinfo(vnode_t vp, uint32_t vid, struct fileproc * fp, user_addr_t  buffer, __unused uint32_t buffersize, register_t * retval) 
{
	struct vnode_fdinfo vfi;
	int error= 0;

	if ((error = vnode_getwithvid(vp, vid)) != 0) {
		return(error);
	}
	bzero(&vfi, sizeof(struct vnode_fdinfo));
	fill_fileinfo(fp, &vfi.pfi);
	error = fill_vnodeinfo(vp, &vfi.pvi);
	vnode_put(vp);
	if (error == 0) {
		error = copyout((caddr_t)&vfi, buffer, sizeof(struct vnode_fdinfo));
		if (error == 0)
			*retval = sizeof(struct vnode_fdinfo);
	}
	return(error);
}

int 
pid_vnodeinfopath(vnode_t vp, uint32_t vid, struct fileproc * fp, user_addr_t  buffer, __unused uint32_t buffersize, register_t * retval) 
{
	struct vnode_fdinfowithpath vfip;
	int count, error= 0;

	if ((error = vnode_getwithvid(vp, vid)) != 0) {
		return(error);
	}
	bzero(&vfip, sizeof(struct vnode_fdinfowithpath));
	fill_fileinfo(fp, &vfip.pfi);
	error = fill_vnodeinfo(vp, &vfip.pvip.vip_vi) ;
	if (error == 0) {
		count = MAXPATHLEN;
		vn_getpath(vp, &vfip.pvip.vip_path[0], &count);
		vfip.pvip.vip_path[MAXPATHLEN-1] = 0;
		vnode_put(vp);
		error = copyout((caddr_t)&vfip, buffer, sizeof(struct vnode_fdinfowithpath));
		if (error == 0)
			*retval = sizeof(struct vnode_fdinfowithpath);
	} else 
		vnode_put(vp);
	return(error);
}

void  
fill_fileinfo(struct fileproc * fp, struct proc_fileinfo * fproc)
{
		fproc->fi_openflags = fp->f_fglob->fg_flag;
		fproc->fi_status = fp->f_flags;
		fproc->fi_offset = fp->f_fglob->fg_offset;
		fproc->fi_type = fp->f_fglob->fg_type;
}



int
fill_vnodeinfo(vnode_t vp, struct vnode_info *vinfo)
{
		vfs_context_t context;
		struct stat * sb;
		int error = 0;

		sb = &vinfo->vi_stat;

		context = vfs_context_create((vfs_context_t)0);
		error = vn_stat(vp, sb, NULL, context);
		(void)vfs_context_rele(context);

		if (error != 0)
			goto out;

		if (vp->v_mount != dead_mountp) {
			vinfo->vi_fsid = vp->v_mount->mnt_vfsstat.f_fsid;
		} else {
			vinfo->vi_fsid.val[0] = 0;
			vinfo->vi_fsid.val[1] = 0;
		}
		vinfo->vi_type = vp->v_type;
out:
		return(error);
}

int
pid_socketinfo(socket_t so, struct fileproc *fp, user_addr_t  buffer, __unused uint32_t buffersize, register_t * retval)
{
	struct socket_fdinfo s;
	int error = 0;

	bzero(&s, sizeof(struct socket_fdinfo));
	fill_fileinfo(fp, &s.pfi);
	if ((error = fill_socketinfo(so, &s.psi)) == 0) {
		if ((error = copyout(&s, buffer, sizeof(struct socket_fdinfo))) == 0)
				*retval = sizeof(struct socket_fdinfo);
	}
	
	return (error);
}

int
pid_pseminfo(struct psemnode *psem, struct fileproc *fp,  user_addr_t  buffer, __unused uint32_t buffersize, register_t * retval)
{
	struct psem_fdinfo pseminfo;
	int error = 0;
 
	bzero(&pseminfo, sizeof(struct psem_fdinfo));
	fill_fileinfo(fp, &pseminfo.pfi);

	if ((error = fill_pseminfo(psem, &pseminfo.pseminfo)) == 0) {
		if ((error = copyout(&pseminfo, buffer, sizeof(struct psem_fdinfo))) == 0)
				*retval = sizeof(struct psem_fdinfo);
	}

	return(error);
}

int
pid_pshminfo(struct pshmnode *pshm, struct fileproc *fp,  user_addr_t  buffer, __unused uint32_t buffersize, register_t * retval)
{
	struct pshm_fdinfo pshminfo;
	int error = 0;
 
	bzero(&pshminfo, sizeof(struct pshm_fdinfo));
	fill_fileinfo(fp, &pshminfo.pfi);

	if ((error = fill_pshminfo(pshm, &pshminfo.pshminfo)) == 0) {
		if ((error = copyout(&pshminfo, buffer, sizeof(struct pshm_fdinfo))) == 0)
				*retval = sizeof(struct pshm_fdinfo);
	}

	return(error);
}

int
pid_pipeinfo(struct pipe *  p, struct fileproc *fp,  user_addr_t  buffer, __unused uint32_t buffersize, register_t * retval)
{
	struct pipe_fdinfo pipeinfo;
	int error = 0;

	bzero(&pipeinfo, sizeof(struct pipe_fdinfo));
	fill_fileinfo(fp, &pipeinfo.pfi);
	if ((error = fill_pipeinfo(p, &pipeinfo.pipeinfo)) == 0) {
		if ((error = copyout(&pipeinfo, buffer, sizeof(struct pipe_fdinfo))) == 0)
				*retval = sizeof(struct pipe_fdinfo);
	}

	return(error);
}

int
pid_kqueueinfo(struct kqueue * kq, struct fileproc *fp,  user_addr_t  buffer, __unused uint32_t buffersize, register_t * retval)
{
	struct kqueue_fdinfo kqinfo;
	int error = 0;
	
	bzero(&kqinfo, sizeof(struct kqueue_fdinfo));
 
	fill_fileinfo(fp, &kqinfo.pfi);

	if ((error = fill_kqueueinfo(kq, &kqinfo.kqueueinfo)) == 0) {
		if ((error = copyout(&kqinfo, buffer, sizeof(struct kqueue_fdinfo))) == 0)
				*retval = sizeof(struct kqueue_fdinfo);
	}

	return(error);
}

int
pid_atalkinfo(__unused struct atalk * at, __unused struct fileproc *fp,  __unused user_addr_t  buffer, __unused uint32_t buffersize, __unused register_t * retval)
{
	return ENOTSUP;
}



/************************** proc_pidfdinfo routine ***************************/
int
proc_pidfdinfo(int pid, int flavor,  int fd, user_addr_t buffer, uint32_t buffersize, register_t * retval)
{
	proc_t p;
	int error = ENOTSUP;
	struct fileproc * fp;
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
		case PROC_PIDFDATALKINFO:
			size = PROC_PIDFDATALKINFO_SIZE;
			break;

		default:
			return(EINVAL);

	}

	if (buffersize < size)
		return(ENOMEM);

	if ((p = proc_findref(pid)) == PROC_NULL) {
		error = ESRCH;
		goto out;
	}
	/* Do we have permission to look into this ? */
	if ((error = proc_security_policy(p)) != 0) {
		goto out1;
	}

	switch (flavor) {
		case PROC_PIDFDVNODEINFO: {
			vnode_t vp;
			uint32_t vid=0;

			if ((error = fp_getfvpandvid(p, fd, &fp,  &vp, &vid)) !=0) {
				goto out1;
			}
			error =  pid_vnodeinfo(vp, vid, fp, buffer, buffersize, retval);
		}
		break;

		case PROC_PIDFDVNODEPATHINFO: {
			vnode_t vp;
			uint32_t vid=0;

			if ((error = fp_getfvpandvid(p, fd, &fp,  &vp, &vid)) !=0) {
				goto out1;
			}

			error =  pid_vnodeinfopath(vp, vid, fp, buffer, buffersize, retval);
		}
		break;

		case PROC_PIDFDSOCKETINFO: {
			socket_t so; 

			if ((error = fp_getfsock(p, fd, &fp,  &so)) !=0) {
				goto out1;
			}
			error =  pid_socketinfo(so, fp, buffer, buffersize, retval);
		}
		break;

		case PROC_PIDFDPSEMINFO: {
			struct psemnode * psem;

			if ((error = fp_getfpsem(p, fd, &fp,  &psem)) !=0) {
				goto out1;
			}
			error =  pid_pseminfo(psem, fp, buffer, buffersize, retval);
		}
		break;

		case PROC_PIDFDPSHMINFO: {
			struct pshmnode * pshm;

			if ((error = fp_getfpshm(p, fd, &fp,  &pshm)) !=0) {
				goto out1;
			}
			error =  pid_pshminfo(pshm, fp, buffer, buffersize, retval);
		}
		break;

		case PROC_PIDFDPIPEINFO: {
			struct pipe * cpipe;

			if ((error = fp_getfpipe(p, fd, &fp,  &cpipe)) !=0) {
				goto out1;
			}
			error =  pid_pipeinfo(cpipe, fp, buffer, buffersize, retval);
		}
		break;

		case PROC_PIDFDKQUEUEINFO: {
			struct kqueue * kq;

			if ((error = fp_getfkq(p, fd, &fp,  &kq)) !=0) {
				goto out1;
			}
			error =  pid_kqueueinfo(kq, fp, buffer, buffersize, retval);
		}
		break;

		case PROC_PIDFDATALKINFO: {
			struct atalk * at;

			if ((error = fp_getfatalk(p, fd, &fp,  &at)) !=0) {
				goto out1;
			}

			error =  pid_atalkinfo(at, fp, buffer, buffersize, retval);
		}
		break;

		default: {
			error = EINVAL;
		}
		break;

	}

	fp_drop(p, fd, fp , 0); 	
out1 :
	proc_dropref(p);
out:
	return(error);
}


static int
proc_security_policy(proc_t p)
{
	if ((kauth_cred_getuid(p->p_ucred) != kauth_cred_getuid(kauth_cred_get())) 
		&& suser(kauth_cred_get(), (u_short *)0)) {
			return(EPERM);
		}

	return(0);
}


/* Temporary hack to get dmesg to work. In Leopard this will disappear */
int 
proc_kernmsgbuf(user_addr_t buffer, uint32_t buffersize, register_t * retval)
{
	int error;

	if (buffersize  < sizeof(struct msgbuf))
		return(ENOMEM);

	if (suser(kauth_cred_get(), (u_short *)0) == 0) {
		error = copyout(msgbufp, buffer, sizeof(struct msgbuf));
		if (error ==  0)
			*retval = sizeof(struct msgbuf);
		return(error);
	} else
		return(EPERM);
}

