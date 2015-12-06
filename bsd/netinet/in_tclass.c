/*
 * Copyright (c) 2009-2014 Apple Inc. All rights reserved.
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

#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/types.h>
#include <sys/filedesc.h>
#include <sys/file_internal.h>
#include <sys/proc.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/errno.h>
#include <sys/protosw.h>
#include <sys/domain.h>
#include <sys/mbuf.h>
#include <sys/queue.h>

#include <net/if.h>
#include <net/route.h>

#include <netinet/in.h>
#include <netinet/in_var.h>
#include <netinet/in_pcb.h>
#include <netinet/ip.h>
#include <netinet/ip_var.h>
#include <netinet/ip6.h>
#include <netinet6/ip6_var.h>
#include <netinet/udp.h>
#include <netinet/udp_var.h>
#include <netinet/tcp.h>
#include <netinet/tcp_var.h>
#include <netinet/tcp_cc.h>
#include <netinet/lro_ext.h>

extern char *proc_name_address(void *p);

static int tfp_count = 0;

static TAILQ_HEAD(, tclass_for_proc) tfp_head =
    TAILQ_HEAD_INITIALIZER(tfp_head);

struct tclass_for_proc {
	TAILQ_ENTRY(tclass_for_proc)	tfp_link;
	int	tfp_class;
	pid_t	tfp_pid;
	char	tfp_pname[MAXCOMLEN + 1];
};

static int dscp_code_from_mbuf_tclass(mbuf_traffic_class_t);
static int get_pid_tclass(struct so_tcdbg *);
static int get_pname_tclass(struct so_tcdbg *);
static int set_pid_tclass(struct so_tcdbg *);
static int set_pname_tclass(struct so_tcdbg *);
static int flush_pid_tclass(struct so_tcdbg *);
static int purge_tclass_for_proc(void);
static int flush_tclass_for_proc(void);
int get_tclass_for_curr_proc(int *);
static inline int so_throttle_best_effort(struct socket* ,struct ifnet *);

static lck_grp_attr_t *tclass_lck_grp_attr = NULL; /* mutex group attributes */
static lck_grp_t *tclass_lck_grp = NULL;	/* mutex group definition */
static lck_attr_t *tclass_lck_attr = NULL;	/* mutex attributes */
decl_lck_mtx_data(static, tclass_lock_data);
static lck_mtx_t *tclass_lock = &tclass_lock_data;

/*
 * If there is no foreground activity on the interface for bg_switch_time
 * seconds, the background connections can switch to foreground TCP
 * congestion control.
 */ 
#define TCP_BG_SWITCH_TIME 2 /* seconds */

/*
 * Must be called with tclass_lock held
 */
static struct tclass_for_proc *
find_tfp_by_pid(pid_t pid)
{
	struct tclass_for_proc *tfp;

	TAILQ_FOREACH(tfp, &tfp_head, tfp_link) {
		if (tfp->tfp_pid == pid)
			break;
	}
	return (tfp);
}

/*
 * Must be called with tclass_lock held
 */
static struct tclass_for_proc *
find_tfp_by_pname(const char *pname)
{
	struct tclass_for_proc *tfp;

	TAILQ_FOREACH(tfp, &tfp_head, tfp_link) {
		if (strncmp(pname, tfp->tfp_pname,
		    sizeof (tfp->tfp_pname)) == 0)
			break;
	}
	return (tfp);
}

__private_extern__ int
get_tclass_for_curr_proc(int *sotc)
{
	struct tclass_for_proc *tfp = NULL;
	proc_t p = current_proc();	/* Not ref counted */
	pid_t pid = proc_pid(p);
	char *pname = proc_name_address(p);

	*sotc = -1;

	lck_mtx_lock(tclass_lock);

	TAILQ_FOREACH(tfp, &tfp_head, tfp_link) {
		if ((tfp->tfp_pid == pid) || (tfp->tfp_pid == -1 &&
		    strncmp(pname, tfp->tfp_pname,
		    sizeof (tfp->tfp_pname)) == 0)) {
			*sotc = tfp->tfp_class;
			break;
		}
	}

	lck_mtx_unlock(tclass_lock);

	return ((tfp == NULL) ? 0 : 1);
}

/*
 * Purge entries with PIDs of exited processes
 */
int
purge_tclass_for_proc(void)
{
	int error = 0;
	struct tclass_for_proc *tfp, *tvar;

	lck_mtx_lock(tclass_lock);

	TAILQ_FOREACH_SAFE(tfp, &tfp_head, tfp_link, tvar) {
		proc_t p;

		if (tfp->tfp_pid == -1)
			continue;
		if ((p = proc_find(tfp->tfp_pid)) == NULL) {
			tfp_count--;
			TAILQ_REMOVE(&tfp_head, tfp, tfp_link);

			_FREE(tfp, M_TEMP);
		} else {
			proc_rele(p);
		}
	}

	lck_mtx_unlock(tclass_lock);

	return (error);
}

/*
 * Remove one entry
 * Must be called with tclass_lock held
 */
static void
free_tclass_for_proc(struct tclass_for_proc *tfp)
{
	if (tfp == NULL)
		return;
	tfp_count--;
	TAILQ_REMOVE(&tfp_head, tfp, tfp_link);
	_FREE(tfp, M_TEMP);
}

/*
 * Remove all entries
 */
int
flush_tclass_for_proc(void)
{
	int error = 0;
	struct tclass_for_proc *tfp, *tvar;

	lck_mtx_lock(tclass_lock);

	TAILQ_FOREACH_SAFE(tfp, &tfp_head, tfp_link, tvar) {
		free_tclass_for_proc(tfp);
	}

	lck_mtx_unlock(tclass_lock);

	return (error);

}

/*
 * Must be called with tclass_lock held
 */
static struct tclass_for_proc *
alloc_tclass_for_proc(pid_t pid, const char *pname)
{
	struct tclass_for_proc *tfp;

	if (pid == -1 && pname == NULL)
		return (NULL);

	tfp = _MALLOC(sizeof (struct tclass_for_proc), M_TEMP, M_NOWAIT|M_ZERO);
	if (tfp == NULL)
		return (NULL);

	tfp->tfp_pid = pid;
	/*
	 * Add per pid entries before per proc name so we can find
	 * a specific instance of a process before the general name base entry.
	 */
	if (pid != -1) {
		TAILQ_INSERT_HEAD(&tfp_head, tfp, tfp_link);
	} else {
		strlcpy(tfp->tfp_pname, pname, sizeof (tfp->tfp_pname));
		TAILQ_INSERT_TAIL(&tfp_head, tfp, tfp_link);
	}

	tfp_count++;

	return (tfp);
}

/*
 * -1 for tclass means to remove the entry
 */
int
set_pid_tclass(struct so_tcdbg *so_tcdbg)
{
	int error = EINVAL;
	proc_t p = NULL;
	struct filedesc *fdp;
	struct fileproc *fp;
	struct tclass_for_proc *tfp;
	int i;
	pid_t pid = so_tcdbg->so_tcdbg_pid;
	int tclass = so_tcdbg->so_tcdbg_tclass;

	p = proc_find(pid);
	if (p == NULL) {
		printf("%s proc_find(%d) failed\n", __func__, pid);
		goto done;
	}

	/* Need a tfp */
	lck_mtx_lock(tclass_lock);

	tfp = find_tfp_by_pid(pid);
	if (tfp == NULL) {
		tfp = alloc_tclass_for_proc(pid, NULL);
		if (tfp == NULL) {
			lck_mtx_unlock(tclass_lock);
			error = ENOBUFS;
			goto done;
		}
	}
	tfp->tfp_class = tclass;

	lck_mtx_unlock(tclass_lock);

	if (tfp != NULL) {
		proc_fdlock(p);

		fdp = p->p_fd;
		for (i = 0; i < fdp->fd_nfiles; i++) {
			struct socket *so;

			fp = fdp->fd_ofiles[i];
			if (fp == NULL ||
			    (fdp->fd_ofileflags[i] & UF_RESERVED) != 0 ||
			    FILEGLOB_DTYPE(fp->f_fglob) != DTYPE_SOCKET)
				continue;

			so = (struct socket *)fp->f_fglob->fg_data;
			if (SOCK_DOM(so) != PF_INET && SOCK_DOM(so) != PF_INET6)
				continue;
			socket_lock(so, 1);
			if (tclass != -1) {
				error = so_set_traffic_class(so, tclass);
				if (error != 0) {
					printf("%s: so_set_traffic_class"
					    "(so=0x%llx, fd=%d, tclass=%d) "
					    "failed %d\n", __func__,
					    (uint64_t)VM_KERNEL_ADDRPERM(so),
					    i, tclass, error);
					error = 0;
				}
			}
			socket_unlock(so, 1);
		}

		proc_fdunlock(p);
	}

	error = 0;
done:
	if (p != NULL)
		proc_rele(p);

	return (error);
}

int
set_pname_tclass(struct so_tcdbg *so_tcdbg)
{
	int error = EINVAL;
	struct tclass_for_proc *tfp;

	lck_mtx_lock(tclass_lock);

	tfp = find_tfp_by_pname(so_tcdbg->so_tcdbg_pname);
	if (tfp == NULL) {
		tfp = alloc_tclass_for_proc(-1, so_tcdbg->so_tcdbg_pname);
		if (tfp == NULL) {
			lck_mtx_unlock(tclass_lock);
			error = ENOBUFS;
			goto done;
		}
	}
	tfp->tfp_class = so_tcdbg->so_tcdbg_tclass;

	lck_mtx_unlock(tclass_lock);

	error = 0;
done:

	return (error);
}

static int
flush_pid_tclass(struct so_tcdbg *so_tcdbg)
{
	pid_t pid = so_tcdbg->so_tcdbg_pid;
	int tclass = so_tcdbg->so_tcdbg_tclass;
	struct filedesc *fdp;
	int error = EINVAL;
	proc_t p;
	int i;

	p = proc_find(pid);
	if (p == PROC_NULL) {
		printf("%s proc_find(%d) failed\n", __func__, pid);
		goto done;
	}

	proc_fdlock(p);
	fdp = p->p_fd;
	for (i = 0; i < fdp->fd_nfiles; i++) {
		struct socket *so;
		struct fileproc *fp;

		fp = fdp->fd_ofiles[i];
		if (fp == NULL ||
		    (fdp->fd_ofileflags[i] & UF_RESERVED) != 0 ||
		    FILEGLOB_DTYPE(fp->f_fglob) != DTYPE_SOCKET)
			continue;

		so = (struct socket *)fp->f_fglob->fg_data;
		error = sock_setsockopt(so, SOL_SOCKET, SO_FLUSH, &tclass,
		    sizeof (tclass));
		if (error != 0) {
			printf("%s: setsockopt(SO_FLUSH) (so=0x%llx, fd=%d, "
			    "tclass=%d) failed %d\n", __func__,
			    (uint64_t)VM_KERNEL_ADDRPERM(so), i, tclass,
			    error);
			error = 0;
		}
	}
	proc_fdunlock(p);

	error = 0;
done:
	if (p != PROC_NULL)
		proc_rele(p);

	return (error);
}

int
get_pid_tclass(struct so_tcdbg *so_tcdbg)
{
	int error = EINVAL;
	proc_t p = NULL;
	struct tclass_for_proc *tfp;
	pid_t pid = so_tcdbg->so_tcdbg_pid;

	so_tcdbg->so_tcdbg_tclass = -1; /* Means not set */
	so_tcdbg->so_tcdbg_opportunistic = -1; /* Means not set */

	p = proc_find(pid);
	if (p == NULL) {
		printf("%s proc_find(%d) failed\n", __func__, pid);
		goto done;
	}

	/* Need a tfp */
	lck_mtx_lock(tclass_lock);

	tfp = find_tfp_by_pid(pid);
	if (tfp != NULL) {
		so_tcdbg->so_tcdbg_tclass = tfp->tfp_class;
		error = 0;
	}
	lck_mtx_unlock(tclass_lock);
done:
	if (p != NULL)
		proc_rele(p);

	return (error);
}

int
get_pname_tclass(struct so_tcdbg *so_tcdbg)
{
	int error = EINVAL;
	struct tclass_for_proc *tfp;

	so_tcdbg->so_tcdbg_tclass = -1; /* Means not set */
	so_tcdbg->so_tcdbg_opportunistic = -1; /* Means not set */

	/* Need a tfp */
	lck_mtx_lock(tclass_lock);

	tfp = find_tfp_by_pname(so_tcdbg->so_tcdbg_pname);
	if (tfp != NULL) {
		so_tcdbg->so_tcdbg_tclass = tfp->tfp_class;
		error = 0;
	}
	lck_mtx_unlock(tclass_lock);

	return (error);
}

static int
delete_tclass_for_pid_pname(struct so_tcdbg *so_tcdbg)
{
	int error = EINVAL;
	pid_t pid = so_tcdbg->so_tcdbg_pid;
	struct tclass_for_proc *tfp = NULL;

	lck_mtx_lock(tclass_lock);

	if (pid != -1)
		tfp = find_tfp_by_pid(pid);
	else
		tfp = find_tfp_by_pname(so_tcdbg->so_tcdbg_pname);

	if (tfp != NULL) {
		free_tclass_for_proc(tfp);
		error = 0;
	}

	lck_mtx_unlock(tclass_lock);

	return (error);
}

/*
 * Setting options requires privileges
 */
__private_extern__ int
so_set_tcdbg(struct socket *so, struct so_tcdbg *so_tcdbg)
{
	int error = 0;

	if ((so->so_state & SS_PRIV) == 0)
		return (EPERM);

	socket_unlock(so, 0);

	switch (so_tcdbg->so_tcdbg_cmd) {
		case SO_TCDBG_PID:
			error = set_pid_tclass(so_tcdbg);
			break;

		case SO_TCDBG_PNAME:
			error = set_pname_tclass(so_tcdbg);
			break;

		case SO_TCDBG_PURGE:
			error = purge_tclass_for_proc();
			break;

		case SO_TCDBG_FLUSH:
			error = flush_tclass_for_proc();
			break;

		case SO_TCDBG_DELETE:
			error = delete_tclass_for_pid_pname(so_tcdbg);
			break;

		case SO_TCDBG_TCFLUSH_PID:
			error = flush_pid_tclass(so_tcdbg);
			break;

		default:
			error = EINVAL;
			break;
	}

	socket_lock(so, 0);

	return (error);
}

/*
 * Not required to be privileged to get
 */
__private_extern__ int
sogetopt_tcdbg(struct socket *so, struct sockopt *sopt)
{
	int error = 0;
	struct so_tcdbg so_tcdbg;
	void *buf = NULL;
	size_t len = sopt->sopt_valsize;

	error = sooptcopyin(sopt, &so_tcdbg, sizeof (struct so_tcdbg),
	    sizeof (struct so_tcdbg));
	if (error != 0)
		return (error);

	sopt->sopt_valsize = len;

	socket_unlock(so, 0);

	switch (so_tcdbg.so_tcdbg_cmd) {
		case SO_TCDBG_PID:
			error = get_pid_tclass(&so_tcdbg);
			break;

		case SO_TCDBG_PNAME:
			error = get_pname_tclass(&so_tcdbg);
			break;

		case SO_TCDBG_COUNT:
			lck_mtx_lock(tclass_lock);
			so_tcdbg.so_tcdbg_count = tfp_count;
			lck_mtx_unlock(tclass_lock);
			break;

		case SO_TCDBG_LIST: {
			struct tclass_for_proc *tfp;
			int n, alloc_count;
			struct so_tcdbg *ptr;

			lck_mtx_lock(tclass_lock);
			if ((alloc_count = tfp_count) == 0) {
				lck_mtx_unlock(tclass_lock);
				error = EINVAL;
				break;
			}
			len = alloc_count * sizeof (struct so_tcdbg);
			lck_mtx_unlock(tclass_lock);

			buf = _MALLOC(len, M_TEMP, M_WAITOK | M_ZERO);
			if (buf == NULL) {
				error = ENOBUFS;
				break;
			}

			lck_mtx_lock(tclass_lock);
			n = 0;
			ptr = (struct so_tcdbg *)buf;
			TAILQ_FOREACH(tfp, &tfp_head, tfp_link) {
				if (++n > alloc_count)
					break;
				if (tfp->tfp_pid != -1) {
					ptr->so_tcdbg_cmd = SO_TCDBG_PID;
					ptr->so_tcdbg_pid = tfp->tfp_pid;
				} else {
					ptr->so_tcdbg_cmd = SO_TCDBG_PNAME;
					ptr->so_tcdbg_pid = -1;
					strlcpy(ptr->so_tcdbg_pname,
					    tfp->tfp_pname,
					    sizeof (ptr->so_tcdbg_pname));
				}
				ptr->so_tcdbg_tclass = tfp->tfp_class;
				ptr++;
			}

			lck_mtx_unlock(tclass_lock);
			}
			break;

		default:
			error = EINVAL;
			break;
	}

	socket_lock(so, 0);

	if (error == 0) {
		if (buf == NULL) {
			error = sooptcopyout(sopt, &so_tcdbg,
			    sizeof (struct so_tcdbg));
		} else {
			error = sooptcopyout(sopt, buf, len);
			_FREE(buf, M_TEMP);
		}
	}
	return (error);
}


__private_extern__ int
so_set_traffic_class(struct socket *so, int optval)
{
	int error = 0;

	if (optval < SO_TC_BE || optval > SO_TC_CTL) {
		error = EINVAL;
	} else {
		switch (optval) {
		case _SO_TC_BK:
			optval = SO_TC_BK;
			break;
		case _SO_TC_VI:
			optval = SO_TC_VI;
			break;
		case _SO_TC_VO:
			optval = SO_TC_VO;
			break;
		default:
			if (!SO_VALID_TC(optval))
				error = EINVAL;
			break;
		}

		if (error == 0) {
			int oldval = so->so_traffic_class;

			VERIFY(SO_VALID_TC(optval));
			so->so_traffic_class = optval;

			if ((SOCK_DOM(so) == PF_INET ||
			    SOCK_DOM(so) == PF_INET6) &&
			    SOCK_TYPE(so) == SOCK_STREAM)
				set_tcp_stream_priority(so);

			if ((SOCK_DOM(so) == PF_INET ||
			    SOCK_DOM(so) == PF_INET6) &&
			    optval != oldval && (optval == SO_TC_BK_SYS ||
			    oldval == SO_TC_BK_SYS)) {
				/*
				 * If the app switches from BK_SYS to something
				 * else, resume the socket if it was suspended.
				 */
				if (oldval == SO_TC_BK_SYS)
					inp_reset_fc_state(so->so_pcb);

				SOTHROTTLELOG(("throttle[%d]: so 0x%llx "
				    "[%d,%d] opportunistic %s\n", so->last_pid,
				    (uint64_t)VM_KERNEL_ADDRPERM(so),
				    SOCK_DOM(so), SOCK_TYPE(so),
				    (optval == SO_TC_BK_SYS) ? "ON" : "OFF"));
			}
		}
	}
	return (error);
}

__private_extern__ void
so_set_default_traffic_class(struct socket *so)
{
	int sotc = -1;

	if (tfp_count > 0 &&
	    (SOCK_DOM(so) == PF_INET || SOCK_DOM(so) == PF_INET6)) {
		get_tclass_for_curr_proc(&sotc);
	}

	so->so_traffic_class = (sotc != -1) ? sotc : SO_TC_BE;
}

__private_extern__ int
so_set_opportunistic(struct socket *so, int optval)
{
	return (so_set_traffic_class(so, (optval == 0) ?
	    SO_TC_BE : SO_TC_BK_SYS));
}

__private_extern__ int
so_get_opportunistic(struct socket *so)
{
	return (so->so_traffic_class == SO_TC_BK_SYS);
}

__private_extern__ mbuf_svc_class_t
mbuf_service_class_from_control(struct mbuf *control)
{
	struct cmsghdr *cm;
	mbuf_svc_class_t msc = MBUF_SC_UNSPEC;

	for (cm = M_FIRST_CMSGHDR(control); cm != NULL;
	    cm = M_NXT_CMSGHDR(control, cm)) {
		int tc;

		if (cm->cmsg_len < sizeof (struct cmsghdr))
			break;

		if (cm->cmsg_level != SOL_SOCKET ||
		    cm->cmsg_type != SO_TRAFFIC_CLASS)
			continue;
		if (cm->cmsg_len != CMSG_LEN(sizeof (int)))
			continue;

		tc = *(int *)(void *)CMSG_DATA(cm);
		msc = so_tc2msc(tc);
		if (MBUF_VALID_SC(msc))
			break;
	}

	return (msc);
}

__private_extern__  int
dscp_code_from_mbuf_tclass(mbuf_traffic_class_t mtc)
{
	int dscp_code;

	switch (mtc) {
		default:
		case MBUF_TC_BE:
			dscp_code = 0;
			break;
		case MBUF_TC_BK:
			dscp_code = 0x08;
			break;
		case MBUF_TC_VI:
			dscp_code = 0x20;
			break;
		case MBUF_TC_VO:
			dscp_code = 0x30;
			break;
	}

	return (dscp_code);
}

__private_extern__ void
so_recv_data_stat(struct socket *so, struct mbuf *m, size_t off)
{
	uint32_t sotc = m_get_traffic_class(m);

	if (sotc >= SO_TC_STATS_MAX)
		sotc = SO_TC_BE;

	so->so_tc_stats[sotc].rxpackets += 1;
	so->so_tc_stats[sotc].rxbytes +=
	    ((m->m_flags & M_PKTHDR) ? m->m_pkthdr.len : 0) + off;
}

__private_extern__ void
so_inc_recv_data_stat(struct socket *so, size_t pkts, size_t bytes, uint32_t tc)
{
	if (tc >= SO_TC_STATS_MAX)
		tc = SO_TC_BE;

	so->so_tc_stats[tc].rxpackets += pkts;
	so->so_tc_stats[tc].rxbytes +=bytes;
}

static inline int
so_throttle_best_effort(struct socket *so, struct ifnet *ifp)
{
	u_int32_t uptime = net_uptime();
	return (soissrcbesteffort(so) &&
	    net_io_policy_throttle_best_effort == 1 &&
	    ifp->if_rt_sendts > 0 &&
	    (int)(uptime - ifp->if_rt_sendts) <= TCP_BG_SWITCH_TIME);
}
 
__private_extern__ void
set_tcp_stream_priority(struct socket *so)
{
	struct inpcb *inp = sotoinpcb(so);
	struct tcpcb *tp = intotcpcb(inp);
	struct ifnet *outifp;
	u_char old_cc = tp->tcp_cc_index;
	int recvbg = IS_TCP_RECV_BG(so);
	bool is_local = false, fg_active = false;
	u_int32_t uptime;

	VERIFY((SOCK_CHECK_DOM(so, PF_INET) 
	    || SOCK_CHECK_DOM(so, PF_INET6))
	    && SOCK_CHECK_TYPE(so, SOCK_STREAM)
	    && SOCK_CHECK_PROTO(so, IPPROTO_TCP));

	/* Return if the socket is in a terminal state */	
	if (inp->inp_state == INPCB_STATE_DEAD)
		return;

	outifp = inp->inp_last_outifp;
	uptime = net_uptime();

	/*
	 * If the socket was marked as a background socket or if the
	 * traffic class is set to background with traffic class socket
	 * option then make both send and recv side of the stream to be
	 * background. The variable sotcdb which can be set with sysctl
	 * is used to disable these settings for testing.
	 */
	if (outifp == NULL || (outifp->if_flags & IFF_LOOPBACK))
		is_local = true;

	/* Check if there has been recent foreground activity */
	if (outifp != NULL) {
		/*
		 * If the traffic source is background, check if
		 * if it can be switched to foreground. This can 
		 * happen when there is no indication of foreground
		 * activity.
		 */
		if (soissrcbackground(so) && 
		    ((outifp->if_fg_sendts > 0 &&
		    (int)(uptime - outifp->if_fg_sendts) <= 
		    TCP_BG_SWITCH_TIME) || net_io_policy_throttled))
			fg_active = true;

		/*
		 * The traffic source is best-effort -- check if
		 * the policy to throttle best effort is enabled
		 * and there was realtime activity on this
		 * interface recently. If this is true, enable
		 * algorithms that respond to increased latency
		 * on best-effort traffic.
		 */ 
		if (so_throttle_best_effort(so, outifp))
			fg_active = true;
	}

	/*
	 * System initiated background traffic like cloud uploads should
	 * always use background delay sensitive algorithms. This will
	 * make the stream more responsive to other streams on the user's
	 * network and it will minimize latency induced.
	 */
	if (fg_active || IS_SO_TC_BACKGROUNDSYSTEM(so->so_traffic_class)) {
		/*
		 * If the interface that the connection is using is
		 * loopback, do not use background congestion
		 * control algorithm.
		 *
		 * If there has been recent foreground activity or if 
		 * there was an indication that a foreground application 
		 * is going to use networking (net_io_policy_throttled),
		 * switch the backgroung streams to use background 
		 * congestion control algorithm. Otherwise, even background
		 * flows can move into foreground.
		 */
		if ((sotcdb & SOTCDB_NO_SENDTCPBG) != 0 || is_local ||
		    !IS_SO_TC_BACKGROUNDSYSTEM(so->so_traffic_class)) {
			if (old_cc == TCP_CC_ALGO_BACKGROUND_INDEX)
				tcp_set_foreground_cc(so);
		} else {
			if (old_cc != TCP_CC_ALGO_BACKGROUND_INDEX)
				tcp_set_background_cc(so);
		}

		/* Set receive side background flags */
		if ((sotcdb & SOTCDB_NO_RECVTCPBG) != 0 || is_local ||
		    !IS_SO_TC_BACKGROUNDSYSTEM(so->so_traffic_class)) {
			tcp_clear_recv_bg(so);
		} else {
			tcp_set_recv_bg(so);
		}
	} else {
		tcp_clear_recv_bg(so);
		if (old_cc == TCP_CC_ALGO_BACKGROUND_INDEX)
			tcp_set_foreground_cc(so);
	}

	if (old_cc != tp->tcp_cc_index || recvbg != IS_TCP_RECV_BG(so)) {
		SOTHROTTLELOG(("throttle[%d]: so 0x%llx [%d,%d] TCP %s send; "
		   "%s recv\n", so->last_pid, (uint64_t)VM_KERNEL_ADDRPERM(so),
		   SOCK_DOM(so), SOCK_TYPE(so),
		   (tp->tcp_cc_index == TCP_CC_ALGO_BACKGROUND_INDEX) ?
		   "background" : "foreground",
		   IS_TCP_RECV_BG(so) ? "background" : "foreground"));
	}
}

/*
 * Set traffic class to an IPv4 or IPv6 packet
 * - mark the mbuf
 * - set the DSCP code following the WMM mapping
 */
__private_extern__ void
set_packet_service_class(struct mbuf *m, struct socket *so,
    mbuf_svc_class_t in_msc, u_int32_t flags)
{
	mbuf_svc_class_t msc = MBUF_SC_BE;	   /* Best effort by default */
	struct inpcb *inp = sotoinpcb(so); /* in6pcb and inpcb are the same */
	struct ip *ip = mtod(m, struct ip *);
#if INET6
	struct ip6_hdr *ip6 = mtod(m, struct ip6_hdr *);
#endif /* INET6 */
	int isipv6 = ((flags & PKT_SCF_IPV6) != 0) ? 1 : 0; 

	if (!(m->m_flags & M_PKTHDR))
		return;

	/*
	 * Here is the precedence:
	 * 1) TRAFFIC_MGT_SO_BACKGROUND trumps all
	 * 2) Traffic class passed via ancillary data to sendmsdg(2)
	 * 3) Traffic class socket option last
	 */
	if (in_msc != MBUF_SC_UNSPEC) {
		if (in_msc >= MBUF_SC_BE && in_msc <= MBUF_SC_CTL)
			msc = in_msc;
	} else {
		VERIFY(SO_VALID_TC(so->so_traffic_class));
		msc = so_tc2msc(so->so_traffic_class);
		/* Assert because tc must have been valid */
		VERIFY(MBUF_VALID_SC(msc));
	}

	/*
	 * If TRAFFIC_MGT_SO_BACKGROUND is set or policy to throttle
	 * best effort is set, depress the priority.
	 */
	if (!IS_MBUF_SC_BACKGROUND(msc) && soisthrottled(so))
		msc = MBUF_SC_BK;

	if (IS_MBUF_SC_BESTEFFORT(msc) && inp->inp_last_outifp != NULL &&
	    so_throttle_best_effort(so, inp->inp_last_outifp))
		msc = MBUF_SC_BK;

	if (soissrcbackground(so))
		m->m_pkthdr.pkt_flags |= PKTF_SO_BACKGROUND;

	if (soissrcrealtime(so) || IS_MBUF_SC_REALTIME(msc))
		m->m_pkthdr.pkt_flags |= PKTF_SO_REALTIME;
	/*
	 * Set the traffic class in the mbuf packet header svc field
	 */
	if (sotcdb & SOTCDB_NO_MTC)
		goto no_mbtc;

	/* Elevate service class if the packet is a pure TCP ACK.
	 * We can do this only when the flow is not a background
	 * flow and the outgoing interface supports 
	 * transmit-start model.
	 */
	if (!IS_MBUF_SC_BACKGROUND(msc) && (flags & PKT_SCF_TCP_ACK))
		msc = MBUF_SC_CTL;

	(void) m_set_service_class(m, msc);

	/*
	 * Set the privileged traffic auxiliary flag if applicable, 
	 * or clear it.
	 */
	if (!(sotcdb & SOTCDB_NO_PRIVILEGED) && soisprivilegedtraffic(so) &&
	    msc != MBUF_SC_UNSPEC)
		m->m_pkthdr.pkt_flags |= PKTF_PRIO_PRIVILEGED;
	else
		m->m_pkthdr.pkt_flags &= ~PKTF_PRIO_PRIVILEGED;

no_mbtc:
	/*
	 * Quick exit when best effort
	 */
	if (msc == MBUF_SC_BE)
		goto no_dscp;

	/*
	 * The default behavior is for the networking stack to not set the
	 * DSCP code, based on SOTCDB_NO_DSCP being set.  If the flag is
	 * cleared, set the DSCP code in IPv4 or IPv6 header only for local
	 * traffic, if it is not already set.  <rdar://problem/11277343>
	 */
	if (sotcdb & SOTCDB_NO_DSCP)
		goto no_dscp;

	/*
	 * Test if a IP TOS or IPV6 TCLASS has already been set
	 * on the socket or the raw packet.
	 */
	if (!(sotcdb & SOTCDB_NO_DSCPTST)) {
#if INET6
		if (isipv6) {
			if ((so->so_type == SOCK_RAW &&
			    (ip6->ip6_flow & htonl(0xff << 20)) != 0) ||
			    (inp->in6p_outputopts &&
			    inp->in6p_outputopts->ip6po_tclass != -1))
				goto no_dscp;
		} else
#endif /* INET6 */
		if ((so->so_type == SOCK_RAW &&
		    (inp->inp_flags & INP_HDRINCL)) ||
		    inp->inp_ip_tos != 0)
			goto no_dscp;
	}

	/*
	 * Test if destination is local
	 */
	if (!(sotcdb & SOTCDB_NO_LCLTST)) {
		int islocal = 0;
		struct rtentry *rt = inp->inp_route.ro_rt;

		if (so->so_type == SOCK_STREAM) {
			if (intotcpcb(inp)->t_flags & TF_LOCAL)
				islocal = 1;
		} else if (rt != NULL &&
		    (rt->rt_gateway->sa_family == AF_LINK ||
		    (rt->rt_ifp->if_flags & (IFF_LOOPBACK|IFF_POINTOPOINT)))) {
			if (!(rt->rt_ifp->if_flags & IFF_POINTOPOINT))
				islocal = 1;
		} else
#if INET6
		if (isipv6 && in6addr_local(&ip6->ip6_dst)) {
			islocal = 1;
		} else
#endif /* INET6 */
		if (inaddr_local(ip->ip_dst)) {
			islocal = 1;
		}
		if (islocal == 0)
			goto no_dscp;
	}

#if INET6
	if (isipv6)
		ip6->ip6_flow |= htonl(dscp_code_from_mbuf_tclass(
		    m_get_traffic_class(m)) << 20);
	else
#endif /* INET6 */
		ip->ip_tos |= dscp_code_from_mbuf_tclass(
		    m_get_traffic_class(m)) << 2;

no_dscp:
	/*
	 * For TCP with background traffic class switch CC algo based on sysctl
	 */
	if (so->so_type == SOCK_STREAM)
		set_tcp_stream_priority(so);

	so_tc_update_stats(m, so, msc);
}

__private_extern__ void
so_tc_update_stats(struct mbuf *m, struct socket *so, mbuf_svc_class_t msc)
{
	mbuf_traffic_class_t mtc;

	/*
	 * Assume socket and mbuf traffic class values are the same
	 * Also assume the socket lock is held.  Note that the stats
	 * at the socket layer are reduced down to the legacy traffic
	 * classes; we could/should potentially expand so_tc_stats[].
	 */
	mtc = MBUF_SC2TC(msc);
	VERIFY(mtc < SO_TC_STATS_MAX);
	so->so_tc_stats[mtc].txpackets += 1;
	so->so_tc_stats[mtc].txbytes += m->m_pkthdr.len;
}

__private_extern__ void
socket_tclass_init(void)
{
        _CASSERT(_SO_TC_MAX == SO_TC_STATS_MAX);

	tclass_lck_grp_attr = lck_grp_attr_alloc_init();
	tclass_lck_grp = lck_grp_alloc_init("tclass", tclass_lck_grp_attr);
	tclass_lck_attr = lck_attr_alloc_init();
	lck_mtx_init(tclass_lock, tclass_lck_grp, tclass_lck_attr);
}

__private_extern__ mbuf_svc_class_t
so_tc2msc(int tc)
{
	mbuf_svc_class_t msc;

	switch (tc) {
	case SO_TC_BK_SYS:
		msc = MBUF_SC_BK_SYS;
		break;
	case SO_TC_BK:
	case _SO_TC_BK:
		msc = MBUF_SC_BK;
		break;
	case SO_TC_BE:
		msc = MBUF_SC_BE;
		break;
	case SO_TC_RD:
		msc = MBUF_SC_RD;
		break;
	case SO_TC_OAM:
		msc = MBUF_SC_OAM;
		break;
	case SO_TC_AV:
		msc = MBUF_SC_AV;
		break;
	case SO_TC_RV:
		msc = MBUF_SC_RV;
		break;
	case SO_TC_VI:
	case _SO_TC_VI:
		msc = MBUF_SC_VI;
		break;
	case SO_TC_VO:
	case _SO_TC_VO:
		msc = MBUF_SC_VO;
		break;
	case SO_TC_CTL:
		msc = MBUF_SC_CTL;
		break;
	case SO_TC_ALL:
	default:
		msc = MBUF_SC_UNSPEC;
		break;
	}

	return (msc);
}

__private_extern__ int
so_svc2tc(mbuf_svc_class_t svc)
{
	switch (svc) {
	case MBUF_SC_UNSPEC:
		return SO_TC_BE;
	case MBUF_SC_BK_SYS:
		return SO_TC_BK_SYS;
	case MBUF_SC_BK:
		return SO_TC_BK;
	case MBUF_SC_BE:
		return SO_TC_BE;
	case MBUF_SC_RD:
		return SO_TC_RD;
	case MBUF_SC_OAM:
		return SO_TC_OAM;
	case MBUF_SC_AV:
		return SO_TC_AV;
	case MBUF_SC_RV:
		return SO_TC_RV;
	case MBUF_SC_VI:
		return SO_TC_VI;
	case MBUF_SC_VO:
		return SO_TC_VO;
	case MBUF_SC_CTL:
		return SO_TC_CTL;
	default:
		return SO_TC_BE;
	}
}

/*
 * LRO is turned on for AV streaming class.
 */
void
so_set_lro(struct socket *so, int optval)
{
	if (optval == SO_TC_AV) {
		so->so_flags |= SOF_USELRO;
	} else {
		if (so->so_flags & SOF_USELRO) {
			/* transition to non LRO class */
			so->so_flags &= ~SOF_USELRO;
			struct inpcb *inp = sotoinpcb(so);
			struct tcpcb *tp = NULL;
			if (inp) {
				tp = intotcpcb(inp);
				if (tp && (tp->t_flagsext & TF_LRO_OFFLOADED)) {
					tcp_lro_remove_state(inp->inp_laddr,
						inp->inp_faddr,
						inp->inp_lport, 
						inp->inp_fport);
					tp->t_flagsext &= ~TF_LRO_OFFLOADED;	
				}
			}
		}
	}
}

