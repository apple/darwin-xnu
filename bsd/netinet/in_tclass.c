/*
 * Copyright (c) 2009-2011 Apple Inc. All rights reserved.
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

extern char *proc_name_address(void *p);

static int tfp_count = 0;

static TAILQ_HEAD(, tclass_for_proc) tfp_head = TAILQ_HEAD_INITIALIZER(tfp_head);

struct tclass_for_proc {
	TAILQ_ENTRY(tclass_for_proc)	tfp_link;
	int 							tfp_class;
	pid_t							tfp_pid;
	char							tfp_pname[MAXCOMLEN + 1];
};

extern void tcp_set_background_cc(struct socket *);
extern void tcp_set_foreground_cc(struct socket *);

int dscp_code_from_mbuf_tclass(int );

static int get_pid_tclass(pid_t , int *);
static int get_pname_tclass(const char * , int *);
static int set_pid_tclass(pid_t , int );
static int set_pname_tclass(const char * , int );
static int purge_tclass_for_proc(void);
static int flush_tclass_for_proc(void);


static lck_grp_attr_t *tclass_lck_grp_attr = NULL;  /* mutex group attributes */
static lck_grp_t *tclass_lck_grp = NULL;            /* mutex group definition */
static lck_attr_t *tclass_lck_attr = NULL;          /* mutex attributes */
static lck_mtx_t *tclass_lock = NULL;

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
	return tfp;
}

/*
 * Must be called with tclass_lock held
 */
static struct tclass_for_proc *
find_tfp_by_pname(const char *pname)
{
	struct tclass_for_proc *tfp;
	
	TAILQ_FOREACH(tfp, &tfp_head, tfp_link) {
		if (strncmp(pname, tfp->tfp_pname, sizeof(tfp->tfp_pname)) == 0)
			break;
	}
	return tfp;
}

static int
get_tclass_for_curr_proc(void)
{
	struct tclass_for_proc *tfp;
	int sotc = SO_TC_BE;
	proc_t p = current_proc();	/* Not ref counted */
	pid_t pid = proc_pid(p);
	char *pname = proc_name_address(p);
	
	lck_mtx_lock(tclass_lock);
	
	TAILQ_FOREACH(tfp, &tfp_head, tfp_link) {
		if ((tfp->tfp_pid == pid) ||
			(tfp->tfp_pid == -1 && strncmp(pname, tfp->tfp_pname, sizeof(tfp->tfp_pname)) == 0)) {
			sotc = tfp->tfp_class;
			break;
		} 
	}

	lck_mtx_unlock(tclass_lock);

	return sotc;
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
	
	return error;
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
		
	return error;

}

/*
 * Must be called with tclass_lock held
 */
static struct tclass_for_proc *
alloc_tclass_for_proc(pid_t pid, const char *pname, int tclass)
{
	struct tclass_for_proc *tfp;
	
	if (pid == -1 && pname == NULL)
		return NULL;

	tfp = _MALLOC(sizeof(struct tclass_for_proc), M_TEMP, M_NOWAIT | M_ZERO);
	if (tfp == NULL)
		return NULL;
	
	tfp->tfp_pid = pid;
	tfp->tfp_class = tclass;
	/*
	 * Add per pid entries before per proc name so we can find 
	 * a specific instance of a process before the general name base entry.
	 */
	if (pid != -1) {
		TAILQ_INSERT_HEAD(&tfp_head, tfp, tfp_link);
	} else {
		strlcpy(tfp->tfp_pname, pname, sizeof(tfp->tfp_pname));
		TAILQ_INSERT_TAIL(&tfp_head, tfp, tfp_link);
	}
	
	tfp_count++;

	return tfp;
}

/*
 * -1 for tclass means to remove the entry
 */
int 
set_pid_tclass(pid_t pid, int tclass)
{
	int error = EINVAL;
	proc_t p = NULL;
	struct filedesc *fdp;
	struct fileproc *fp;
	struct tclass_for_proc *tfp;
	int i;

	p = proc_find(pid);
	if (p == NULL) {
		printf("set_pid_tclass proc_find(%d) \n", pid);
		goto done;
	}
	
	/* Need a tfp */
	lck_mtx_lock(tclass_lock);
	
	tfp = find_tfp_by_pid(pid);
	if (tclass == -1) {
		if (tfp != NULL) {
			free_tclass_for_proc(tfp);
			error = 0;
		}
		lck_mtx_unlock(tclass_lock);
		goto done;
	} else {
		if (tfp == NULL) {
			tfp = alloc_tclass_for_proc(pid, NULL, tclass);
			if (tfp == NULL) {
				lck_mtx_unlock(tclass_lock);
				error = ENOBUFS;
				goto done;
			}
		} else {
			tfp->tfp_class = tclass;
		}
	}
	lck_mtx_unlock(tclass_lock);

	if (tfp != NULL) {
		proc_fdlock(p);
		
		fdp = p->p_fd;
		for (i = 0; i < fdp->fd_nfiles; i++) {
			struct socket *so;
			
			fp = fdp->fd_ofiles[i];
			if (fp == NULL || (fdp->fd_ofileflags[i] & UF_RESERVED) != 0 ||
				fp->f_fglob->fg_type != DTYPE_SOCKET)
				continue;
			
			so = (struct socket *)fp->f_fglob->fg_data;
			if (so->so_proto->pr_domain->dom_family != AF_INET && 
				so->so_proto->pr_domain->dom_family != AF_INET6)
				continue;
			socket_lock(so, 1);
			error = so_set_traffic_class(so, tclass != -1 ? tclass : SO_TC_BE);
			socket_unlock(so, 1);
			if (error != 0) {
				printf("set_pid_tclass so_set_traffic_class(%p, %d) failed %d\n", so, tclass, error);
				error = 0;
			}
		}
		
		proc_fdunlock(p);
	}
	
	error = 0;	
done:
	if (p != NULL)
		proc_rele(p);
	
	return error;
}

int 
set_pname_tclass(const char *pname, int tclass)
{
	int error = EINVAL;
	struct tclass_for_proc *tfp;

	lck_mtx_lock(tclass_lock);
	
	tfp = find_tfp_by_pname(pname);
	if (tclass == -1) {
		if (tfp != NULL)
			free_tclass_for_proc(tfp);
	} else {
		if (tfp == NULL) {
			tfp = alloc_tclass_for_proc(-1, pname, tclass);
			if (tfp == NULL) {
				lck_mtx_unlock(tclass_lock);
				error = ENOBUFS;
				goto done;
			}
		} else {
			tfp->tfp_class = tclass;
		}
	}
	lck_mtx_unlock(tclass_lock);
	
	error = 0;	
done:
	
	return error;
}

int 
get_pid_tclass(pid_t pid, int *tclass)
{
	int error = EINVAL;
	proc_t p = NULL;
	struct tclass_for_proc *tfp;
	
	*tclass = -1; /* Means not set */

	p = proc_find(pid);
	if (p == NULL) {
		printf("get_pid_tclass proc_find(%d) \n", pid);
		goto done;
	}
	
	/* Need a tfp */
	lck_mtx_lock(tclass_lock);
	
	tfp = find_tfp_by_pid(pid);
	if (tfp != NULL) {
		*tclass = tfp->tfp_class ;
		error = 0;
	}
	lck_mtx_unlock(tclass_lock);
done:
	if (p != NULL)
		proc_rele(p);
	
	return error;
}

int 
get_pname_tclass(const char *pname, int *tclass)
{
	int error = EINVAL;
	struct tclass_for_proc *tfp;
	
	*tclass = -1; /* Means not set */

	/* Need a tfp */
	lck_mtx_lock(tclass_lock);
	
	tfp = find_tfp_by_pname(pname);
	if (tfp != NULL) {
		*tclass = tfp->tfp_class ;
		error = 0;
	}
	lck_mtx_unlock(tclass_lock);
	
	return error;
}



/*
 * Setting options requires privileges
 */
__private_extern__ int 
so_set_tcdbg(struct socket *so, struct so_tcdbg *so_tcdbg)
{
	int error = 0;
	
	if ((so->so_state & SS_PRIV) == 0)
		return EPERM;

	socket_unlock(so, 0);

	switch (so_tcdbg->so_tcdbg_cmd) {
		case SO_TCDBG_PID:
			error = set_pid_tclass(so_tcdbg->so_tcdbg_pid, so_tcdbg->so_tcdbg_tclass);
			break;
		
		case SO_TCDBG_PNAME:
			error = set_pname_tclass(so_tcdbg->so_tcdbg_pname, so_tcdbg->so_tcdbg_tclass);
			break;
		
		case SO_TCDBG_PURGE:
			error = purge_tclass_for_proc();
			break;
		
		case SO_TCDBG_FLUSH:
			error = flush_tclass_for_proc();
			break;
		
		default:
			error = EINVAL;
			break;
		
	}

	socket_lock(so, 0);

	return error;
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

	error = sooptcopyin(sopt, &so_tcdbg, sizeof(struct so_tcdbg), sizeof(struct so_tcdbg));
	if (error != 0)
		return error;
	
	sopt->sopt_valsize = len;
	
	socket_unlock(so, 0);

	switch (so_tcdbg.so_tcdbg_cmd) {
		case SO_TCDBG_PID:
			error = get_pid_tclass(so_tcdbg.so_tcdbg_pid, &so_tcdbg.so_tcdbg_tclass);
			break;
		
		case SO_TCDBG_PNAME:
			error = get_pname_tclass(so_tcdbg.so_tcdbg_pname, &so_tcdbg.so_tcdbg_tclass);
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
			len = alloc_count * sizeof(struct so_tcdbg);
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
					strlcpy(ptr->so_tcdbg_pname, tfp->tfp_pname, sizeof(ptr->so_tcdbg_pname));
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
			error = sooptcopyout(sopt, &so_tcdbg, sizeof(struct so_tcdbg));
		} else {
			error = sooptcopyout(sopt, buf, len);
			_FREE(buf, M_TEMP);
		}
	}
	return error;
}


__private_extern__ int
so_set_traffic_class(struct socket *so, int optval)
{
	int error = 0;
	
	if (optval < SO_TC_BE || optval > SO_TC_VO) {
		error = EINVAL;
	} else {
		so->so_traffic_class = optval;
	
		if ((INP_SOCKAF(so) == AF_INET || INP_SOCKAF(so) == AF_INET6) && 
			INP_SOCKTYPE(so) == SOCK_STREAM) {
			set_tcp_stream_priority(so);
		}
	}
	return error;
}

__private_extern__ void
so_set_default_traffic_class(struct socket *so)
{
	int sotc = SO_TC_BE;

	if (tfp_count > 0 && (INP_SOCKAF(so) == AF_INET || INP_SOCKAF(so) == AF_INET6)) {
		sotc = get_tclass_for_curr_proc();
	}
	
	so->so_traffic_class = sotc;
	
	return;
}


__private_extern__ int
mbuf_traffic_class_from_control(struct mbuf *control)
{
	struct cmsghdr *cm;
	
	for (cm = M_FIRST_CMSGHDR(control); 
		 cm != NULL; 
		 cm = M_NXT_CMSGHDR(control, cm)) {
		int tc;

		if (cm->cmsg_len < sizeof(struct cmsghdr))
			break;
		
		if (cm->cmsg_level != SOL_SOCKET ||
			cm->cmsg_type != SO_TRAFFIC_CLASS)
			continue;
		if (cm->cmsg_len != CMSG_LEN(sizeof(int)))
			continue;
		
		tc = *(int *)CMSG_DATA(cm);
		
		switch (tc) {
			case SO_TC_BE:
				return MBUF_TC_BE;
			case SO_TC_BK:
				return MBUF_TC_BK;
			case SO_TC_VI:
				return MBUF_TC_VI;
			case SO_TC_VO:
				return MBUF_TC_VO;
			default:
				break;
		}
	}
	
	return MBUF_TC_UNSPEC;
}

__private_extern__  int
dscp_code_from_mbuf_tclass(int mtc)
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
	
	return dscp_code;
}

__private_extern__ void
so_recv_data_stat(struct socket *so, struct mbuf *m, size_t off)
{
	uint32_t sotc = m->m_pkthdr.prio;

	if (sotc >= SO_TC_STATS_MAX)
		sotc = SO_TC_BE;
	
	so->so_tc_stats[sotc].rxpackets += 1;
	so->so_tc_stats[sotc].rxbytes += ((m->m_flags & M_PKTHDR) ? m->m_pkthdr.len : 0) + off;

	return;
}

__private_extern__ void
set_tcp_stream_priority(struct socket *so)
{
	struct tcpcb *tp = intotcpcb(sotoinpcb(so));

	/* If the socket was marked as a background socket or if the
	 * traffic class is set to background with traffic class socket 
	 * option then make both send and recv side of the stream to be 
	 * background. The variable sotcdb which can be set with sysctl 
	 * is used to disable these settings for testing.
	 */
	if (soisbackground(so) || so->so_traffic_class == SO_TC_BK) {
		if ((sotcdb & SOTCDB_NO_SENDTCPBG) != 0) {
			if (tp->tcp_cc_index == TCP_CC_ALGO_BACKGROUND_INDEX)
				tcp_set_foreground_cc(so);
		} else {
			if (tp->tcp_cc_index != TCP_CC_ALGO_BACKGROUND_INDEX)
				tcp_set_background_cc(so);
		}
		
		/* Set receive side background flags */
		if ((sotcdb & SOTCDB_NO_RECVTCPBG) != 0) {
			so->so_traffic_mgt_flags &= ~(TRAFFIC_MGT_TCP_RECVBG);
		} else {
			so->so_traffic_mgt_flags |= TRAFFIC_MGT_TCP_RECVBG;
		}
	} else {
		so->so_traffic_mgt_flags &= ~(TRAFFIC_MGT_TCP_RECVBG);
		if (tp->tcp_cc_index == TCP_CC_ALGO_BACKGROUND_INDEX)
			tcp_set_foreground_cc(so);
	}
	return;
}

/*
 * Set traffic class to an IPv4 or IPv6 packet
 * - mark the mbuf
 * - set the DSCP code following the WMM mapping
 */
__private_extern__ void
set_packet_tclass(struct mbuf *m, struct socket *so, int in_mtc, int isipv6)
{
	int mtc = MBUF_TC_BE; /* Best effort by default */
	struct inpcb *inp = sotoinpcb(so);	 /* in6pcb and inpcb are the same */
	struct ip *ip = mtod(m, struct ip *);
#if INET6
	struct ip6_hdr *ip6 = mtod(m, struct ip6_hdr *);
#endif /* INET6 */
	
	if (!(m->m_flags & M_PKTHDR))
		return;
	
	/* 
	 * Here is the precedence:
	 * 1) TRAFFIC_MGT_SO_BACKGROUND trumps all
	 * 2) Traffic class passed via ancillary data to sendmsdg(2)
	 * 3) Traffic class socket option last
	 */
	if (soisbackground(so)) {
		mtc = MBUF_TC_BK;
	} else if (in_mtc != MBUF_TC_UNSPEC) {
		if (in_mtc >= MBUF_TC_BE && in_mtc <= MBUF_TC_VO)
			mtc = in_mtc;
	} else {
		switch (so->so_traffic_class) {
			case SO_TC_BE:
				mtc = MBUF_TC_BE;
				break;
			case SO_TC_BK:
				mtc = MBUF_TC_BK;
				break;
			case SO_TC_VI:
				mtc = MBUF_TC_VI;
				break;
			case SO_TC_VO:
				mtc = MBUF_TC_VO;
				break;
			default:
				break;
		}
	}
	
	/*
	 * Set the traffic class in the mbuf packet header prio field
	 */
	if ((sotcdb & SOTCDB_NO_MTC))
		goto no_mbtc;
	m->m_pkthdr.prio = mtc;
	
no_mbtc:
	/*
         * Quick exit when best effort
	 */
	if (mtc == MBUF_TC_BE)
		goto no_dscp;
	/*
	 * Now let set the DSCP code in IPv4 or IPv6 header
	 * By default do this only for local traffic if a code is not already set
	 */
	if ((sotcdb & SOTCDB_NO_DSCP))
		goto no_dscp;
		
	/*
	 * Test if a IP TOS or IPV6 TCLASS has already been set on the socket or the raw packet
	 */
	if ((sotcdb & SOTCDB_NO_DSCPTST) == 0) {
#if INET6
		if (isipv6) 
		{
			if ((so->so_type == SOCK_RAW && (ip6->ip6_flow & htonl(0xff << 20)) != 0) ||
			    (inp->in6p_outputopts && inp->in6p_outputopts->ip6po_tclass != -1))
				goto no_dscp;
		} 
		else 
#endif /* INET6 */
		{
			if ((so->so_type == SOCK_RAW && (inp->inp_flags & INP_HDRINCL)) ||
				inp->inp_ip_tos != 0)
				goto no_dscp;
		}
	}
	
	/*
	 * Test if destination is local
	 */
	if ((sotcdb & SOTCDB_NO_LCLTST) == 0) {
		int islocal = 0;
		struct route *ro = &inp->inp_route;

		if (so->so_type == SOCK_STREAM) {
			struct tcpcb *tp = intotcpcb(inp);
			
			if ((tp->t_flags & TF_LOCAL))
				islocal = 1;
		}
		else
#if INET6
		if (isipv6) 
		{
			if ((ro != NULL && ro->ro_rt != NULL &&
				 (ro->ro_rt->rt_gateway->sa_family == AF_LINK ||
				  (ro->ro_rt->rt_ifp->if_flags & IFF_LOOPBACK))) ||
				 in6addr_local(&ip6->ip6_dst))
				islocal = 1;
		} 
		else
#endif /* INET6 */
		{
			if ((ro != NULL && ro->ro_rt != NULL && 
				 (ro->ro_rt->rt_gateway->sa_family == AF_LINK ||
				  (ro->ro_rt->rt_ifp->if_flags & IFF_LOOPBACK))) ||
				 inaddr_local(ip->ip_dst))
				islocal = 1;
		}
		if (islocal == 0)
			goto no_dscp;
	}

#if INET6
	if (isipv6)
		ip6->ip6_flow |=
			htonl(dscp_code_from_mbuf_tclass(m->m_pkthdr.prio) << 20);
	else
#endif /* INET6 */
		ip->ip_tos |= dscp_code_from_mbuf_tclass(m->m_pkthdr.prio) << 2;
	
no_dscp:
	/*
	 * For TCP with background traffic class switch CC algo based on sysctl
	 */
	if (so->so_type == SOCK_STREAM) {
		set_tcp_stream_priority(so);
	}
	
	/*
	 * Assume socket and mbuf traffic class values are the same
	 * Also assume the socket lock is held
	 */
	so->so_tc_stats[mtc].txpackets += 1;
	so->so_tc_stats[mtc].txbytes += m->m_pkthdr.len;
	
	return;
}

__private_extern__ void
socket_tclass_init(void)
{
	tclass_lck_grp_attr = lck_grp_attr_alloc_init();
	tclass_lck_grp = lck_grp_alloc_init("tclass", tclass_lck_grp_attr);
	tclass_lck_attr = lck_attr_alloc_init();
	if ((tclass_lock = lck_mtx_alloc_init(tclass_lck_grp, tclass_lck_attr)) == NULL) {
			panic("failed to allocate memory for tclass\n");
	}
}


