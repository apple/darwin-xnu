/*
 * Copyright (c) 1999-2008 Apple Computer, Inc. All rights reserved.
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
 * Kernel Control domain - allows control connections to
 *  and to read/write data.
 *
 * Vincent Lubet, 040506
 * Christophe Allie, 010928
 * Justin C. Walker, 990319
 */

#include <sys/types.h>
#include <sys/param.h>
#include <sys/systm.h>
#include <sys/syslog.h>
#include <sys/socket.h>
#include <sys/socketvar.h>
#include <sys/protosw.h>
#include <sys/domain.h>
#include <sys/malloc.h>
#include <sys/mbuf.h>
#include <sys/sys_domain.h>
#include <sys/kern_event.h>
#include <sys/kern_control.h>
#include <sys/kauth.h>
#include <net/if_var.h>

#include <mach/vm_types.h>

#include <kern/thread.h>

/*
 * Definitions and vars for we support
 */

#define CTL_SENDSIZE	(2 * 1024)	/* default buffer size */
#define CTL_RECVSIZE 	(8 * 1024)	/* default buffer size */

/*
 * Definitions and vars for we support
 */

static u_int32_t		ctl_maxunit = 65536;
static lck_grp_attr_t	*ctl_lck_grp_attr = 0;
static lck_attr_t		*ctl_lck_attr = 0;
static lck_grp_t		*ctl_lck_grp = 0;
static lck_mtx_t 		*ctl_mtx;


/* all the controllers are chained */
TAILQ_HEAD(kctl_list, kctl) 	ctl_head;

static int ctl_attach(struct socket *, int, struct proc *);
static int ctl_detach(struct socket *);
static int ctl_sofreelastref(struct socket *so);
static int ctl_connect(struct socket *, struct sockaddr *, struct proc *);
static int ctl_disconnect(struct socket *);
static int ctl_ioctl(struct socket *so, u_long cmd, caddr_t data,
                  struct ifnet *ifp, struct proc *p);
static int ctl_send(struct socket *, int, struct mbuf *,
            struct sockaddr *, struct mbuf *, struct proc *);
static int ctl_ctloutput(struct socket *, struct sockopt *);
static int ctl_peeraddr(struct socket *so, struct sockaddr **nam);

static struct kctl *ctl_find_by_name(const char *);
static struct kctl *ctl_find_by_id_unit(u_int32_t id, u_int32_t unit);

static struct ctl_cb *kcb_find(struct kctl *, u_int32_t unit);
static void ctl_post_msg(u_int32_t event_code, u_int32_t id);

static int ctl_lock(struct socket *, int, void *);
static int ctl_unlock(struct socket *, int, void *);
static lck_mtx_t * ctl_getlock(struct socket *, int);

static struct pr_usrreqs ctl_usrreqs =
{
	pru_abort_notsupp, pru_accept_notsupp, ctl_attach, pru_bind_notsupp,
	ctl_connect, pru_connect2_notsupp, ctl_ioctl, ctl_detach,
	ctl_disconnect, pru_listen_notsupp, ctl_peeraddr,
	pru_rcvd_notsupp, pru_rcvoob_notsupp, ctl_send,
	pru_sense_null, pru_shutdown_notsupp, pru_sockaddr_notsupp,
	sosend, soreceive, pru_sopoll_notsupp
};

static struct protosw kctlswk_dgram =
{
	SOCK_DGRAM, &systemdomain, SYSPROTO_CONTROL, 
	PR_ATOMIC|PR_CONNREQUIRED|PR_PCBLOCK,
	NULL, NULL, NULL, ctl_ctloutput,
	NULL, NULL,
	NULL, NULL, NULL, NULL, &ctl_usrreqs,
	ctl_lock, ctl_unlock, ctl_getlock, { 0, 0 } , 0, { 0 }
};

static struct protosw kctlswk_stream =
{
	SOCK_STREAM, &systemdomain, SYSPROTO_CONTROL, 
	PR_CONNREQUIRED|PR_PCBLOCK,
	NULL, NULL, NULL, ctl_ctloutput,
	NULL, NULL,
	NULL, NULL, NULL, NULL, &ctl_usrreqs,
	ctl_lock, ctl_unlock, ctl_getlock, { 0, 0 } , 0, { 0 }
};


/*
 * Install the protosw's for the Kernel Control manager.
 */
__private_extern__ int
kern_control_init(void)
{
	int error = 0;
	
	ctl_lck_grp_attr = lck_grp_attr_alloc_init();
	if (ctl_lck_grp_attr == 0) {
			printf(": lck_grp_attr_alloc_init failed\n");
			error = ENOMEM;
			goto done;
	}
			
	ctl_lck_grp = lck_grp_alloc_init("Kernel Control Protocol", ctl_lck_grp_attr);
	if (ctl_lck_grp == 0) {
			printf("kern_control_init: lck_grp_alloc_init failed\n");
			error = ENOMEM;
			goto done;
	}
	
	ctl_lck_attr = lck_attr_alloc_init();
	if (ctl_lck_attr == 0) {
			printf("kern_control_init: lck_attr_alloc_init failed\n");
			error = ENOMEM;
			goto done;
	}
	
	ctl_mtx = lck_mtx_alloc_init(ctl_lck_grp, ctl_lck_attr);
	if (ctl_mtx == 0) {
			printf("kern_control_init: lck_mtx_alloc_init failed\n");
			error = ENOMEM;
			goto done;
	}
	TAILQ_INIT(&ctl_head);
	
	error = net_add_proto(&kctlswk_dgram, &systemdomain);
	if (error) {
		log(LOG_WARNING, "kern_control_init: net_add_proto dgram failed (%d)\n", error);
	}
	error = net_add_proto(&kctlswk_stream, &systemdomain);
	if (error) {
		log(LOG_WARNING, "kern_control_init: net_add_proto stream failed (%d)\n", error);
	}
	
	done:
	if (error != 0) {
		if (ctl_mtx) {
				lck_mtx_free(ctl_mtx, ctl_lck_grp);
				ctl_mtx = 0;
		}
		if (ctl_lck_grp) {
				lck_grp_free(ctl_lck_grp);
				ctl_lck_grp = 0;
		}
		if (ctl_lck_grp_attr) {
				lck_grp_attr_free(ctl_lck_grp_attr);
				ctl_lck_grp_attr = 0;
		}
		if (ctl_lck_attr) {
				lck_attr_free(ctl_lck_attr);
				ctl_lck_attr = 0;
		}
	}
	return error;
}

static void
kcb_delete(struct ctl_cb *kcb)
{
	if (kcb != 0) {
		if (kcb->mtx != 0)
			lck_mtx_free(kcb->mtx, ctl_lck_grp);
		FREE(kcb, M_TEMP);
	}
}


/*
 * Kernel Controller user-request functions
 * attach function must exist and succeed 
 * detach not necessary 
 * we need a pcb for the per socket mutex
 */
static int
ctl_attach(__unused struct socket *so, __unused int proto, __unused struct proc *p)
{	
	int error = 0;
	struct ctl_cb			*kcb = 0;

	MALLOC(kcb, struct ctl_cb *, sizeof(struct ctl_cb), M_TEMP, M_WAITOK);
	if (kcb == NULL) {
		error = ENOMEM;
		goto quit;
	}
	bzero(kcb, sizeof(struct ctl_cb));
	
	kcb->mtx = lck_mtx_alloc_init(ctl_lck_grp, ctl_lck_attr);
	if (kcb->mtx == NULL) {
		error = ENOMEM;
		goto quit;
	}
	kcb->so = so;
	so->so_pcb = (caddr_t)kcb;
    
quit:
	if (error != 0) {
		kcb_delete(kcb);
		kcb = 0;
	}
	return error;
}

static int
ctl_sofreelastref(struct socket *so)
{
    struct ctl_cb 	*kcb = (struct ctl_cb *)so->so_pcb;

    so->so_pcb = 0;
    
    if (kcb != 0) {
        struct kctl		*kctl;
        if ((kctl = kcb->kctl) != 0) {
            lck_mtx_lock(ctl_mtx);
            TAILQ_REMOVE(&kctl->kcb_head, kcb, next);
            lck_mtx_lock(ctl_mtx);
    	}
    	kcb_delete(kcb);
    }
    sofreelastref(so, 1);
    return 0;
}

static int
ctl_detach(struct socket *so)
{
    struct ctl_cb 	*kcb = (struct ctl_cb *)so->so_pcb;
    
    if (kcb == 0)
    	return 0;

    soisdisconnected(so);    
    so->so_flags |= SOF_PCBCLEARING;
    return 0;
}


static int
ctl_connect(struct socket *so, struct sockaddr *nam, __unused struct proc *p)
{	
    struct kctl			*kctl;
    int					error = 0;
    struct sockaddr_ctl	sa;
    struct ctl_cb		*kcb = (struct ctl_cb *)so->so_pcb;
    struct ctl_cb		*kcb_next = NULL;
    
    if (kcb == 0)
    	panic("ctl_connect so_pcb null\n");
    
    if (nam->sa_len !=  sizeof(struct sockaddr_ctl))
    	return(EINVAL);
    
    bcopy(nam, &sa, sizeof(struct sockaddr_ctl));
    
    lck_mtx_lock(ctl_mtx);
    kctl = ctl_find_by_id_unit(sa.sc_id, sa.sc_unit);
    if (kctl == NULL) {
        lck_mtx_unlock(ctl_mtx);
        return ENOENT;
    }

	if (((kctl->flags & CTL_FLAG_REG_SOCK_STREAM) && (so->so_type != SOCK_STREAM)) ||
		(!(kctl->flags & CTL_FLAG_REG_SOCK_STREAM) && (so->so_type != SOCK_DGRAM))) {
        lck_mtx_unlock(ctl_mtx);
        return EPROTOTYPE;
	}

    if (kctl->flags & CTL_FLAG_PRIVILEGED) {
        if (p == 0) {
            lck_mtx_unlock(ctl_mtx);
            return(EINVAL);
        }
        if (kauth_cred_issuser(kauth_cred_get()) == 0) {
            lck_mtx_unlock(ctl_mtx);
            return EPERM;
        }
    }

	if ((kctl->flags & CTL_FLAG_REG_ID_UNIT) || sa.sc_unit != 0) {
		if (kcb_find(kctl, sa.sc_unit) != NULL) {
			lck_mtx_unlock(ctl_mtx);
			return EBUSY;
		}
	} else {
		/* Find an unused ID, assumes control IDs are listed in order */
    	u_int32_t	unit = 1;
    	
    	TAILQ_FOREACH(kcb_next, &kctl->kcb_head, next) {
    		if (kcb_next->unit > unit) {
    			/* Found a gap, lets fill it in */
    			break;
    		}
    		unit = kcb_next->unit + 1;
    		if (unit == ctl_maxunit)
    			break;
    	}
    	
		if (unit == ctl_maxunit) {
			lck_mtx_unlock(ctl_mtx);
			return EBUSY;
		}
		
		sa.sc_unit = unit;
    }

	kcb->unit = sa.sc_unit;
    kcb->kctl = kctl;
    if (kcb_next != NULL) {
    	TAILQ_INSERT_BEFORE(kcb_next, kcb, next);
    }
    else {
		TAILQ_INSERT_TAIL(&kctl->kcb_head, kcb, next);
	}
    lck_mtx_unlock(ctl_mtx);

    error = soreserve(so, kctl->sendbufsize, kctl->recvbufsize);
    if (error)
		goto done;
    soisconnecting(so);
    
	socket_unlock(so, 0);
    error = (*kctl->connect)(kctl, &sa, &kcb->userdata);
	socket_lock(so, 0);
    if (error)
		goto done;
    
    soisconnected(so);

done:
    if (error) {
        soisdisconnected(so);
        lck_mtx_lock(ctl_mtx);
        kcb->kctl = 0;
        kcb->unit = 0;
        TAILQ_REMOVE(&kctl->kcb_head, kcb, next);
        lck_mtx_unlock(ctl_mtx);
    }
    return error;
}

static int
ctl_disconnect(struct socket *so)
{
    struct ctl_cb 	*kcb = (struct ctl_cb *)so->so_pcb;

    if ((kcb = (struct ctl_cb *)so->so_pcb)) {
        struct kctl		*kctl = kcb->kctl;
        
        if (kctl && kctl->disconnect) {
            socket_unlock(so, 0);
            (*kctl->disconnect)(kctl, kcb->unit, kcb->userdata);
            socket_lock(so, 0);
        }
        lck_mtx_lock(ctl_mtx);
        kcb->kctl = 0;
    	kcb->unit = 0;
        TAILQ_REMOVE(&kctl->kcb_head, kcb, next);
        soisdisconnected(so);
        lck_mtx_unlock(ctl_mtx);
    }
    return 0;
}

static int
ctl_peeraddr(struct socket *so, struct sockaddr **nam)
{
	struct ctl_cb 		*kcb = (struct ctl_cb *)so->so_pcb;
	struct kctl			*kctl;
	struct sockaddr_ctl	sc;
	
	if (kcb == NULL)	/* sanity check */
		return(ENOTCONN);
	
	if ((kctl = kcb->kctl) == NULL)
		return(EINVAL);
		
	bzero(&sc, sizeof(struct sockaddr_ctl));
	sc.sc_len = sizeof(struct sockaddr_ctl);
	sc.sc_family = AF_SYSTEM;
	sc.ss_sysaddr = AF_SYS_CONTROL;
	sc.sc_id =  kctl->id;
	sc.sc_unit = kcb->unit;
	
	*nam = dup_sockaddr((struct sockaddr *)&sc, 1);
	
	return 0;
}

static int
ctl_send(struct socket *so, int flags, struct mbuf *m,
            __unused struct sockaddr *addr, __unused struct mbuf *control,
            __unused struct proc *p)
{
	int	 	error = 0;
	struct ctl_cb 	*kcb = (struct ctl_cb *)so->so_pcb;
	struct kctl		*kctl;
	
	if (kcb == NULL)	/* sanity check */
		return(ENOTCONN);
	
	if ((kctl = kcb->kctl) == NULL)
		return(EINVAL);
		
	if (kctl->send) {
		socket_unlock(so, 0);
		error = (*kctl->send)(kctl, kcb->unit, kcb->userdata, m, flags);
		socket_lock(so, 0);
	}
	return error;
}

errno_t
ctl_enqueuembuf(void *kctlref, u_int32_t unit, struct mbuf *m, u_int32_t flags)
{
	struct ctl_cb 	*kcb;
	struct socket 	*so;
	errno_t 		error = 0;
	struct kctl		*kctl = (struct kctl *)kctlref;
	
	if (kctl == NULL)
		return EINVAL;
		
	kcb = kcb_find(kctl, unit);
	if (kcb == NULL)
		return EINVAL;
	
	so = (struct socket *)kcb->so;
	if (so == NULL) 
		return EINVAL;
	
	socket_lock(so, 1);
	if (sbspace(&so->so_rcv) < m->m_pkthdr.len) {
		error = ENOBUFS;
		goto bye;
	}
	if ((flags & CTL_DATA_EOR))
		m->m_flags |= M_EOR;
	if (sbappend(&so->so_rcv, m) && (flags & CTL_DATA_NOWAKEUP) == 0)
		sorwakeup(so);
bye:
	socket_unlock(so, 1);
	return error;
}

errno_t
ctl_enqueuedata(void *kctlref, u_int32_t unit, void *data, size_t len, u_int32_t flags)
{
	struct ctl_cb 	*kcb;
	struct socket 	*so;
	struct mbuf 	*m;
	errno_t			error = 0;
	struct kctl		*kctl = (struct kctl *)kctlref;
	unsigned int 	num_needed;
	struct mbuf 	*n;
	size_t			curlen = 0;
	
	if (kctlref == NULL)
		return EINVAL;
		
	kcb = kcb_find(kctl, unit);
	if (kcb == NULL)
		return EINVAL;
	
	so = (struct socket *)kcb->so;
	if (so == NULL) 
		return EINVAL;
	
	socket_lock(so, 1);
	if (sbspace(&so->so_rcv) < (int)len) {
		error = ENOBUFS;
		goto bye;
	}

	num_needed = 1;
	m = m_allocpacket_internal(&num_needed, len, NULL, M_NOWAIT, 1, 0);
	if (m == NULL) {
		printf("ctl_enqueuedata: m_allocpacket_internal(%lu) failed\n", len);
		error = ENOBUFS;
		goto bye;
	}
	
	for (n = m; n != NULL; n = n->m_next) {
		size_t mlen = mbuf_maxlen(n);
		
		if (mlen + curlen > len)
			mlen = len - curlen;
		n->m_len = mlen;
		bcopy((char *)data + curlen, n->m_data, mlen);
		curlen += mlen;
	}
	mbuf_pkthdr_setlen(m, curlen);

	if ((flags & CTL_DATA_EOR))
		m->m_flags |= M_EOR;
	if (sbappend(&so->so_rcv, m) && (flags & CTL_DATA_NOWAKEUP) == 0)
		sorwakeup(so);
bye:
	socket_unlock(so, 1);
	return error;
}


errno_t 
ctl_getenqueuespace(kern_ctl_ref kctlref, u_int32_t unit, size_t *space)
{
	struct ctl_cb 	*kcb;
	struct kctl		*kctl = (struct kctl *)kctlref;
	struct socket 	*so;
	long avail;
	
	if (kctlref == NULL || space == NULL)
		return EINVAL;
		
	kcb = kcb_find(kctl, unit);
	if (kcb == NULL)
		return EINVAL;
	
	so = (struct socket *)kcb->so;
	if (so == NULL) 
		return EINVAL;
	
	socket_lock(so, 1);
	avail = sbspace(&so->so_rcv);
	*space = (avail < 0) ? 0 : avail;
	socket_unlock(so, 1);

	return 0;
}

static int
ctl_ctloutput(struct socket *so, struct sockopt *sopt)
{
	struct ctl_cb 	*kcb = (struct ctl_cb *)so->so_pcb;
	struct kctl	*kctl;
	int 	error = 0;
	void 	*data;
	size_t	len;
	
	if (sopt->sopt_level != SYSPROTO_CONTROL) {
		return(EINVAL);
	}
	
	if (kcb == NULL)	/* sanity check */
		return(ENOTCONN);
	
	if ((kctl = kcb->kctl) == NULL)
		return(EINVAL);
		
	switch (sopt->sopt_dir) {
		case SOPT_SET:
			if (kctl->setopt == NULL)
				return(ENOTSUP);
			if (sopt->sopt_valsize == 0) {
				data = NULL;
			} else {
				MALLOC(data, void *, sopt->sopt_valsize, M_TEMP, M_WAITOK);
				if (data == NULL)
					return(ENOMEM);
				error = sooptcopyin(sopt, data, sopt->sopt_valsize, sopt->sopt_valsize);
			}
			if (error == 0) {
				socket_unlock(so, 0);
				error = (*kctl->setopt)(kcb->kctl, kcb->unit, kcb->userdata, sopt->sopt_name, 
							data, sopt->sopt_valsize);
				socket_lock(so, 0);
			}
			FREE(data, M_TEMP);
			break;
	
		case SOPT_GET:
			if (kctl->getopt == NULL)
				return(ENOTSUP);
			data = NULL;
			if (sopt->sopt_valsize && sopt->sopt_val) {
				MALLOC(data, void *, sopt->sopt_valsize, M_TEMP, M_WAITOK);
				if (data == NULL)
					return(ENOMEM);
				/* 4108337 - copy in data for get socket option */
				error = sooptcopyin(sopt, data, sopt->sopt_valsize, sopt->sopt_valsize);
			}
			len = sopt->sopt_valsize;
			socket_unlock(so, 0);
			error = (*kctl->getopt)(kcb->kctl, kcb->unit, kcb->userdata, sopt->sopt_name, 
						data, &len);
			socket_lock(so, 0);    
			if (error == 0) {
				if (data != NULL)
					error = sooptcopyout(sopt, data, len);
				else 
					sopt->sopt_valsize = len;
			}
			if (data != NULL)
				FREE(data, M_TEMP);                
			break;
	}
	return error;
}

static int 
ctl_ioctl(__unused struct socket *so, u_long cmd, caddr_t data,
			__unused struct ifnet *ifp, __unused struct proc *p)
{
	int 	error = ENOTSUP;
	
	switch (cmd) {
		/* get the number of controllers */
		case CTLIOCGCOUNT: {
			struct kctl	*kctl;
			int n = 0;

			lck_mtx_lock(ctl_mtx);
			TAILQ_FOREACH(kctl, &ctl_head, next)
				n++;
			lck_mtx_unlock(ctl_mtx);

			*(u_int32_t *)data = n;
			error = 0;
			break;
		}
		case CTLIOCGINFO: {
			struct ctl_info *ctl_info = (struct ctl_info *)data;
			struct kctl 	*kctl = 0;
			size_t name_len = strlen(ctl_info->ctl_name);
			
			if (name_len == 0 || name_len + 1 > MAX_KCTL_NAME) {
				error = EINVAL;
				break;
			}
			lck_mtx_lock(ctl_mtx);
			kctl = ctl_find_by_name(ctl_info->ctl_name);
			lck_mtx_unlock(ctl_mtx);
			if (kctl == 0) {
				error = ENOENT;
				break;
			}
			ctl_info->ctl_id = kctl->id;
			error = 0;
			break;
		}
	
		/* add controls to get list of NKEs */
	
	}
	
	return error;
}

/*
 * Register/unregister a NKE
 */
errno_t
ctl_register(struct kern_ctl_reg *userkctl, kern_ctl_ref *kctlref)
{
	struct kctl 	*kctl = NULL;
	struct kctl 	*kctl_next = NULL;
	u_int32_t		id = 1;
	size_t			name_len;
	
	if (userkctl == NULL)	/* sanity check */
		return(EINVAL);
	if (userkctl->ctl_connect == NULL)
		return(EINVAL);
	name_len = strlen(userkctl->ctl_name);
	if (name_len == 0 || name_len + 1 > MAX_KCTL_NAME)
		return(EINVAL);
	
	MALLOC(kctl, struct kctl *, sizeof(*kctl), M_TEMP, M_WAITOK);
	if (kctl == NULL)
		return(ENOMEM);
	bzero((char *)kctl, sizeof(*kctl));
	
	lck_mtx_lock(ctl_mtx);
	
	/*
	 * Kernel Control IDs
	 *
	 * CTL_FLAG_REG_ID_UNIT indicates the control ID and unit number are
	 * static. If they do not exist, add them to the list in order. If the
	 * flag is not set, we must find a new unique value. We assume the
	 * list is in order. We find the last item in the list and add one. If
	 * this leads to wrapping the id around, we start at the front of the
	 * list and look for a gap.
	 */
	
	if ((userkctl->ctl_flags & CTL_FLAG_REG_ID_UNIT) == 0) {
		/* Must dynamically assign an unused ID */
		
		/* Verify the same name isn't already registered */
		if (ctl_find_by_name(userkctl->ctl_name) != NULL) {
			lck_mtx_unlock(ctl_mtx);
			FREE(kctl, M_TEMP);
			return(EEXIST);
		}
		
		/* Start with 1 in case the list is empty */
		id = 1;
		kctl_next = TAILQ_LAST(&ctl_head, kctl_list);
		
		if (kctl_next != NULL) {
			/* List was not empty, add one to the last item in the list */
			id = kctl_next->id + 1;
			kctl_next = NULL;
			
			/*
			 * If this wrapped the id number, start looking at the front
			 * of the list for an unused id.
			 */
			if (id == 0) {
				/* Find the next unused ID */
				id = 1;
				
				TAILQ_FOREACH(kctl_next, &ctl_head, next) {
					if (kctl_next->id > id) {
						/* We found a gap */
						break;
					}
					
					id = kctl_next->id + 1;
				}
			}
		}
		
		userkctl->ctl_id = id;
		kctl->id = id;
		kctl->reg_unit = -1;
	} else {
		TAILQ_FOREACH(kctl_next, &ctl_head, next) {
			if (kctl_next->id > userkctl->ctl_id)
				break;
		}
		
		if (ctl_find_by_id_unit(userkctl->ctl_id, userkctl->ctl_unit) != NULL) {
			lck_mtx_unlock(ctl_mtx);
			FREE(kctl, M_TEMP);
			return(EEXIST);
		}
		kctl->id = userkctl->ctl_id;
		kctl->reg_unit = userkctl->ctl_unit;
	}
	strlcpy(kctl->name, userkctl->ctl_name, MAX_KCTL_NAME);
	kctl->flags = userkctl->ctl_flags;

	/* Let the caller know the default send and receive sizes */
	if (userkctl->ctl_sendsize == 0)
		userkctl->ctl_sendsize = CTL_SENDSIZE;
	kctl->sendbufsize = userkctl->ctl_sendsize;

	if (userkctl->ctl_recvsize == 0)
		userkctl->ctl_recvsize = CTL_RECVSIZE;
	kctl->recvbufsize = userkctl->ctl_recvsize;

	kctl->connect = userkctl->ctl_connect;
	kctl->disconnect = userkctl->ctl_disconnect;
	kctl->send = userkctl->ctl_send;
	kctl->setopt = userkctl->ctl_setopt;
	kctl->getopt = userkctl->ctl_getopt;
	
	TAILQ_INIT(&kctl->kcb_head);
	
	if (kctl_next)
		TAILQ_INSERT_BEFORE(kctl_next, kctl, next);
	else
		TAILQ_INSERT_TAIL(&ctl_head, kctl, next);
	
	lck_mtx_unlock(ctl_mtx);
	
	*kctlref = kctl;
	
	ctl_post_msg(KEV_CTL_REGISTERED, kctl->id);
	return(0);
}

errno_t
ctl_deregister(void *kctlref)
{	
    struct kctl		*kctl;

    if (kctlref == NULL)	/* sanity check */
        return(EINVAL);

    lck_mtx_lock(ctl_mtx);
    TAILQ_FOREACH(kctl, &ctl_head, next) {
    	if (kctl == (struct kctl *)kctlref)
    		break;
    }
    if (kctl != (struct kctl *)kctlref) {
        lck_mtx_unlock(ctl_mtx);
        return EINVAL;
    }
	if (!TAILQ_EMPTY(&kctl->kcb_head)) {
        lck_mtx_unlock(ctl_mtx);
		return EBUSY;
	}

    TAILQ_REMOVE(&ctl_head, kctl, next);

    lck_mtx_unlock(ctl_mtx);
    
    ctl_post_msg(KEV_CTL_DEREGISTERED, kctl->id);
    FREE(kctl, M_TEMP);
    return(0);
}

/*
 * Must be called with global ctl_mtx lock taked
 */
static struct kctl *
ctl_find_by_name(const char *name)
{	
    struct kctl 	*kctl;

    TAILQ_FOREACH(kctl, &ctl_head, next)
        if (strncmp(kctl->name, name, sizeof(kctl->name)) == 0)
            return kctl;

    return NULL;
}

/*
 * Must be called with global ctl_mtx lock taked
 *
 */
static struct kctl *
ctl_find_by_id_unit(u_int32_t id, u_int32_t unit)
{	
    struct kctl 	*kctl;

    TAILQ_FOREACH(kctl, &ctl_head, next) {
        if (kctl->id == id && (kctl->flags & CTL_FLAG_REG_ID_UNIT) == 0)
            return kctl;
        else if (kctl->id == id && kctl->reg_unit == unit)
            return kctl;
    }
    return NULL;
}

/*
 * Must be called with kernel controller lock taken
 */
static struct ctl_cb *
kcb_find(struct kctl *kctl, u_int32_t unit)
{	
    struct ctl_cb 	*kcb;

    TAILQ_FOREACH(kcb, &kctl->kcb_head, next)
        if ((kcb->unit == unit))
            return kcb;

    return NULL;
}

/*
 * Must be called witout lock
 */
static void 
ctl_post_msg(u_int32_t event_code, u_int32_t id) 
{
    struct ctl_event_data  	ctl_ev_data;
    struct kev_msg  		ev_msg;
    
    ev_msg.vendor_code    = KEV_VENDOR_APPLE;
    
    ev_msg.kev_class      = KEV_SYSTEM_CLASS;
    ev_msg.kev_subclass   = KEV_CTL_SUBCLASS;
    ev_msg.event_code 	  = event_code;    
        
    /* common nke subclass data */
    bzero(&ctl_ev_data, sizeof(ctl_ev_data));
    ctl_ev_data.ctl_id = id;
    ev_msg.dv[0].data_ptr    = &ctl_ev_data;	
    ev_msg.dv[0].data_length = sizeof(ctl_ev_data);

    ev_msg.dv[1].data_length = 0;

    kev_post_msg(&ev_msg);
}

static int
ctl_lock(struct socket *so, int refcount, void *lr)
{
	void *lr_saved;

	if (lr == NULL)
		lr_saved = __builtin_return_address(0);
	else
		lr_saved = lr;

	if (so->so_pcb != NULL) {
		lck_mtx_lock(((struct ctl_cb *)so->so_pcb)->mtx);
	} else  {
		panic("ctl_lock: so=%p NO PCB! lr=%p lrh= %s\n", 
		    so, lr_saved, solockhistory_nr(so));
		/* NOTREACHED */
	}

	if (so->so_usecount < 0) {
		panic("ctl_lock: so=%p so_pcb=%p lr=%p ref=%x lrh= %s\n",
		    so, so->so_pcb, lr_saved, so->so_usecount, solockhistory_nr(so));
		/* NOTREACHED */
	}

	if (refcount)
		so->so_usecount++;

	so->lock_lr[so->next_lock_lr] = lr_saved;
	so->next_lock_lr = (so->next_lock_lr+1) % SO_LCKDBG_MAX;
	return (0);
}

static int
ctl_unlock(struct socket *so, int refcount, void *lr)
{
	void *lr_saved;
	lck_mtx_t *mutex_held;

	if (lr == NULL)
		lr_saved = __builtin_return_address(0);
	else
		lr_saved = lr;

#ifdef MORE_KCTLLOCK_DEBUG
	printf("ctl_unlock: so=%x sopcb=%x lock=%x ref=%x lr=%p\n",
	    so, so->so_pcb, ((struct ctl_cb *)so->so_pcb)->mtx,
	    so->so_usecount, lr_saved);
#endif
	if (refcount)
		so->so_usecount--;

	if (so->so_usecount < 0) {
		panic("ctl_unlock: so=%p usecount=%x lrh= %s\n", 
		    so, so->so_usecount, solockhistory_nr(so));
		/* NOTREACHED */
	}
	if (so->so_pcb == NULL) {
		panic("ctl_unlock: so=%p NO PCB usecount=%x lr=%p lrh= %s\n", 
		    so, so->so_usecount, (void *)lr_saved, solockhistory_nr(so));
		/* NOTREACHED */
	}
	mutex_held = ((struct ctl_cb *)so->so_pcb)->mtx;

	lck_mtx_assert(mutex_held, LCK_MTX_ASSERT_OWNED);
	so->unlock_lr[so->next_unlock_lr] = lr_saved;
	so->next_unlock_lr = (so->next_unlock_lr+1) % SO_LCKDBG_MAX;
	lck_mtx_unlock(mutex_held);

	if (so->so_usecount == 0)
		ctl_sofreelastref(so);

	return (0);
}

static lck_mtx_t *
ctl_getlock(struct socket *so, __unused int locktype)
{
	struct ctl_cb *kcb = (struct ctl_cb *)so->so_pcb;
	
	if (so->so_pcb)  {
		if (so->so_usecount < 0)
			panic("ctl_getlock: so=%p usecount=%x lrh= %s\n", 
			    so, so->so_usecount, solockhistory_nr(so));
		return(kcb->mtx);
	} else {
		panic("ctl_getlock: so=%p NULL NO so_pcb %s\n", 
		    so, solockhistory_nr(so));
		return (so->so_proto->pr_domain->dom_mtx);
	}
}
