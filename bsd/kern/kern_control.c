/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
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
/* Copyright (C) 1999 Apple Computer, Inc. */

/*
 * NKE management domain - allows control connections to
 *  an NKE and to read/write data.
 *
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
#include <net/kext_net.h>
#include <sys/sys_domain.h>
#include <sys/kern_event.h>
#include <sys/kern_control.h>
#include <net/if_var.h>

#include <mach/vm_types.h>
#include <mach/kmod.h>

#include <kern/thread.h>


/*
 * Definitions and vars for we support
 */

#define CTL_SENDSIZE	(2 * 1024)	/* default buffer size */
#define CTL_RECVSIZE 	(8 * 1024)	/* default buffer size */

/*
 internal structure maintained for each register controller 
*/
struct ctl
{
    TAILQ_ENTRY(ctl) 	next;		/* controller chain */
    struct socket	*skt; 		/* current controlling socket */

    /* controller information provided when registering */
    u_int32_t 	id;			/* unique nke identifier, provided by DTS */
    u_int32_t 	unit;			/* unit number for use by the nke */
    void	*userdata;		/* for private use by nke */
    
    /* misc communication information */
    u_int32_t	flags;			/* support flags */
    u_int32_t	recvbufsize;		/* request more than the default buffer size */
    u_int32_t	sendbufsize;		/* request more than the default buffer size */
    
    /* Dispatch functions */
    int 	(*connect)(kern_ctl_ref, void *);			/* Make contact */
    void 	(*disconnect)(kern_ctl_ref, void *);			/* Break contact */
    int 	(*write) (kern_ctl_ref, void *, struct mbuf *);		/* Send data to nke */
    int 	(*set)(kern_ctl_ref, void *, int, void *, size_t );	/* set ctl configuration */
    int 	(*get)(kern_ctl_ref, void *, int, void *, size_t *);	/* get ctl configuration */
};


/* all the controllers are chained */
TAILQ_HEAD(, ctl) 	ctl_head;

int ctl_attach(struct socket *, int, struct proc *);
int ctl_connect(struct socket *, struct sockaddr *, struct proc *);
int ctl_disconnect(struct socket *);
int ctl_ioctl(struct socket *so, u_long cmd, caddr_t data,
                  struct ifnet *ifp, struct proc *p);
int ctl_send(struct socket *, int, struct mbuf *,
            struct sockaddr *, struct mbuf *, struct proc *);
int ctl_ctloutput(struct socket *, struct sockopt *);

struct ctl *ctl_find(u_int32_t, u_int32_t unit);
void ctl_post_msg(u_long event_code, u_int32_t id, u_int32_t unit);


struct pr_usrreqs ctl_usrreqs =
{
	pru_abort_notsupp, pru_accept_notsupp, ctl_attach, pru_bind_notsupp,
	ctl_connect, pru_connect2_notsupp, ctl_ioctl, pru_detach_notsupp,
	ctl_disconnect, pru_listen_notsupp, pru_peeraddr_notsupp,
	pru_rcvd_notsupp, pru_rcvoob_notsupp, ctl_send,
	pru_sense_null, pru_shutdown_notsupp, pru_sockaddr_notsupp,
	sosend, soreceive, sopoll
};

struct protosw ctlsw =
{
	SOCK_DGRAM, &systemdomain, SYSPROTO_CONTROL, PR_ATOMIC|PR_CONNREQUIRED,
	NULL, NULL, NULL, ctl_ctloutput,
	NULL, NULL,
	NULL, NULL, NULL, NULL, &ctl_usrreqs
};

/*
 * Install the protosw's for the NKE manager.
 */
int
kern_control_init(void)
{
    int retval;

    retval = net_add_proto(&ctlsw, &systemdomain);
    if (retval) {
        log(LOG_WARNING, "Can't install Kernel Controller Manager (%d)\n", retval);
        return retval;
    }

    TAILQ_INIT(&ctl_head);
    
    return(KERN_SUCCESS);
}


/*
 * Kernel Controller user-request functions
 */
int
ctl_attach (struct socket *so, int proto, struct proc *p)
{	
    /* 
     * attach function must exist and succeed 
     * detach not necessary since we use 
     * connect/disconnect to handle so_pcb
     */
    
    return 0;
}

int
ctl_connect(struct socket *so, struct sockaddr *nam, struct proc *p)
{	
    struct ctl		*ctl;
    int 		error = 0;
    struct sockaddr_ctl *sa = (struct sockaddr_ctl *)nam;

    ctl = ctl_find(sa->sc_id, sa->sc_unit);
    if (ctl == NULL)
        return(EADDRNOTAVAIL);

    if (ctl->flags & CTL_FLAG_PRIVILEGED) {
        if (p == 0)
            return(EINVAL);
        if (error = suser(p->p_ucred, &p->p_acflag))
            return error;
    }

    if (ctl->skt != NULL)
        return(EBUSY);

    error = soreserve(so, 
        ctl->sendbufsize ? ctl->sendbufsize : CTL_SENDSIZE,
        ctl->recvbufsize ? ctl->recvbufsize : CTL_RECVSIZE);
    if (error)
        return error;
    
    ctl->skt = so;
    
    if (ctl->connect)
        error = (*ctl->connect)(ctl, ctl->userdata);
    if (error) {
        ctl->skt = NULL;
        return error;
    }
    
    so->so_pcb = (caddr_t)ctl;
    soisconnected(so);
    
    return error;
}

int
ctl_disconnect(struct socket *so)
{
    struct ctl		*ctl;

    if ((ctl = (struct ctl *)so->so_pcb))
    {
        if (ctl->disconnect)
            (*ctl->disconnect)(ctl, ctl->userdata);
        ctl->skt = NULL;
        so->so_pcb = NULL;
        soisdisconnected(so);
    }
    return 0;
}

int
ctl_send(struct socket *so, int flags, struct mbuf *m,
            struct sockaddr *addr, struct mbuf *control,
            struct proc *p)
{
    struct ctl 	*ctl = (struct ctl *)so->so_pcb;
    int	 	error = 0;

    if (ctl == NULL)
        return(ENOTCONN);
        
    if (ctl->write)
        error = (*ctl->write)(ctl, ctl->userdata, m);
    
    return error;
}

int
ctl_enqueuembuf(void *ctlref, struct mbuf *m, u_int32_t flags)
{
    struct ctl 		*ctl = (struct ctl *)ctlref;
    struct socket 	*so = (struct socket *)ctl->skt;

    if (ctl == NULL)	/* sanity check */
        return(EINVAL);

    if (so == NULL)
        return(ENOTCONN);

    if (sbspace(&so->so_rcv) < m->m_pkthdr.len)
        return(ENOBUFS);

    sbappend(&so->so_rcv, m);
    if ((flags & CTL_DATA_NOWAKEUP) == 0)
        sorwakeup(so);
    return 0;
}

int
ctl_enqueuedata(void *ctlref, void *data, size_t len, u_int32_t flags)
{
    struct ctl 		*ctl = (struct ctl *)ctlref;
    struct socket 	*so = (struct socket *)ctl->skt;
    struct mbuf 	*m;

    if (ctl == NULL)	/* sanity check */
        return(EINVAL);

    if (so == NULL)
        return(ENOTCONN);

    if (len > MCLBYTES)
        return(EMSGSIZE);

    if (sbspace(&so->so_rcv) < len)
        return(ENOBUFS);
        
    if ((m = m_gethdr(M_NOWAIT, MT_DATA)) == NULL)
        return (ENOBUFS);
    
    if (len > MHLEN) {
        MCLGET(m, M_NOWAIT);
        if (!(m->m_flags & M_EXT)) {
            m_freem(m);
            return(ENOBUFS);
        }
    }

    bcopy(data, mtod(m, void *), len);
    m->m_pkthdr.len = m->m_len = len;

    sbappend(&so->so_rcv, m);
    if ((flags & CTL_DATA_NOWAKEUP) == 0)
        sorwakeup(so);
    return 0;
}

int
ctl_ctloutput(struct socket *so, struct sockopt *sopt)
{
    struct ctl	*ctl = (struct ctl *)so->so_pcb;
    int 	error = 0, s;
    void 	*data;
    size_t	len;

    if (sopt->sopt_level != SYSPROTO_CONTROL) {
        return(EINVAL);
    }

    if (ctl == NULL)
        return(ENOTCONN);
        
    switch (sopt->sopt_dir) {
        case SOPT_SET:
            if (ctl->set == NULL)
                return(ENOTSUP);
            MALLOC(data, void *, sopt->sopt_valsize, M_TEMP, M_WAITOK);
            if (data == NULL)
                return(ENOMEM);
            error = sooptcopyin(sopt, data, sopt->sopt_valsize, sopt->sopt_valsize);
            if (error == 0)
                error = (*ctl->set)(ctl, ctl->userdata, sopt->sopt_name, data, sopt->sopt_valsize);
            FREE(data, M_TEMP);
            break;

        case SOPT_GET:
            if (ctl->get == NULL)
                return(ENOTSUP);
            data = NULL;
            if (sopt->sopt_valsize && sopt->sopt_val) {
                MALLOC(data, void *, sopt->sopt_valsize, M_TEMP, M_WAITOK);
                if (data == NULL)
                    return(ENOMEM);
            }
            len = sopt->sopt_valsize;
            error = (*ctl->get)(ctl, ctl->userdata, sopt->sopt_name, data, &len);
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

int ctl_ioctl(struct socket *so, u_long cmd, caddr_t data,
                  struct ifnet *ifp, struct proc *p)
{
    int 	error = ENOTSUP, s, n;
    struct ctl	*ctl = (struct ctl *)so->so_pcb;
    
    switch (cmd) {
        /* get the number of controllers */
        case CTLIOCGCOUNT:
            n = 0;
            TAILQ_FOREACH(ctl, &ctl_head, next)
                n++;
            *(u_int32_t *)data = n;
            error = 0;
            break;
        

        /* add controls to get list of NKEs */

    }
    
    return error;
}

/*
 * Register/unregister a NKE
 */
int
ctl_register(struct kern_ctl_reg *userctl, void *userdata, kern_ctl_ref *ctlref)
{	
    struct ctl 	*ctl;

    if (userctl == NULL)	/* sanity check */
        return(EINVAL);

    ctl = ctl_find(userctl->ctl_id, userctl->ctl_unit);
    if (ctl != NULL)
        return(EEXIST);
    
    MALLOC(ctl, struct ctl *, sizeof(*ctl), M_TEMP, M_WAITOK);
    if (ctl == NULL)
        return(ENOMEM);
        
    bzero((char *)ctl, sizeof(*ctl));

    ctl->id = userctl->ctl_id;
    ctl->unit = userctl->ctl_unit;
    ctl->flags = userctl->ctl_flags;
    ctl->sendbufsize = userctl->ctl_sendsize;
    ctl->recvbufsize = userctl->ctl_recvsize;
    ctl->userdata = userdata;
    ctl->connect = userctl->ctl_connect;
    ctl->disconnect = userctl->ctl_disconnect;
    ctl->write = userctl->ctl_write;
    ctl->set = userctl->ctl_set;
    ctl->get = userctl->ctl_get;

    TAILQ_INSERT_TAIL(&ctl_head, ctl, next);
    
    *ctlref = ctl;

    ctl_post_msg(KEV_CTL_REGISTERED, ctl->id, ctl->unit);
    return(0);
}

int
ctl_deregister(void *ctlref)
{	
    struct ctl		*ctl = (struct ctl *)ctlref;
    struct socket	*so;

    if (ctl == NULL)	/* sanity check */
        return(EINVAL);

    TAILQ_REMOVE(&ctl_head, ctl, next);

    if (ctl->skt) {
        ctl->skt->so_pcb = 0;
        soisdisconnected(ctl->skt);
    }
    
    ctl_post_msg(KEV_CTL_DEREGISTERED, ctl->id, ctl->unit);
    FREE(ctl, M_TEMP);
    return(0);
}

/*
 * Locate a NKE
 */
struct ctl *
ctl_find(u_int32_t id, u_int32_t unit)
{	
    struct ctl 	*ctl;

    TAILQ_FOREACH(ctl, &ctl_head, next)
        if ((ctl->id == id) && (ctl->unit == unit))
            return ctl;

    return NULL;
}

void ctl_post_msg(u_long event_code, u_int32_t id, u_int32_t unit) 
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
    ctl_ev_data.ctl_unit = unit;
    ev_msg.dv[0].data_ptr    = &ctl_ev_data;	
    ev_msg.dv[0].data_length = sizeof(ctl_ev_data);

    ev_msg.dv[1].data_length = 0;

    kev_post_msg(&ev_msg);
}

