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


#ifndef SYS_KERN_CONTROL_H
#define SYS_KERN_CONTROL_H

#include <sys/appleapiopts.h>

#ifdef __APPLE_API_UNSTABLE
/*
 * Define Controller event subclass, and associated events.
 */

/* Subclass of KEV_SYSTEM_CLASS */
#define KEV_CTL_SUBCLASS 	1

#define KEV_CTL_REGISTERED     	1	/* a new controller appears */
#define KEV_CTL_DEREGISTERED   	2	/* a controller disappears */

/* All KEV_CTL_SUBCLASS events share the same header */
struct ctl_event_data {
    u_int32_t 	ctl_id;
    u_int32_t 	ctl_unit;
};


/*
 * Controls destined to the Controller Manager.
 */

#define	CTLIOCGCOUNT	_IOR('N', 1, int)	/* get number of control structures registered */

/*
 * Controller address structure
 * used to establish contact between user client and kernel controller
 * sc_id/sc_unit uniquely identify each controller
 * sc_id is a 32-bit "signature" obtained by developers from Apple Computer
 * sc_unit is a unit number for this sc_id, and is privately used 
 * by the developper to identify several instances to control
 */

struct sockaddr_ctl
{
    u_char	sc_len;		/* sizeof(struct sockaddr_ctl) */
    u_char	sc_family;	/* AF_SYSTEM */
    u_int16_t 	ss_sysaddr; 	/* AF_SYS_CONTROL */
    u_int32_t 	sc_id; 		/* 32-bit "signature" managed by Apple */
    u_int32_t 	sc_unit;	/* Developer private unit number */
    u_int32_t 	sc_reserved[5];
};
#endif /* __APPLE_API_UNSTABLE */

#ifdef KERNEL
#ifdef __APPLE_API_UNSTABLE

/* Reference to a controller object */
typedef void * kern_ctl_ref;

/* Support flags for controllers */
#define CTL_FLAG_PRIVILEGED	0x1	/* user must be root to contact controller */

/* Data flags for controllers */
#define CTL_DATA_NOWAKEUP	0x1	/* don't wake up client yet */


/*
 * Controller registration structure, given at registration time
 */
struct kern_ctl_reg
{
    /* control information */
    u_int32_t	ctl_id;			/* unique id of the controller, provided by DTS */
    u_int32_t	ctl_unit;		/* unit number for the controller, for the specified id */
                                        /* a controller can be registered several times with the same id */
                                        /* but must have a different unit number */
                                        
    /* control settings */
    u_int32_t	ctl_flags;		/* support flags */
    u_int32_t	ctl_sendsize;		/* override send/receive buffer size */
    u_int32_t	ctl_recvsize;		/* 0 = use default values */

    /* Dispatch functions */

    int 	(*ctl_connect)
                    (kern_ctl_ref ctlref, void *userdata);
                                        /* Make contact, called when user client calls connect */
                                        /* the socket with the id/unit of the controller */

    void 	(*ctl_disconnect)
                    (kern_ctl_ref ctlref, void *userdata);
                                        /* Break contact, called when user client */
                                        /* closes the control socket */
                    
    int 	(*ctl_write)		
                    (kern_ctl_ref ctlref, void *userdata, struct mbuf *m);
                                        /* Send data to the controller, called when user client */
                                        /* writes data to the socket */
                                        
    int 	(*ctl_set)		
                    (kern_ctl_ref ctlref, void *userdata, int opt, void *data, size_t len);
                                        /* set controller configuration, called when user client */
                                        /* calls setsockopt() for the socket */
                                        /* opt is the option number */
                                        /* data points to the data, already copied in kernel space */
                                        /* len is the lenght of the data buffer */

    int 	(*ctl_get)
                    (kern_ctl_ref ctlref, void *userdata, int opt, void *data, size_t *len);
                                        /* get controller configuration, called when user client */
                                        /* calls getsockopt() for the socket */
                                        /* opt is the option number */
                                        /* data points to the data buffer of max lenght len */
                                        /* the controller can directly copy data in the buffer space */
                                        /* and does not need to worry about copying out the data */
                                        /* as long as it respects the max buffer lenght */
                                        /* on input, len contains the maximum buffer length */
                                        /* on output, len contains the actual buffer lenght */
                                        /* if data is NULL on input, then, by convention, the controller */
                                        /* should return in len the lenght of the data it would like */
                                        /* to return in the subsequent call for that option */

    /* prepare the future */
    u_int32_t	ctl_reserved[4];	/* for future use if needed */
};


/* 
 * FUNCTION :
 * Register the controller to the controller manager
 * For example, can be called from a Kernel Extension Start routine
 * 
 * PARAMETERS :
 * userctl : 	Registration structure containing control information
 *          	and callback functions for the controller. 
 *         	Callbacks are optional and can be null.
 *         	A controller with all callbacks set to null would not be very useful.
 * userdata : 	This parameter is for use by the controller and 
 *         	will be passed to every callback function
 * 
 * RETURN CODE :
 * 0 : 		No error
 *     		ctlref will be filled with a control reference, 
 * 		to use in subsequent call to the controller manager
 * EINVAL : 	Invalid registration structure
 * ENOMEM : 	Not enough memory available to register the controller
 * EEXIST : 	Controller id/unit already registered
 */
 
int
ctl_register(struct kern_ctl_reg *userctl, void *userdata, kern_ctl_ref *ctlref);	

/*
 * FUNCTION :
 * Deregister the controller
 * For example, can be called from a Kernel Extension Stop routine
 * 
 * PARAMETERS :
 * ctlref : 	Reference to the controller previously registered
 *
 * RETURN CODE :
 * 0 : 		No error, 
 * 		The controller manager no longer knows about the controller
 * EINVAL : 	Invalid reference
 */
 
int 
ctl_deregister(kern_ctl_ref ctlref);	

/*
 * FUNCTION :
 * Send data to the application in contact with the controller
 * ctl_enqueuedata will allocate a mbuf, copy data and enqueue it.
 *
 * PARAMETERS :
 * ctlref : 	Reference to the controller previously registered
 * data : 	Data to send
 * len : 	Length of the data (maximum lenght of MCLBYTES)
 * flags : 	Flags used when enqueing
 * 		CTL_DATA_NOWAKEUP = just enqueue, don't wake up client
 *
 * RETURN CODE :
 * 0 : 		No error
 * EINVAL: 	Invalid reference
 * EMSGSIZE: 	The buffer is too large
 * ENOTCONN : 	No user client is connected
 * ENOBUFS : 	Socket buffer is full, or can't get a new mbuf
 *              The controller should re-enqueue later
 */
 
int 
ctl_enqueuedata(kern_ctl_ref ctlref, void *data, size_t len, u_int32_t flags);

/*
 * FUNCTION :
 * Send data to the application in contact with the controller
 *
 * PARAMETERS :
 * ctlref : 	Reference to the controller previously registered
 * m : 		mbuf containing the data to send
 * flags : 	Flags used when enqueing
 * 		CTL_DATA_NOWAKEUP = just enqueue, don't wake up client
 *
 * RETURN CODE :
 * 0 : 		No error
 * EINVAL: 	Invalid reference
 * ENOTCONN : 	No user client is connected
 * ENOBUFS : 	Socket buffer is full, 
 *              The controller should either free the mbuf or re-enqueue later
 */
 
int 
ctl_enqueuembuf(kern_ctl_ref ctlref, struct mbuf *m, u_int32_t flags);

#endif /* __APPLE_API_UNSTABLE */
#endif /* KERNEL */

#endif /* SYS_KERN_CONTROL_H */

