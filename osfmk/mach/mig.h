/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
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
 * @OSF_COPYRIGHT@
 */

/*
 * Mach MIG Subsystem Interfaces
 */

#ifndef	_MACH_MIG_H_
#define _MACH_MIG_H_

#include <mach/port.h>
#include <mach/message.h>
#include <mach/kern_return.h>

/*
 * Definition for MIG-generated server stub routines.  These routines
 * unpack the request message, call the server procedure, and pack the
 * reply message.
 */
typedef void	(*mig_stub_routine_t) (mach_msg_header_t *InHeadP,
				       mach_msg_header_t *OutHeadP);

typedef mig_stub_routine_t mig_routine_t;

/*
 * Definition for MIG-generated server routine.  This routine takes a
 * message, and returns the appropriate stub function for handling that
 * message.
 */
typedef mig_routine_t (*mig_server_routine_t) (mach_msg_header_t *InHeadP);

/*
 * Generic definition for implementation routines.  These routines do
 * the real work associated with this request.  This generic type is
 * used for keeping the pointers in the subsystem array.
 */
typedef kern_return_t   (*mig_impl_routine_t)(void);

typedef struct mig_routine_descriptor {
	mig_stub_routine_t	 stub_routine;	/* Unmarshalling function   */
	mach_msg_size_t		 max_reply_msg; /* Max size for this reply  */
} mig_routine_descriptor;
typedef mig_routine_descriptor  *mig_routine_descriptor_t;

typedef struct mig_subsystem {
	mig_server_routine_t	 server;	/* server routine	    */
	mach_msg_id_t		 start;		/* Min routine number	    */
	mach_msg_id_t		 end;		/* Max routine number + 1   */
	mach_msg_size_t		 max_reply;	/* Max reply message size   */
	mach_msg_size_t		 max_request;	/* Max request msg size     */
	mig_routine_descriptor   routine[1];	/* Routine descriptor array */
} *mig_subsystem_t;

#ifdef	KERNEL_PRIVATE
/*
 * MIG object runtime definitions
 *
 * Conforming MIG subsystems may enable this support to get
 * significant assistance from the base mig_object_t implementation.
 *
 * Support includes:
 *	- Transparency from port manipulation.
 *	- Dymanic port allocation on first "remoting" of an object.
 *	- Reference conversions from object to port and vice versa.
 *	- Automatic port deallocation on no-more-senders.
 *	- Support for multiple server implementations in a single space.
 *	- Messaging bypass for local servers.
 *	- Automatic hookup to base dispatch mechanism.
 *	- General notification support
 * Coming soon:
 *	- User-level support
 */
typedef unsigned int 				mig_notify_type_t;

typedef struct MIGIID {
	unsigned long				data1;
	unsigned short				data2;
	unsigned short				data3;
	unsigned char				data4[8];
} MIGIID;

typedef struct IMIGObjectVtbl			IMIGObjectVtbl;
typedef struct IMIGNotifyObjectVtbl		IMIGNotifyObjectVtbl;

typedef struct IMIGObject {
	IMIGObjectVtbl				*pVtbl;
} IMIGObject;

typedef struct IMIGNotifyObject {
	IMIGNotifyObjectVtbl			*pVtbl;
} IMIGNotifyObject;

struct IMIGObjectVtbl {
	kern_return_t (*QueryInterface)(
			IMIGObject		*object,
			const MIGIID		*iid,
			void			**ppv);

	unsigned long (*AddRef)(
			IMIGObject		*object);

	unsigned long (*Release)(	
			IMIGObject		*object);

	unsigned long (*GetServer)(
			IMIGObject		*object,
			mig_server_routine_t 	*server);
	    
	boolean_t (*RaiseNotification)(
			IMIGObject 		*object,
			mig_notify_type_t	notify_type);

	boolean_t (*RequestNotification)(
			IMIGObject		*object,
			IMIGNotifyObject	*notify,
			mig_notify_type_t	notify_type);
};		

/*
 * IMIGNotifyObject
 *
 * A variant of the IMIGObject interface that is a sink for
 * MIG notifications.
 *
 * A reference is held on both the subject MIGObject and the target
 * MIGNotifyObject. Because of this, care must be exercised to avoid
 * reference cycles.  Once a notification is raised, the object
 * reference is returned and the request must be re-requested (if
 * desired).
 *
 * One interesting note:  because this interface is itself a MIG
 * object, one may request notification about state changes in
 * the MIGNotifyObject itself.
 */
struct IMIGNotifyObjectVtbl {
	kern_return_t (*QueryInterface)(
			IMIGNotifyObject	*notify,
			const MIGIID		*iid,
			void			**ppv);

	unsigned long (*AddRef)(	
			IMIGNotifyObject	*notify);

	unsigned long (*Release)(	
			IMIGNotifyObject	*notify);

	unsigned long (*GetServer)(
			IMIGNotifyObject	*notify,
			mig_server_routine_t	*server);

	boolean_t (*RaiseNotification)(
			IMIGNotifyObject	*notify,
			mig_notify_type_t	notify_type);

	boolean_t (*RequestNotification)(
			IMIGNotifyObject	*notify,
			IMIGNotifyObject	*notify_notify,
			mig_notify_type_t	notify_type);

	void (*HandleNotification)(
			IMIGNotifyObject	*notify,
			IMIGObject		*object,
			mig_notify_type_t	notify_type);
};

#endif /* KERNEL_PRIVATE */

#endif /* _MACH_MIG_H_ */
