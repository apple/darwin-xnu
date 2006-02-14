/*
 * Copyright (c) 2000-2005 Apple Computer, Inc. All rights reserved.
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

#include <stdint.h>
#include <mach/port.h>
#include <mach/message.h>
#include <mach/vm_types.h>

#include <sys/cdefs.h>

#if defined(MACH_KERNEL)

/* Turn MIG type checking on by default for kernel */
#define __MigTypeCheck 1
#define __MigKernelSpecificCode 1
#define _MIG_KERNEL_SPECIFIC_CODE_ 1

/* Otherwise check legacy setting (temporary) */
#elif defined(TypeCheck)  

#define __MigTypeCheck TypeCheck
 
#endif /* defined(TypeCheck) */

/*
 * Pack MIG message structs if we have Power alignment of structs.
 * This is an indicator of the need to view shared structs in a
 * binary-compatible format - and MIG message structs are no different.
 */
#if __DARWIN_ALIGN_POWER
#define __MigPackStructs 1
#endif

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

typedef mach_msg_type_descriptor_t routine_arg_descriptor;
typedef mach_msg_type_descriptor_t *routine_arg_descriptor_t;
typedef mach_msg_type_descriptor_t *mig_routine_arg_descriptor_t;

#define MIG_ROUTINE_ARG_DESCRIPTOR_NULL ((mig_routine_arg_descriptor_t)0)

struct routine_descriptor {
	mig_impl_routine_t	impl_routine;	/* Server work func pointer   */
	mig_stub_routine_t	stub_routine;	/* Unmarshalling func pointer */
	unsigned int		argc;			/* Number of argument words   */
	unsigned int		descr_count;	/* Number complex descriptors */
	routine_arg_descriptor_t
						arg_descr;		/* pointer to descriptor array*/
	unsigned int		max_reply_msg;	/* Max size for reply msg     */
};
typedef struct routine_descriptor *routine_descriptor_t;

typedef struct routine_descriptor mig_routine_descriptor;
typedef mig_routine_descriptor *mig_routine_descriptor_t;

#define MIG_ROUTINE_DESCRIPTOR_NULL ((mig_routine_descriptor_t)0)

typedef struct mig_subsystem {
	mig_server_routine_t server;		/* pointer to demux routine	*/
	mach_msg_id_t		 start;			/* Min routine number	    */
	mach_msg_id_t		 end;			/* Max routine number + 1   */
	mach_msg_size_t		 maxsize;		/* Max reply message size   */
	vm_address_t		 reserved;		/* reserved for MIG use	    */
	mig_routine_descriptor
						 routine[1];	/* Routine descriptor array */
} *mig_subsystem_t;

#define MIG_SUBSYSTEM_NULL		((mig_subsystem_t)0)

typedef struct mig_symtab {
	char				*ms_routine_name;
	int					ms_routine_number;
	void    			(*ms_routine)(void);	/* Since the functions in the
					 							 * symbol table have unknown
												 * signatures, this is the best
					 							 * we can do...
					 							 */
} mig_symtab_t;

#ifdef	PRIVATE

/* MIG object runtime - not ready for public consumption */

#ifdef  KERNEL_PRIVATE

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
typedef unsigned int 			mig_notify_type_t;

typedef struct MIGIID {
	unsigned long				data1;
	unsigned short				data2;
	unsigned short				data3;
	unsigned char				data4[8];
} MIGIID;

typedef struct IMIGObjectVtbl			IMIGObjectVtbl;
typedef struct IMIGNotifyObjectVtbl		IMIGNotifyObjectVtbl;

typedef struct IMIGObject {
	const IMIGObjectVtbl			*pVtbl;
} IMIGObject;

typedef struct IMIGNotifyObject {
	const IMIGNotifyObjectVtbl		*pVtbl;
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

#endif	/* KERNEL_PRIVATE */
#endif  /* PRIVATE */

__BEGIN_DECLS

/* Client side reply port allocate */
extern mach_port_t mig_get_reply_port(void);

/* Client side reply port deallocate */
extern void mig_dealloc_reply_port(mach_port_t reply_port);

/* Client side reply port "deallocation" */
extern void mig_put_reply_port(mach_port_t reply_port);

/* Bounded string copy */
extern int mig_strncpy(char	*dest, const char *src,	int	len);

#ifdef KERNEL_PRIVATE

/* Allocate memory for out-of-stack mig structures */
extern char *mig_user_allocate(vm_size_t size);

/* Deallocate memory used for out-of-stack mig structures */
extern void mig_user_deallocate(char *data, vm_size_t size);

#else

/* Allocate memory for out-of-line mig structures */
extern void mig_allocate(vm_address_t *, vm_size_t);

/* Deallocate memory used for out-of-line mig structures */
extern void mig_deallocate(vm_address_t, vm_size_t);

#endif /* KERNEL_PRIVATE */

__END_DECLS

#endif	/* _MACH_MIG_H_ */
