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
 * Mach RPC Subsystem Interfaces
 */

#ifndef	_MACH_RPC_H_
#define _MACH_RPC_H_

#include <mach/boolean.h>
#include <mach/kern_return.h>
#include <mach/port.h>
#include <mach/vm_types.h>

#include <mach/mig.h>
#include <mach/mig_errors.h>
#include <mach/machine/rpc.h>
#include <mach/thread_status.h>

#ifdef	MACH_KERNEL_PRIVATE
#include <ipc/ipc_object.h>
#endif	/* MACH_KERNEL_PRIVATE */

/*
 * The various bits of the type field of the routine_arg_descriptor
 */

/* The basic types */

#define TYPE_SHIFT                      0
#define MACH_RPC_PORT			(1 << TYPE_SHIFT)
#define MACH_RPC_ARRAY                  (1 << (TYPE_SHIFT + 1))
#define MACH_RPC_VARIABLE               (1 << (TYPE_SHIFT + 2))
#define LAST_TYPE_BIT                   (TYPE_SHIFT+3)

/* XXX Port arrays need not be variable arrays, as assumed below. Fixme. */
#define MACH_RPC_ARRAY_FIX		(MACH_RPC_ARRAY)
#define MACH_RPC_ARRAY_FIXED		(MACH_RPC_ARRAY)
#define MACH_RPC_ARRAY_VAR		(MACH_RPC_ARRAY | MACH_RPC_VARIABLE)
#define MACH_RPC_ARRAY_VARIABLE		(MACH_RPC_ARRAY | MACH_RPC_VARIABLE)
#define MACH_RPC_PORT_ARRAY		(MACH_RPC_PORT  | MACH_RPC_ARRAY_VAR)

/* Argument direction bits */

#define DIRECT_SHIFT            	LAST_TYPE_BIT
#define DIRECTION_SHIFT                 LAST_TYPE_BIT
#define MACH_RPC_IN			(1 << DIRECTION_SHIFT)
#define MACH_RPC_OUT			(1 << (DIRECTION_SHIFT + 1))
#define LAST_DIRECT_BIT         	(DIRECTION_SHIFT + 2)
#define LAST_DIRECTION_BIT              (DIRECTION_SHIFT + 2)

#define MACH_RPC_INOUT			(MACH_RPC_IN | MACH_RPC_OUT)

/* Persist and pointer bit */

#define POINTER_SHIFT                   LAST_DIRECTION_BIT
#define MACH_RPC_POINTER                (1 << POINTER_SHIFT)
#define LAST_POINTER_BIT                (POINTER_SHIFT + 1)

/* Port disposition bits */

#define NAME_SHIFT                    	LAST_POINTER_BIT
#define MACH_RPC_RECEIVE                (1 << NAME_SHIFT)
#define MACH_RPC_SEND                   (2 << NAME_SHIFT)
#define MACH_RPC_SEND_ONCE              (3 << NAME_SHIFT)
#define LAST_NAME_BIT			(NAME_SHIFT + 2)

#define ACTION_SHIFT			LAST_NAME_BIT
#define MACH_RPC_MOVE                   (1 << ACTION_SHIFT)
#define MACH_RPC_COPY                   (2 << ACTION_SHIFT)
#define MACH_RPC_MAKE                   (3 << ACTION_SHIFT)
#define LAST_ACTION_BIT                 (ACTION_SHIFT + 2)

#define MACH_RPC_MOVE_RECEIVE		(MACH_RPC_MOVE | MACH_RPC_RECEIVE)
#define MACH_RPC_MOVE_SEND		(MACH_RPC_MOVE | MACH_RPC_SEND)
#define MACH_RPC_COPY_SEND		(MACH_RPC_COPY | MACH_RPC_SEND)
#define MACH_RPC_MAKE_SEND		(MACH_RPC_MAKE | MACH_RPC_SEND)
#define MACH_RPC_MOVE_SEND_ONCE		(MACH_RPC_MOVE | MACH_RPC_SEND_ONCE)
#define MACH_RPC_MAKE_SEND_ONCE		(MACH_RPC_MAKE | MACH_RPC_SEND_ONCE)

/* Hint for virtual vs. physical copy */ 

#define OPTION_SHIFT                    LAST_ACTION_BIT
#define MACH_RPC_PHYSICAL_COPY		(1 << OPTION_SHIFT)
#define MACH_RPC_VIRTUAL_COPY		(1 << (OPTION_SHIFT + 1))
#define LAST_OPTION_BIT                 (OPTION_SHIFT + 2)

/* Deallocate? */

#define DEALLOCATE_SHIFT                LAST_OPTION_BIT
#define MACH_RPC_DEALLOCATE		(1 << DEALLOCATE_SHIFT)
#define LAST_DEALLOCATE_BIT             (DEALLOCATE_SHIFT + 1)

/* Argument is already on the stack */

#define ONSTACK_SHIFT                   LAST_DEALLOCATE_BIT
#define MACH_RPC_ONSTACK		(1 << ONSTACK_SHIFT)
#define LAST_ONSTACK_BIT                (ONSTACK_SHIFT + 1)

/* Is variable array bounded? Derived from type and arg.size */

#define BOUND_SHIFT			LAST_ONSTACK_BIT
#define MACH_RPC_BOUND			(1 << BOUND_SHIFT)
#define MACH_RPC_UNBOUND		(0)
#define BOUND				MACH_RPC_BOUND
#define UNBND				MACH_RPC_UNBOUND
#define LAST_BOUND_BIT			(BOUND_SHIFT + 1)

/*
 * Basic mach rpc types.
 */
typedef unsigned int    routine_arg_type;
typedef unsigned int	routine_arg_offset;
typedef unsigned int	routine_arg_size;

/*
 * Definitions for a signature's argument and routine descriptor's.
 */
struct routine_arg_descriptor {
	routine_arg_type	type;	   /* Port, Array, etc. */
        routine_arg_size        size;      /* element size in bytes */
        routine_arg_size        count;     /* number of elements */
	routine_arg_offset	offset;	   /* Offset in list of routine args */
};
typedef struct routine_arg_descriptor *routine_arg_descriptor_t;

struct routine_descriptor {
	mig_impl_routine_t	impl_routine;	/* Server work func pointer   */
	mig_stub_routine_t	stub_routine;	/* Unmarshalling func pointer */
	unsigned int		argc;		/* Number of argument words   */
	unsigned int		descr_count;	/* Number of complex argument */
					        /* descriptors                */
	struct routine_arg_descriptor *
				arg_descr;	/* Pointer to beginning of    */
						/* the arg_descr array        */
	unsigned int		max_reply_msg;	/* Max size for reply msg     */
};
typedef struct routine_descriptor *routine_descriptor_t;

#define DESCR_SIZE(x) ((x)->descr_count * sizeof(struct routine_arg_descriptor))

struct rpc_signature {
    struct routine_descriptor rd;
    struct routine_arg_descriptor rad[1];
};

#ifdef	MACH_KERNEL_PRIVATE

typedef struct rpc_signature *rpc_signature_t;

#endif

#define RPC_SIGBUF_SIZE 8
/*
 *	A subsystem describes a set of server routines that can be invoked by
 *	mach_rpc() on the ports that are registered with the subsystem.  For
 *	each routine, the routine number is given, along with the
 *	address of the implementation function in the server and a
 *	description of the arguments of the routine (it's "signature").
 *
 *	This structure definition is only a template for what is really a
 *	variable-length structure (generated by MIG for each subsystem).
 *	The actual structures do not always have one entry in the routine
 *	array, and also have a varying number of entries in the arg_descr
 *	array.  Each routine has an array of zero or more arg descriptors
 *	one for each complex arg.  These arrays are all catenated together
 *	to form the arg_descr field of the subsystem struct.  The
 *	arg_descr field of each routine entry points to a unique sub-sequence
 *	within this catenated array.  The goal is to keep everything
 *	contiguous.
 */
struct rpc_subsystem {
	struct subsystem *subsystem;	/* Reserved for system use */

	mach_msg_id_t	start;		/* Min routine number */
	mach_msg_id_t	end;		/* Max routine number + 1 */
	unsigned int	maxsize;	/* Max mach_msg size */
	vm_address_t	base_addr;	/* Address of this struct in user */

	struct routine_descriptor	/* Array of routine descriptors */
			routine[1       /* Actually, (start-end+1) */
				 ];

	struct routine_arg_descriptor
			arg_descriptor[1   /* Actually, the sum of the descr_ */
					]; /* count fields for all routines   */
};
typedef struct rpc_subsystem  *rpc_subsystem_t;

#define RPC_SUBSYSTEM_NULL	((rpc_subsystem_t) 0)

/* 
 * 	New RPC declarations
 *
 *	First pass at definitions and types for the new rpc service.
 *	This is subject to revision.
 */

/*
 *	RPC macros
 */

#define RPC_MASK(shift,last)                                            \
        ( ((1 << ((last)-(shift)))-1) << (shift) )

#define RPC_FIELD(field,shift,last)                                     \
        ( (field) & (((1 << ((last)-(shift)))-1) << (shift)) )

#define RPC_BOUND(dsc)                                                  \
        (((RPC_FIELD((dsc).type,TYPE_SHIFT+1,TYPE_SHIFT+3) ==           \
           MACH_RPC_ARRAY_VARIABLE) && (dsc).count != 0) ? MACH_RPC_BOUND : 0)

#define ROUNDUP2(x,n)    ((((unsigned)(x)) + (n) - 1) & ~((n)-1))
#define ROUNDWORD(x)    ROUNDUP2(x,sizeof(int))

/*
 *      RPC errors
 *
 *      Display and process errors of different severity, from just for
 *      information only to fatal (panic). Error code colors indicate how
 *      difficult it is for the subsystem to handle the error correctly.
 *      The implication is that, for example, early versions of the code may
 *      not be handling code red errors properly. The code should use this
 *      facility instead of regular printf's.
 */

#define	MACH_RPC_DEBUG	1

#define ERR_INFO        1               /* purely informational */
#define ERR_GREEN       2               /* easily handled error */
#define ERR_YELLOW      3               /* medium difficult error */
#define ERR_RED         4               /* difficult to handle error */
#define ERR_FATAL       5               /* unrecoverable error, panic */

#if MACH_RPC_DEBUG > 1
#define rpc_error(E,S)                                                  \
        printf("RPC error ");                                           \
        rpc_error_show_severity(S);                                     \
        printf("in file \"%s\", line %d: ", __FILE__, __LINE__);        \
        printf E ;                                                      \
        printf("\n");                                                   \
        rpc_error_severity(S)
#else
#define rpc_error(E,S)                                                  \
	if ((S) == ERR_FATAL || (S) == ERR_RED) {			\
        printf("RPC error ");                                           \
        rpc_error_show_severity(S);                                     \
        printf("in file \"%s\", line %d: ", __FILE__, __LINE__);        \
        printf E ;                                                      \
        printf("\n");                                                   \
        rpc_error_severity(S);						\
	}
#endif	/* MACH_RPC_DEBUG */

/*
 *      RPC buffer size and break points
 *
 *      These values define the rpc buffer size on the kernel stack,
 *      and break point values for switching to virtual copy (cow).
 *      This should be in a machine dependent include file. All sizes
 *      are in word (sizeof(int)) units.
 */

#define RPC_KBUF_SIZE   16              /* kernel stack buffer size (ints) */
#define RPC_COW_SIZE    1024            /* size where COW is a win (ints) */
#define RPC_DESC_COUNT  4               /* default descriptor count */


/*
 *      RPC copy state
 *
 *      Record the rpc copy state for arrays, so we can unwind our state
 *      during error processing. There is one entry per complex (signatured)
 *      argument. The first entry is marked COPY_TYPE_ALLOC_KRN if this record
 *      itself was kalloc'd because the number of complex arg descriptors
 *      exceeded the default value (RPC_DESC_COUNT). This is not a conflict
 *      since the first argument is always the destination port, never an array.
 */

#define COPY_TYPE_NO_COPY               0       /* nothing special */
#define COPY_TYPE_ON_KSTACK             1       /* array is on kernel stack */
#define COPY_TYPE_ON_SSTACK             2       /* array is on server stack */
#define COPY_TYPE_VIRTUAL_IN            3       /* vm_map_copyin part of cow */
#define COPY_TYPE_VIRTUAL_OUT_SVR       4       /* map cpyout svr part of cow */
#define COPY_TYPE_VIRTUAL_OUT_CLN       5       /* map cpyout cln part of cow */
#define COPY_TYPE_ALLOC_KRN             6       /* kernel kalloc'd for array */
#define COPY_TYPE_ALLOC_SVR             7       /* vm_alloc'd in server space */
#define COPY_TYPE_ALLOC_CLN             8       /* vm_alloc'd in client space */
#define COPY_TYPE_PORT                  9       /* plain port translated */
#define COPY_TYPE_PORT_ARRAY            10      /* port array translated */


/*
 * 	RPC types
 */
typedef int 			rpc_id_t;
typedef int 			rpc_return_t;
typedef unsigned int		rpc_size_t;
typedef unsigned int		rpc_offset_t;

struct rpc_copy_state {
        unsigned                copy_type;      /* what kind of copy */
        vm_offset_t             alloc_addr;     /* address to free */
};
typedef struct rpc_copy_state *rpc_copy_state_t;
typedef struct rpc_copy_state  rpc_copy_state_data_t;

typedef boolean_t (*copyfunc_t)(const char *, char *, vm_size_t);


/*
 *	RPC function declarations
 */

#ifdef	CALLOUT_RPC_MODEL

extern
void            rpc_bootstrap( void );

extern
void            rpc_remote_bootstrap( void );

extern 
rpc_return_t	mach_rpc_trap(
				mach_port_name_t	dest_port,
				rpc_id_t		routine_num,
				rpc_signature_t	signature_ptr,
				rpc_size_t 	signature_size );
										
extern 
rpc_return_t	mach_rpc_return_trap( void );

extern 
rpc_return_t	mach_rpc_return_error( void );

void			mach_rpc_return_wrapper( void );

void            	rpc_upcall( 
				vm_offset_t		stack,
				vm_offset_t		new_stack, 
				vm_offset_t		server_func, 
				int 			return_code );

void            	rpc_error_severity( int severity );
void            	rpc_error_show_severity( int severity );
unsigned int    	name_rpc_to_ipc( unsigned int action );

void			clean_port_array(
				ipc_object_t *		array,
				unsigned		count,
				unsigned		cooked,
				unsigned		direct );

void            	unwind_rpc_state( 
				routine_descriptor_t	routine, 
				rpc_copy_state_t	state, 
				int * 			arg_buf );

kern_return_t		unwind_invoke_state( 
				thread_act_t		thr_act );

kern_return_t   	rpc_invke_args_in( 
				routine_descriptor_t	routine, 
				rpc_copy_state_t	state,
				int *			arg_buf,
				copyfunc_t		infunc );

kern_return_t   	rpc_invke_args_out( 
				routine_descriptor_t	routine, 
				rpc_copy_state_t	state,
				int *			arg_buf, 
				int ** 			new_sp,
				copyfunc_t		outfunc );

kern_return_t   	rpc_reply_args_in( 
				routine_descriptor_t	routine, 
				rpc_copy_state_t	state,
				int *			svr_buf,
				copyfunc_t		infunc );

kern_return_t   	rpc_reply_args_out( 
				routine_descriptor_t	routine, 
				rpc_copy_state_t	state,
				int *			svr_buf, 
				int * 			cln_buf,
				copyfunc_t		outfunc );

#endif  /* CALLOUT_RPC_MODEL */

/*
 * libmach helper functions:
 */
extern rpc_subsystem_t	mach_subsystem_join(
				rpc_subsystem_t,
				rpc_subsystem_t,
				unsigned int *,
				void *(* )(int));

#endif	/* _MACH_RPC_H_ */


