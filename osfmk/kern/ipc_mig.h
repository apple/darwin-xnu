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

#ifndef	_IPC_MIG_H_
#define	_IPC_MIG_H_

#include <mach/message.h>
#include <sys/kdebug.h>

/*
 * Define the trace points for MIG-generated calls.  One traces the input parameters
 * to MIG called things, another traces the outputs, and one traces bad message IDs.
 */
#ifdef _MIG_TRACE_PARAMETERS_

#define __BeforeRcvCallTrace(msgid,arg1,arg2,arg3,arg4)				      \
	KERNEL_DEBUG_CONSTANT(KDBG_MIGCODE(msgid) | DBG_FUNC_START,		      \
			      (unsigned int)(arg1),				      \
			      (unsigned int)(arg2),				      \
			      (unsigned int)(arg3),				      \
			      (unsigned int)(arg4),				      \
			      (unsigned int)(0));

#define __AfterRcvCallTrace(msgid,arg1,arg2,arg3,arg4)				      \
	KERNEL_DEBUG_CONSTANT(KDBG_MIGCODE(msgid) | DBG_FUNC_END,		      \
			      (unsigned int)(arg1),				      \
			      (unsigned int)(arg2),				      \
			      (unsigned int)(arg3),				      \
			      (unsigned int)(arg4),				      \
			      (unsigned int)(0));

#define __BeforeSimpleCallTrace(msgid,arg1,arg2,arg3,arg4)			      \
	KERNEL_DEBUG_CONSTANT(KDBG_MIGCODE(msgid) | DBG_FUNC_START,		      \
			      (unsigned int)(arg1),				      \
			      (unsigned int)(arg2),				      \
			      (unsigned int)(arg3),				      \
			      (unsigned int)(arg4),				      \
			      (unsigned int)(0));

#define __AfterSimpleCallTrace(msgid,arg1,arg2,arg3,arg4)			      \
	KERNEL_DEBUG_CONSTANT(KDBG_MIGCODE(msgid) | DBG_FUNC_END,		      \
			      (unsigned int)(arg1),				      \
			      (unsigned int)(arg2),				      \
			      (unsigned int)(arg3),				      \
			      (unsigned int)(arg4),				      \
			      (unsigned int)(0));

#else /* !_MIG_TRACE_PARAMETERS_ */

#define	__BeforeRcvRpc(msgid, _NAME_)						      \
	KERNEL_DEBUG_CONSTANT(KDBG_MIGCODE(msgid) | DBG_FUNC_START,		      \
			      (unsigned int)(0),				      \
			      (unsigned int)(0),				      \
			      (unsigned int)(0),				      \
			      (unsigned int)(0),				      \
			      (unsigned int)(0));

#define	__AfterRcvRpc(msgid, _NAME_)						      \
	KERNEL_DEBUG_CONSTANT(KDBG_MIGCODE(msgid) | DBG_FUNC_END,		      \
			      (unsigned int)(0),				      \
			      (unsigned int)(0),				      \
			      (unsigned int)(0),				      \
			      (unsigned int)(0),				      \
			      (unsigned int)(0));


#define	__BeforeRcvSimple(msgid, _NAME_)					      \
	KERNEL_DEBUG_CONSTANT(KDBG_MIGCODE(msgid) | DBG_FUNC_START,		      \
			      (unsigned int)(0),				      \
			      (unsigned int)(0),				      \
			      (unsigned int)(0),				      \
			      (unsigned int)(0),				      \
			      (unsigned int)(0));

#define	__AfterRcvSimple(msgid, _NAME_)						      \
	KERNEL_DEBUG_CONSTANT(KDBG_MIGCODE(msgid) | DBG_FUNC_END,		      \
			      (unsigned int)(0),				      \
			      (unsigned int)(0),				      \
			      (unsigned int)(0),				      \
			      (unsigned int)(0),				      \
			      (unsigned int)(0));

#endif /* !_MIG_TRACE_PARAMETERS_ */

#define _MIG_MSGID_INVALID(msgid)						      \
	KERNEL_DEBUG_CONSTANT(MACHDBG_CODE(DBG_MACH_MSGID_INVALID, (msgid)),          \
			      (unsigned int)(0),				      \
			      (unsigned int)(0),				      \
			      (unsigned int)(0),				      \
			      (unsigned int)(0),				      \
			      (unsigned int)(0))

/* Send a message from the kernel */
extern mach_msg_return_t mach_msg_send_from_kernel(
	mach_msg_header_t	*msg,
	mach_msg_size_t		send_size);


extern mach_msg_return_t mach_msg_rpc_from_kernel(
	mach_msg_header_t	*msg,
	mach_msg_size_t		send_size,
	mach_msg_size_t		rcv_size);

extern void mach_msg_receive_continue(void);

#endif	/* _IPC_MIG_H_ */
