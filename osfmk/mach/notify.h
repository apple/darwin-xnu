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
 * HISTORY
 * 
 * Revision 1.1.1.1  1998/09/22 21:05:30  wsanchez
 * Import of Mac OS X kernel (~semeria)
 *
 * Revision 1.1.1.1  1998/03/07 02:25:46  wsanchez
 * Import of OSF Mach kernel (~mburg)
 *
 * Revision 1.2.12.2  1996/01/09  19:22:05  devrcs
 * 	Made not_count in mach_no_senders_notification_t
 * 	a mach_msg_type_number_t.
 * 	[1995/12/01  19:49:21  jfraser]
 *
 * 	Merged '64-bit safe' changes from DEC alpha port.
 * 	[1995/11/21  18:09:14  jfraser]
 *
 * Revision 1.2.12.1  1994/09/23  02:41:27  ezf
 * 	change marker to not FREE
 * 	[1994/09/22  21:42:15  ezf]
 * 
 * Revision 1.2.6.5  1993/09/09  16:07:46  jeffc
 * 	CR9745 - delete message accepted notifications
 * 	[1993/09/03  22:15:11  jeffc]
 * 
 * Revision 1.2.6.4  1993/08/05  19:09:35  jeffc
 * 	CR9508 - Delete dead code. Remove MACH_IPC_TYPED
 * 	[1993/08/03  20:18:41  jeffc]
 * 
 * 	CR9508 - Delete dead code. Remove MACH_IPC_COMPAT
 * 	[1993/08/03  17:09:19  jeffc]
 * 
 * Revision 1.2.6.3  1993/08/03  18:29:46  gm
 * 	CR9596: Change KERNEL to MACH_KERNEL.
 * 	[1993/08/02  18:24:51  gm]
 * 
 * Revision 1.2.6.2  1993/06/09  02:42:49  gm
 * 	Fix untyped notifications. CR #8969
 * 	[1993/04/27  11:29:30  rod]
 * 
 * Revision 1.2  1993/04/19  16:38:19  devrcs
 * 	Added trailer support to untyped ipc.	[travos@osf.org, fdr@osf.org]
 * 	[1993/04/06  18:28:00  travos]
 * 	Merge untyped ipc:
 * 	Remove the NDR format label from messages with no untyped data
 * 	[1993/03/12  22:50:02  travos]
 * 	changed msgh_body to not_body in the notification message structures.
 * 	[1993/02/25  21:50:38  fdr]
 * 	New definitions for notifications (via compile option MACH_IPC_TYPED)
 * 	[1993/02/24  19:25:42  travos]
 * 
 * 	ansi C conformance changes
 * 	[1993/02/02  18:54:03  david]
 * 	Revision 1.1  1992/09/30  02:31:55  robert
 * 	Initial revision
 * 	[1993/02/02  19:05:08  david]
 * 
 * $EndLog$
 */
/* CMU_HIST */
/*
 * Revision 2.4.2.1  92/03/03  16:22:23  jeffreyh
 * 	Changes form TRUNK
 * 	[92/02/26  12:12:10  jeffreyh]
 * 
 * Revision 2.5  92/01/15  13:44:41  rpd
 * 	Changed MACH_IPC_COMPAT conditionals to default to not present.
 * 
 * Revision 2.4  91/05/14  16:58:21  mrt
 * 	Correcting copyright
 * 
 * Revision 2.3  91/02/05  17:35:18  mrt
 * 	Changed to new Mach copyright
 * 	[91/02/01  17:20:02  mrt]
 * 
 * Revision 2.2  90/06/02  14:59:32  rpd
 * 	Converted to new IPC.
 * 	[90/03/26  22:38:14  rpd]
 * 
 * Revision 2.7.7.1  90/02/20  22:24:32  rpd
 * 	Revised for new IPC.
 * 	[90/02/19  23:38:57  rpd]
 * 
 *
 * Condensed history:
 *	Moved ownership rights under MACH_IPC_XXXHACK (rpd).
 * 	Added NOTIFY_PORT_DESTROYED (rpd).
 *	Added notification message structure definition (mwyoung).
 *	Created, based on Accent values (mwyoung).
 */
/* CMU_ENDHIST */
/* 
 * Mach Operating System
 * Copyright (c) 1991,1990,1989,1988,1987 Carnegie Mellon University
 * All Rights Reserved.
 * 
 * Permission to use, copy, modify and distribute this software and its
 * documentation is hereby granted, provided that both the copyright
 * notice and this permission notice appear in all copies of the
 * software, derivative works or modified versions, and any portions
 * thereof, and that both notices appear in supporting documentation.
 * 
 * CARNEGIE MELLON ALLOWS FREE USE OF THIS SOFTWARE IN ITS "AS IS"
 * CONDITION.  CARNEGIE MELLON DISCLAIMS ANY LIABILITY OF ANY KIND FOR
 * ANY DAMAGES WHATSOEVER RESULTING FROM THE USE OF THIS SOFTWARE.
 * 
 * Carnegie Mellon requests users of this software to return to
 * 
 *  Software Distribution Coordinator  or  Software.Distribution@CS.CMU.EDU
 *  School of Computer Science
 *  Carnegie Mellon University
 *  Pittsburgh PA 15213-3890
 * 
 * any improvements or extensions that they make and grant Carnegie Mellon
 * the rights to redistribute these changes.
 */
/*
 */
/*
 *	File:	mach/notify.h
 *
 *	Kernel notification message definitions.
 */

#ifndef	_MACH_NOTIFY_H_
#define _MACH_NOTIFY_H_

#include <mach/port.h>
#include <mach/message.h>
#include <mach/ndr.h>

/*
 *  An alternative specification of the notification interface
 *  may be found in mach/notify.defs.
 */

#define MACH_NOTIFY_FIRST		0100
#define MACH_NOTIFY_PORT_DELETED	(MACH_NOTIFY_FIRST + 001 )
			/* A send or send-once right was deleted. */
#define MACH_NOTIFY_PORT_DESTROYED	(MACH_NOTIFY_FIRST + 005)
			/* A receive right was (would have been) deallocated */
#define MACH_NOTIFY_NO_SENDERS		(MACH_NOTIFY_FIRST + 006)
			/* Receive right has no extant send rights */
#define MACH_NOTIFY_SEND_ONCE		(MACH_NOTIFY_FIRST + 007)
			/* An extant send-once right died */
#define MACH_NOTIFY_DEAD_NAME		(MACH_NOTIFY_FIRST + 010)
			/* Send or send-once right died, leaving a dead-name */
#define MACH_NOTIFY_LAST		(MACH_NOTIFY_FIRST + 015)

typedef struct {
    mach_msg_header_t	not_header;
    NDR_record_t	NDR;
    mach_port_name_t not_port;/* MACH_MSG_TYPE_PORT_NAME */
    mach_msg_format_0_trailer_t trailer;
} mach_port_deleted_notification_t;

typedef struct {
    mach_msg_header_t	not_header;
    mach_msg_body_t	not_body;
    mach_msg_port_descriptor_t not_port;/* MACH_MSG_TYPE_PORT_RECEIVE */
    mach_msg_format_0_trailer_t trailer;
} mach_port_destroyed_notification_t;

typedef struct {
    mach_msg_header_t	not_header;
    NDR_record_t	NDR;
    mach_msg_type_number_t not_count;
    mach_msg_format_0_trailer_t trailer;
} mach_no_senders_notification_t;

typedef struct {
    mach_msg_header_t	not_header;
    mach_msg_format_0_trailer_t trailer;
} mach_send_once_notification_t;

typedef struct {
    mach_msg_header_t	not_header;
    NDR_record_t	NDR;
    mach_port_name_t not_port;/* MACH_MSG_TYPE_PORT_NAME */
    mach_msg_format_0_trailer_t trailer;
} mach_dead_name_notification_t;

#endif	/* _MACH_NOTIFY_H_ */
