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
 * @APPLE_FREE_COPYRIGHT@
 */
/*
 * HISTORY
 * 
 * Revision 1.1.1.1  1998/09/22 21:05:43  wsanchez
 * Import of Mac OS X kernel (~semeria)
 *
 * Revision 1.1.1.1  1998/03/07 02:26:05  wsanchez
 * Import of OSF Mach kernel (~mburg)
 *
 * Revision 1.1.9.4  1997/05/09  15:36:59  barbou
 * 	Moved "video" funnel declaration to video_board.h.
 * 	[97/05/09            barbou]
 *
 * Revision 1.1.9.3  1997/05/08  19:33:07  barbou
 * 	SMP support:
 * 	Funnelized the "video" driver.
 * 	[1997/05/08  18:20:34  barbou]
 * 
 * Revision 1.1.9.2  1997/01/27  15:27:31  stephen
 * 	Export new set/get_status
 * 	VC_GETKEYBOARDLEDS/VC_SETKEYBOARDLEDS
 * 	[1997/01/27  15:27:01  stephen]
 * 
 * Revision 1.1.9.1  1996/12/09  16:52:52  stephen
 * 	nmklinux_1.0b3_shared into pmk1.1
 * 	[1996/12/09  10:57:12  stephen]
 * 
 * Revision 1.1.7.4  1996/10/18  08:25:16  stephen
 * 	Added v_rowscanbytes field
 * 	[1996/10/18  08:24:11  stephen]
 * 
 * Revision 1.1.7.3  1996/10/14  18:36:33  stephen
 * 	Added v_rows, v_volumns
 * 	Removed sys/ioctl.h inclusion
 * 	File is now exported from microkernel
 * 	[1996/10/14  18:24:17  stephen]
 * 
 * Revision 1.1.7.2  1996/08/23  09:24:10  stephen
 * 	Added guards around file
 * 	[1996/08/23  09:23:05  stephen]
 * 
 * Revision 1.1.7.1  1996/06/20  12:53:46  stephen
 * 	added VM_TYPE_AV
 * 	[1996/06/20  12:51:04  stephen]
 * 
 * Revision 1.1.4.3  1996/05/28  10:47:39  stephen
 * 	Added HPV video capability
 * 	[1996/05/28  10:45:10  stephen]
 * 
 * Revision 1.1.4.2  1996/05/03  17:26:06  stephen
 * 	Added APPLE_FREE_COPYRIGHT
 * 	[1996/05/03  17:20:05  stephen]
 * 
 * Revision 1.1.4.1  1996/04/11  09:06:47  emcmanus
 * 	Copied from mainline.ppc.
 * 	[1996/04/10  17:01:34  emcmanus]
 * 
 * Revision 1.1.2.2  1996/03/14  12:58:25  stephen
 * 	Various new definitions from Mike
 * 	[1996/03/14  12:21:30  stephen]
 * 
 * Revision 1.1.2.1  1996/02/08  17:37:58  stephen
 * 	created
 * 	[1996/02/08  17:32:46  stephen]
 * 
 * $EndLog$
 */

#ifndef _POWERMAC_VIDEO_CONSOLE_H_
#define _POWERMAC_VIDEO_CONSOLE_H_


struct vc_info {
	unsigned long	v_height;	/* pixels */
	unsigned long	v_width;	/* pixels */
	unsigned long	v_depth;
	unsigned long	v_rowbytes;
	unsigned long	v_baseaddr;
	unsigned long	v_type;
	char		v_name[32];
	unsigned long	v_physaddr;
	unsigned long	v_rows;		/* characters */
	unsigned long	v_columns;	/* characters */
	unsigned long	v_rowscanbytes;	/* Actualy number of bytes used for display per row*/
					/* Note for PCI (VCI) systems, part of the row byte line
					  is used for the hardware cursor which is not to be touched */
	unsigned long	v_reserved[5];
};

#endif /* _POWERMAC_VIDEO_CONSOLE_H_ */
