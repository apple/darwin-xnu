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
/* InitGlobals.c 
 *
 * From v01.08 06/06/90 mbs
 *    Modified for MP, 1996 by Tuyen Nguyen
 *   Modified, April 9, 1997 by Tuyen Nguyen for MacOSX.
 */

#include <sys/errno.h>
#include <sys/types.h>
#include <sys/param.h>
#include <machine/spl.h>
#include <sys/systm.h>
#include <sys/kernel.h>
#include <sys/proc.h>
#include <sys/filedesc.h>
#include <sys/fcntl.h>
#include <sys/mbuf.h>
#include <sys/socket.h>
#include <sys/time.h>

#include <netat/sysglue.h>
#include <netat/appletalk.h>
#include <netat/at_pcb.h>
#include <netat/debug.h>
#include <netat/adsp.h>
#include <netat/adsp_internal.h>

/*
 * InitGlobals
 * 
 * INPUTS:
 * 		none
 * OUTPUTS:
 * 		none
 */
void InitGlobals()
{

	adspGlobal.lastCID = (random() & 0xffff);
	adspGlobal.inTimer = 0;
	TimerTick();		/* start the ADSP timer */

}


/*
 * CleanupGlobals
 * 
 * INPUTS:
 * 		none
 * OUTPUTS:
 * 		none
 */

void CleanupGlobals() 
{
	TimerStop();
}
