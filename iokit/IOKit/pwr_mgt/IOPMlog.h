/*
 * Copyright (c) 1998-2000 Apple Computer, Inc. All rights reserved.
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
#define PMlogSetParent			1
#define PMlogAddChild			2
#define PMlogRemoveChild			3
#define PMlogControllingDriver		4
#define PMlogControllingDriverErr1		5	/* bad power state array version */
#define PMlogControllingDriverErr2		6	/* too many power states */
#define PMlogControllingDriverErr3		7	/* not a real IOPMDriver */
#define PMlogControllingDriverErr4		8	/* power state change in progress */
#define PMlogInterestedDriver		9
#define PMlogAcknowledgeErr1		10	/* unknown entity called acknowledgePowerChange */
#define PMlogChildAcknowledge		11
#define PMlogDriverAcknowledge		12	/* interested driver acknowledges */
#define PMlogAcknowledgeErr2		13	/* object has already acked */
#define PMlogAcknowledgeErr3		14	/* not expecting any acks */
#define PMlogAcknowledgeErr4		15	/* not expecting acknowledgeSetPowerState */
#define PMlogDriverAcknowledgeSet		16	/* controlling driver acknowledges */
#define PMlogWillChange			17
#define PMlogDidChange			18
#define PMlogRequestDomain		19
#define PMlogMakeUsable			20
#define PMlogChangeStateTo		21
#define PMlogChangeStateToPriv		22
#define PMlogSetAggressiveness		23
#define PMlogCriticalTemp			24
#define PMlogOverrideOn			25
#define PMlogOverrideOff			26
#define PMlogEnqueueErr			27	/* change queue overflow */
#define PMlogCollapseQueue			28
#define PMlogChangeDone			29
#define PMlogCtrlDriverTardy		30	/* controlling driver didn't acknowledge */
#define PMlogIntDriverTardy			31	/* interested driver didn't acknowledge */
#define PMlogStartAckTimer			32
#define PMlogStartParentChange		33
#define PMlogAmendParentChange		34
#define PMlogStartDeviceChange		35
#define PMlogRequestDenied			36	/* parent denied domain state change request */
#define PMlogControllingDriverErr5		37	/* zero power states or we already have a driver with more power states */
#define PMlogProgramHardware		38
#define PMlogInformDriverPreChange	39
#define PMlogInformDriverPostChange	40
#define PMlogRemoveDriver			41
#define PMsetIdleTimerPeriod		42
#define PMlogSystemWake			43
#define PMlogAcknowledgeErr5		44
#define PMlogClientAcknowledge		45
#define PMlogClientTardy		46		/* application or kernel client didn't acknowledge */
#define PMlogClientCancel		47
