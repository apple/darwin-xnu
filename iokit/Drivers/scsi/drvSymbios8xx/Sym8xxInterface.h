/*
 * Copyright (c) 1999 Apple Computer, Inc. All rights reserved.
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

/* Sym8xxInterface.h created by russb2 on Sat 30-May-1998 */

/*
 * This file contains shared data structures between the script and the driver
 *
 */

#define MAX_SCSI_TARGETS		16
#define MAX_SCSI_LUNS			8
#define MAX_SCSI_TAG			256
#define MIN_SCSI_TAG			128

#define kHostAdapterSCSIId		7

#define MAX_SCHED_MAILBOXES		256
#define kMailBoxEmpty			0
#define kMailBoxCancel			1

#define kSCSITimerIntervalMS		250
#define kReqSenseTimeoutMS		3000
#define kAbortTimeoutMS			3000
#define kResetQuiesceDelayMS		3000
#define kAbortScriptTimeoutMS		50

/*
 * NEXUS DATA Structure
 *
 * The Nexus structure contains per-request information for the script/driver
 * to execute a SCSI request.
 */

typedef struct SGEntry
{
    UInt32   			length;
    UInt32   			physAddr;
} SGEntry;

/*
 * Note: There are (3) SG List entries reserved for use by the driver, 
 *       i.e SG Entries 0-1 and the last entry in the list.
 */
#define MAX_SGLIST_ENTRIES	(64+3)

/*
 * This part of the Nexus structure contains the script engine clock registers to
 * be used for this request. This information is also contained in the per-target
 * table (AdapterInterface->targetClocks).
 */
typedef struct NexusParms
{
    UInt8   			reserved_1;
    UInt8   			sxferReg;
    UInt8   			target;
    UInt8   			scntl3Reg;
} NexusParms;

/*
 * Pointers in the Nexus to our CDB/MsgOut data are in this format.
 */
typedef struct NexusData
{
   UInt32   			length;
   UInt32    			ppData;
} NexusData;

typedef struct Nexus 		Nexus;
struct Nexus
{
    NexusParms			targetParms;

    SGEntry        		*ppSGList;

    NexusData			msg;
    NexusData			cdb;

    UInt32   			currentDataPtr;
    UInt32   			savedDataPtr;

    UInt8   			tag;
    UInt8   			dataXferCalled;
    UInt8   			wideResidCount;
    UInt8                       reserved_1[1];

    /*
     * Data buffers for nexus
     */
    UInt8			cdbData[16];
    UInt8                  	msgData[16];
    UInt32   			sgNextIndex;
    SGEntry              	sgListData[MAX_SGLIST_ENTRIES];

};

/*  
 * Abort Bdr Mailbox  
 * 
 * The mailbox is used to send an Abort or Bus Device Reset to a device 
 * This mailbox is 4 bytes long, and all the necessary information are  
 * contained in this mailbox (No nexus Data associated)                 
 */
typedef struct IOAbortBdrMailBox
{
   UInt8      			identify;    /* Identify msg (0xC0) if Abort         		A0 */
   UInt8   			tag;         /* Tag Message or Zero                  		A1 */
   UInt8   			scsi_id;     /* SCSI id of the target of the request 		A2 */
   UInt8   			message;     /* Abort(0x06) or Bdr(0x0C) or AbortTag (0x0D)  	A3 */
} IOAbortBdrMailBox;

/*
 * IODone mailbox  
 *                                                    
 * This mailbox is used to signal the completion of an I/O to the driver.  
 */                       

typedef struct IODoneMailBox 
{
   UInt8      			nexus;      /* Nexus of the completed I/O      */
   UInt8   			status;     /* Status of the completed I/O     */
   UInt8     			zero;
   UInt8      			semaphore;  /* If set, these contents are valid   */
} IODoneMailBox;

/*
 * Adapter Interface
 *
 * This structure contains the shared data between the script and
 * the driver. The script's local variable table is updated to point to the 
 * physical addresses of the data in this control block.
 */

typedef struct TargetClocks
{
    UInt8   			reserved_1;
    UInt8   			sxferReg;
    UInt8   			reserved_2;
    UInt8   			scntl3Reg;
} TargetClocks;

typedef struct AdapterInterface
{
    Nexus                   	**nexusPtrsVirt;
    Nexus                   	**nexusPtrsPhys;

    Nexus			*nexusArrayPhys[MAX_SCSI_TAG];		/* Active SRBs or -1 				*/
    Nexus			*schedMailBox[MAX_SCHED_MAILBOXES];	/* New SRBs					*/
    TargetClocks		targetClocks[MAX_SCSI_TARGETS];

    UInt32   			xferSWideInst[4];

} AdapterInterface;

#define SCRIPT_VAR(x)  ( *(UInt32    *)(chipRamAddr+(x)) )
