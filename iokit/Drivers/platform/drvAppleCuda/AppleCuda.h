/*
 * Copyright (c) 1998-2000 Apple Computer, Inc. All rights reserved.
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
 * Copyright 1996 1995 by Open Software Foundation, Inc. 1997 1996 1995 1994 1993 1992 1991  
 *              All Rights Reserved 
 *  
 * Permission to use, copy, modify, and distribute this software and 
 * its documentation for any purpose and without fee is hereby granted, 
 * provided that the above copyright notice appears in all copies and 
 * that both the copyright notice and this permission notice appear in 
 * supporting documentation. 
 *  
 * OSF DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE 
 * INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS 
 * FOR A PARTICULAR PURPOSE. 
 *  
 * IN NO EVENT SHALL OSF BE LIABLE FOR ANY SPECIAL, INDIRECT, OR 
 * CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM 
 * LOSS OF USE, DATA OR PROFITS, WHETHER IN ACTION OF CONTRACT, 
 * NEGLIGENCE, OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION 
 * WITH THE USE OR PERFORMANCE OF THIS SOFTWARE. 
 * 
 */
/*
 * Copyright 1996 1995 by Apple Computer, Inc. 1997 1996 1995 1994 1993 1992 1991  
 *              All Rights Reserved 
 *  
 * Permission to use, copy, modify, and distribute this software and 
 * its documentation for any purpose and without fee is hereby granted, 
 * provided that the above copyright notice appears in all copies and 
 * that both the copyright notice and this permission notice appear in 
 * supporting documentation. 
 *  
 * APPLE COMPUTER DISCLAIMS ALL WARRANTIES WITH REGARD TO THIS SOFTWARE 
 * INCLUDING ALL IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS 
 * FOR A PARTICULAR PURPOSE. 
 *  
 * IN NO EVENT SHALL APPLE COMPUTER BE LIABLE FOR ANY SPECIAL, INDIRECT, OR 
 * CONSEQUENTIAL DAMAGES OR ANY DAMAGES WHATSOEVER RESULTING FROM 
 * LOSS OF USE, DATA OR PROFITS, WHETHER IN ACTION OF CONTRACT, 
 * NEGLIGENCE, OR OTHER TORTIOUS ACTION, ARISING OUT OF OR IN CONNECTION 
 * WITH THE USE OR PERFORMANCE OF THIS SOFTWARE. 
 */
/*
 * MKLINUX-1.0DR2
 */

/* 1 April 1997 Simon Douglas:
 * Stolen wholesale from MkLinux.
 * Added nonblocking adb poll from interrupt level for the debugger.
 * Acknowledge before response so polled mode can work from inside the adb handler.
 *
 * 18 June 1998 sdouglas
 * Start IOKit version. Fix errors from kCudaSRQAssertMask. Use ool cmd & reply buffers,
 * not fixed len in packet. Does queueing here.
 *
 * 20 Nov 1998 suurballe
 * Port to C++
 */


#include <mach/mach_types.h>

#include <IOKit/IOService.h>

extern "C" {
#include <pexpert/pexpert.h>
}
#include <IOKit/IOLocks.h>
#include "AppleCudaCommands.h"
#include "AppleCudaHW.h"
#include <IOKit/adb/adb.h>
#include <IOKit/pwr_mgt/RootDomain.h>

//
//  CudaInterruptState - internal to CudaCore.c
//

enum CudaInterruptState
{
    CUDA_STATE_INTERRUPT_LIMBO  	= -1,       //
    CUDA_STATE_IDLE         		= 0,        //
    CUDA_STATE_ATTN_EXPECTED    	= 1,        //
    CUDA_STATE_TRANSMIT_EXPECTED    	= 2,        //
    CUDA_STATE_RECEIVE_EXPECTED 	= 3         //
};

typedef enum CudaInterruptState CudaInterruptState;

//
//  CudaTransactionFlag - internal to CudaCore.c
//

enum CudaTransactionFlag
{
    CUDA_TS_NO_REQUEST  	= 0x0000,
    CUDA_TS_SYNC_RESPONSE   	= 0x0001,
    CUDA_TS_ASYNC_RESPONSE  	= 0x0002
};

typedef enum CudaTransactionFlag CudaTransactionFlag;

//typedef void (* ADB_input_func)(IOService * obj_id, UInt8 * buffer, UInt32 length, UInt8 command);

class IOCudaADBController;
class IOInterruptEventSource;
class IOWorkLoop;


class AppleCuda: public IOService
{
OSDeclareDefaultStructors(AppleCuda)

private:

IOService *			cudaDevice;
IOWorkLoop *			workLoop;
IOService *			ADBid;
IOCudaADBController *		ourADBinterface;
ADB_callback_func		autopoll_handler;
UInt8                           _cuda_power_state;
// callPlatformFunction symbols
const OSSymbol 	*cuda_check_any_interrupt;

	// number of autopoll buffers between interrupt and thread
#define NUM_AP_BUFFERS (1<<3)
	// max adb register size for autopoll
#define MAX_AP_RESPONSE (8)

unsigned char			cuda_autopoll_buffers[ NUM_AP_BUFFERS ]
						     [ MAX_AP_RESPONSE ];

protected:

virtual void free( void );

public:

VIARegisterAddress   		cuda_via_regs;
bool				cuda_polled_mode;
IOSimpleLock *			cuda_request_lock;
volatile cuda_request_t *	cuda_request;		// head of todo queue
volatile cuda_request_t *	cuda_last_request;	// tail of todo queue
volatile CudaInterruptState	cuda_interrupt_state;
volatile unsigned int		inIndex;
volatile unsigned int		outIndex;
volatile CudaTransactionFlag	cuda_transaction_state;
cuda_packet_t    		cuda_unsolicited[ NUM_AP_BUFFERS ];
bool	  		 	cuda_is_header_transfer;
int     			cuda_transfer_count;
IOInterruptEventSource * 	eventSrc;
cuda_packet_t *			cuda_current_response;
bool	   			cuda_is_packet_type;
AbsoluteTime			cuda_state_transition_delay;
IOPMrootDomain *                _rootDomain;

bool init ( OSDictionary * properties = 0 );
bool start ( IOService * );
virtual IOWorkLoop *getWorkLoop() const;
void serviceAutopolls ( void );
void registerForADBInterrupts ( ADB_callback_func handler, IOService * caller );
IOReturn doSyncRequest ( cuda_request_t * request );
IOReturn powerStateWillChangeTo ( IOPMPowerFlags, unsigned long, IOService*);
IOReturn powerStateDidChangeTo ( IOPMPowerFlags, unsigned long, IOService*);
virtual IOReturn callPlatformFunction(const OSSymbol *functionName,
					bool waitForFunction,
                                        void *param1, void *param2,
                                        void *param3, void *param4);

};

