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


#include "AppleCuda.h"
#include "IOCudaADBController.h"
#include <IOKit/IOLib.h>
#include <IOKit/IOSyncer.h>
#include <IOKit/IOWorkLoop.h>
#include <IOKit/IOInterruptEventSource.h>
#include <IOKit/IODeviceMemory.h>
#include <IOKit/IOPlatformExpert.h>
#include <IOKit/pwr_mgt/IOPM.h> 

#include <IOKit/assert.h>

#define super IOService
OSDefineMetaClassAndStructors(AppleCuda,IOService)

static  void 	cuda_interrupt ( AppleCuda * self );

static  void    cuda_process_response(AppleCuda * self);
static  void    cuda_transmit_data(AppleCuda * self);
static  void    cuda_expected_attention(AppleCuda * self);
static  void    cuda_unexpected_attention(AppleCuda * self);
static  void    cuda_receive_data(AppleCuda * self);
static  void    cuda_receive_last_byte(AppleCuda * self);
static  void    cuda_collision(AppleCuda * self);
static  void    cuda_idle(AppleCuda * self);

static  void    cuda_poll(AppleCuda * self);
static  void    cuda_error(AppleCuda * self);
static  void    cuda_send_request(AppleCuda * self);
static IOReturn cuda_do_sync_request( AppleCuda * self,
		cuda_request_t * request, bool polled);
static	void	cuda_do_state_transition_delay(AppleCuda * self);

static int Cuda_PE_poll_input(unsigned int options, char * c);
static int Cuda_PE_read_write_time_of_day(unsigned int options, long * secs);
static int Cuda_PE_halt_restart(unsigned int type);
static int Cuda_PE_write_IIC(unsigned char addr, unsigned char reg,
				unsigned char data);

static void
autopollArrived ( OSObject *inCuda, IOInterruptEventSource *, int );

static int set_cuda_power_message ( int command );
static int set_cuda_file_server_mode ( int command );
static void cuda_async_set_power_message_enable( thread_call_param_t param, thread_call_param_t );
static void cuda_async_set_file_server_mode( thread_call_param_t param, thread_call_param_t ) ;

bool CudahasRoot( OSObject * us, void *, IOService * yourDevice );


//
// inline functions
//

static __inline__ unsigned char cuda_read_data(AppleCuda * self)
{
    volatile unsigned char val;

    val = *self->cuda_via_regs.shift; eieio();
    return val;
}

static __inline__ int cuda_get_result(cuda_request_t *request)
{
    int status = ADB_RET_OK;
    int theStatus = request->a_reply.a_header[1];
    
    if ( theStatus & kCudaTimeOutMask ) {
        status = ADB_RET_TIMEOUT;
#if 0
    // these are expected before autopoll mask is set
    } else if ( theStatus & kCudaSRQAssertMask ) {
        status = ADB_RET_UNEXPECTED_RESULT;
#endif
    } else if ( theStatus & kCudaSRQErrorMask ) {
        status = ADB_RET_REQUEST_ERROR;
    } else if ( theStatus & kCudaBusErrorMask ) {
        status = ADB_RET_BUS_ERROR;
    }

    return status;
}

static __inline__ void cuda_lock(AppleCuda * self)
{
    if( !self->cuda_polled_mode)
        IOSimpleLockLock(self->cuda_request_lock);
}

static __inline__ void cuda_unlock(AppleCuda * self)
{
    if( !self->cuda_polled_mode)
        IOSimpleLockUnlock(self->cuda_request_lock);
}

//
// 
//


static AppleCuda * gCuda;
// **********************************************************************************
// init
//
// **********************************************************************************
bool AppleCuda::init ( OSDictionary * properties = 0 )
{
return super::init(properties);
}


// **********************************************************************************
// start
//
// **********************************************************************************
bool AppleCuda::start ( IOService * nub )
{
int i;
IOMemoryMap * viaMap;
unsigned char * cuda_base;

if( !super::start(nub))
    return false;

gCuda = this;
  // callPlatformFunction symbols
  cuda_check_any_interrupt = OSSymbol::withCString("cuda_check_any_interrupt");

workLoop = NULL;
eventSrc = NULL;
ourADBinterface = NULL;
_rootDomain = 0; 

workLoop = IOWorkLoop::workLoop();
if ( !workLoop ) {
        kprintf("Start is bailing\n");
	return false;
}

eventSrc = IOInterruptEventSource::interruptEventSource(this, autopollArrived);
if (!eventSrc || 
	kIOReturnSuccess != workLoop->addEventSource(eventSrc) ) {
        kprintf("Start is bailing\n");
	return false;
}

if( 0 == (viaMap = nub->mapDeviceMemoryWithIndex( 0 )) ) {
	IOLog("%s: no via memory\n", getName());
        kprintf("Start is bailing\n");
	return false;
}
cuda_base = (unsigned char *)viaMap->getVirtualAddress();

kprintf("VIA base = %08x\n", (UInt32)cuda_base);
ourADBinterface = new IOCudaADBController;
if ( !ourADBinterface ) {
        kprintf("Start is bailing\n");
	return false;
}
if ( !ourADBinterface->init(0,this) ) {
        kprintf("Start is bailing\n");
        return false;
}

if ( !ourADBinterface->attach( this) ) {
        kprintf("Start is bailing\n");
        return false;
}

cuda_request_lock = IOSimpleLockAlloc();
IOSimpleLockInit(cuda_request_lock);

cuda_via_regs.dataB         	    = cuda_base;
cuda_via_regs.handshakeDataA        = cuda_base+0x0200;
cuda_via_regs.dataDirectionB        = cuda_base+0x0400;
cuda_via_regs.dataDirectionA        = cuda_base+0x0600;
cuda_via_regs.timer1CounterLow      = cuda_base+0x0800;
cuda_via_regs.timer1CounterHigh     = cuda_base+0x0A00;
cuda_via_regs.timer1LatchLow        = cuda_base+0x0C00;
cuda_via_regs.timer1LatchHigh       = cuda_base+0x0E00;
cuda_via_regs.timer2CounterLow      = cuda_base+0x1000;
cuda_via_regs.timer2CounterHigh     = cuda_base+0x1200;
cuda_via_regs.shift         	    = cuda_base+0x1400;
cuda_via_regs.auxillaryControl      = cuda_base+0x1600;
cuda_via_regs.peripheralControl     = cuda_base+0x1800;
cuda_via_regs.interruptFlag    	    = cuda_base+0x1A00;
cuda_via_regs.interruptEnable       = cuda_base+0x1C00;
cuda_via_regs.dataA         	    = cuda_base+0x1E00;

// we require delays of this duration between certain state transitions
clock_interval_to_absolutetime_interval(200, 1, &cuda_state_transition_delay);

// Set the direction of the cuda signals.  ByteACk and TIP are output and
// TREQ is an input

*cuda_via_regs.dataDirectionB |= (kCudaByteAcknowledgeMask | kCudaTransferInProgressMask);
*cuda_via_regs.dataDirectionB &= ~kCudaTransferRequestMask;

// Set the clock control.  Set to shift data in by external clock CB1.

*cuda_via_regs.auxillaryControl = (*cuda_via_regs.auxillaryControl | kCudaTransferMode) &
								kCudaSystemRecieve;

// Clear any posible cuda interupt.

if ( *cuda_via_regs.shift );

// Initialize the internal data.

cuda_interrupt_state    = CUDA_STATE_IDLE;
cuda_transaction_state  = CUDA_TS_NO_REQUEST;
cuda_is_header_transfer = false;
cuda_is_packet_type 	= false;
cuda_transfer_count 	= 0;
cuda_current_response   = NULL;
for( i = 0; i < NUM_AP_BUFFERS; i++ ) {
	cuda_unsolicited[ i ].a_buffer = cuda_autopoll_buffers[ i ];
}

// Terminate transaction and set idle state

cuda_neg_tip_and_byteack(this);

// we want to delay 4 mS for ADB reset to complete

IOSleep( 4 );

// Clear pending interrupt if any...

(void)cuda_read_data(this);

// Issue a Sync Transaction, ByteAck asserted while TIP is negated.

cuda_assert_byte_ack(this);

// Wait for the Sync acknowledgement, cuda to assert TREQ

cuda_wait_for_transfer_request_assert(this);

// Wait for the Sync acknowledgement interrupt.

cuda_wait_for_interrupt(this);

// Clear pending interrupt

(void)cuda_read_data(this);

// Terminate the sync cycle by Negating ByteAck

cuda_neg_byte_ack(this);

// Wait for the Sync termination acknowledgement, cuda negates TREQ.

cuda_wait_for_transfer_request_neg(this);

// Wait for the Sync termination acknowledgement interrupt.

cuda_wait_for_interrupt(this);

// Terminate transaction and set idle state, TIP negate and ByteAck negate.
cuda_neg_transfer_in_progress(this);

// Clear pending interrupt, if there is one...
(void)cuda_read_data(this);

#if 0
        cuda_polled_mode = true;
#else
#define	VIA_DEV_CUDA		2
nub->registerInterrupt(VIA_DEV_CUDA,
                       this, (IOInterruptAction) cuda_interrupt);
nub->enableInterrupt(VIA_DEV_CUDA);
#endif

PE_poll_input = Cuda_PE_poll_input;
PE_read_write_time_of_day = Cuda_PE_read_write_time_of_day;
PE_halt_restart = Cuda_PE_halt_restart;
PE_write_IIC = Cuda_PE_write_IIC;
publishResource( "IOiic0", this );
publishResource( "IORTC", this );


//set_cuda_power_message(kADB_powermsg_enable); //won't work on beige G3
thread_call_func(cuda_async_set_power_message_enable, (thread_call_param_t)this, true);
thread_call_func(cuda_async_set_file_server_mode, (thread_call_param_t)this, true);

    registerService();	//Gossamer needs to find this driver for waking up G3

    _cuda_power_state = 1;  //default is wake state
    //We want to know when sleep is about to occur
    addNotification( gIOPublishNotification,serviceMatching("IOPMrootDomain"),
                 (IOServiceNotificationHandler)CudahasRoot, this, 0 );

ourADBinterface->start( this );

return true;
}

/* Here are some power management functions so we can tell when system is
    going to sleep. */
bool CudahasRoot( OSObject * us, void *, IOService * yourDevice )
{
    if (( yourDevice != NULL ) && ((AppleCuda *)us)->_rootDomain == 0)
    {
        ((AppleCuda *)us)->_rootDomain = (IOPMrootDomain *) yourDevice;
        ((IOPMrootDomain *)yourDevice)->registerInterestedDriver((IOService *) us);
    }
    return true;
}   
 
IOReturn AppleCuda::powerStateWillChangeTo ( IOPMPowerFlags theFlags, unsigned long unused1,
    IOService* unused2)
{
//kprintf("will change to %x", theFlags);
    if ( ! (theFlags & IOPMPowerOn) )
    {
        _cuda_power_state = 0;  //0 means sleeping
    }
    return IOPMAckImplied;
}

IOReturn AppleCuda::powerStateDidChangeTo ( IOPMPowerFlags theFlags, unsigned long unused1,
    IOService* unused2)
{
//kprintf("did change to %x", theFlags);
    if (theFlags & IOPMPowerOn)
    {
        _cuda_power_state = 1;  //1 means awake
    }
    return IOPMAckImplied;
}



// *****************************************************************************
// getWorkLoop
//
// Return the cuda's workloop.
//
// *****************************************************************************
IOWorkLoop *AppleCuda::getWorkLoop() const
{
    return workLoop;
}

// *****************************************************************************
// free
//
// Release everything we may have allocated.
//
// *****************************************************************************
void AppleCuda::free ( void )
{
if ( workLoop ) {
	workLoop->release();
}
if ( eventSrc ) {
	eventSrc->release();
}
if ( ourADBinterface ) {
	ourADBinterface->release();
}
    if (_rootDomain) 
    {
        _rootDomain->deRegisterInterestedDriver((IOService *) this); 
        _rootDomain = 0;
    }
super::free();
}


// **********************************************************************************
// registerForADBInterrupts
//
// Some driver is calling to say it is prepared to receive "unsolicited" adb
// interrupts (e.g. autopoll keyboard and trackpad data).  The parameters identify
// who to call when we get one.
// **********************************************************************************
void AppleCuda::registerForADBInterrupts ( ADB_callback_func handler, IOService * caller )
{
autopoll_handler = handler;
ADBid = caller;
}


// **********************************************************************************
// autopollArrived
//
// **********************************************************************************
static void autopollArrived ( OSObject * CudaDriver, IOInterruptEventSource *, int )
{
((AppleCuda *)CudaDriver)->serviceAutopolls();
}

#define RB_BOOT		1	/* Causes reboot, not halt.  Is in xnu/bsd/sys/reboot.h */
extern "C" {
	void boot(int paniced, int howto, char * command);
}


static void cuda_async_set_power_message_enable( thread_call_param_t param, thread_call_param_t )
{
    //AppleCuda * me = (AppleCuda *) param;

    set_cuda_power_message(kADB_powermsg_enable);
}

static void cuda_async_set_file_server_mode( thread_call_param_t param, thread_call_param_t )
{
    set_cuda_file_server_mode(1); 
}   
        
// **********************************************************************************
// serviceAutopolls
//      We get here just before calling autopollHandler() in IOADBController.cpp
// **********************************************************************************
void AppleCuda::serviceAutopolls ( void )
{
cuda_packet_t *	response;

  while( inIndex != outIndex ) {

        response = &cuda_unsolicited[ outIndex ];

        //Check for power messages, which are handled differently from regular
        //  autopoll data coming from mouse or keyboard.
        if (response->a_header[0] == ADB_PACKET_POWER)
        {
                unsigned char flag, cmd;

                flag = response->a_header[1];
                cmd  = response->a_header[2];

                if ((flag == kADB_powermsg_flag_chassis)
                &&  (cmd == kADB_powermsg_cmd_chassis_off))
                {
                        thread_call_func(cuda_async_set_power_message_enable,
                                (thread_call_param_t)this, true);

                        if (_rootDomain)
                        {
                            if (_cuda_power_state)
                            {
                                //Put system to sleep now
                                _rootDomain->receivePowerNotification (kIOPMSleepNow);
                            }
                            else //If asleep, wake up the system
                            {
                                //Tickle activity timer in root domain.  This will not
                                // wake up machine that is in demand-sleep, but it will
                                // wake up an inactive system that dozed
                                _rootDomain->activityTickle(0,0);
                            }
                        }
                }
		else if ((flag == kADB_powermsg_flag_keyboardpwr)
                &&  (cmd == kADB_powermsg_cmd_keyboardoff))
		{
			//set_cuda_power_message(kADB_powermsg_continue);
			//This needs to by async so Beige G3 ADB won't lock up
    			thread_call_func(cuda_async_set_power_message_enable, 
				(thread_call_param_t)this, true);
		}

        }

        if ( ADBid != NULL ) {
           (*autopoll_handler)(ADBid,response->a_header[2],response->a_bcount,response->a_buffer);
        }

        outIndex = (outIndex + 1) & (NUM_AP_BUFFERS - 1);

  } //end of while loop

}


// **********************************************************************************
// doSyncRequest
//
// **********************************************************************************
IOReturn AppleCuda::doSyncRequest ( cuda_request_t * request )
{
return(cuda_do_sync_request(this, request, false));
}


IOReturn AppleCuda::callPlatformFunction(const OSSymbol *functionName,
						    bool waitForFunction,
						    void *param1, void *param2,
						    void *param3, void *param4)
{  
    if (functionName == cuda_check_any_interrupt)
    {
	bool	*hasint;
	
	hasint = (bool *)param1;
	*hasint = false;

	if (inIndex != outIndex)
	{
	    *hasint = true;
	}
	return kIOReturnSuccess;
    }
    
    return kIOReturnBadArgument;
}


// **********************************************************************************
// cuda_do_sync_request
//
// **********************************************************************************
IOReturn cuda_do_sync_request ( AppleCuda * self, cuda_request_t * request, bool polled )
{
    bool		wasPolled = false;
    IOInterruptState	ints;

    if( !polled ) {
        request->sync = IOSyncer::create();
	request->needWake = true;
    }

    ints = IOSimpleLockLockDisableInterrupt(self->cuda_request_lock);

    if( polled ) {
        wasPolled = self->cuda_polled_mode;
        self->cuda_polled_mode = polled;
    }

    if( self->cuda_last_request )
	self->cuda_last_request->a_next = request;
    else
	self->cuda_request = request;

    self->cuda_last_request = request;

    if( self->cuda_interrupt_state == CUDA_STATE_IDLE )
	cuda_send_request(self);

    if( polled ) {
        cuda_poll(self);
        self->cuda_polled_mode = wasPolled;
        assert( 0 == self->cuda_request );
        assert( 0 == self->cuda_last_request );
    }

    IOSimpleLockUnlockEnableInterrupt(self->cuda_request_lock, ints);

    if( !polled)
	request->sync->wait();

    return cuda_get_result(request);
}


// **********************************************************************************
// Cuda_PE_read_write_time_of_day
//
// **********************************************************************************
static int Cuda_PE_read_write_time_of_day ( unsigned int options, long * secs )
{
cuda_request_t cmd;

adb_init_request(&cmd);

cmd.a_cmd.a_hcount = 2;
cmd.a_cmd.a_header[0] = ADB_PACKET_PSEUDO;

switch( options ) {

	case kPEReadTOD:
            cmd.a_cmd.a_header[1] = ADB_PSEUDOCMD_GET_REAL_TIME;
            cmd.a_reply.a_buffer = (UInt8 *)secs;
            cmd.a_reply.a_bcount = sizeof(*secs);
	    break;

	case kPEWriteTOD:
            cmd.a_cmd.a_header[1] = ADB_PSEUDOCMD_SET_REAL_TIME;
            cmd.a_cmd.a_buffer = (UInt8 *)secs;
            cmd.a_cmd.a_bcount = sizeof(*secs);
	    break;

	default:
	    return 1;
}

return cuda_do_sync_request(gCuda, &cmd, true);
}


// **********************************************************************************
// Cuda_PE_halt_restart
//
// **********************************************************************************
static int Cuda_PE_halt_restart ( unsigned int type )
{
cuda_request_t cmd;

adb_init_request(&cmd);

cmd.a_cmd.a_hcount = 2;
cmd.a_cmd.a_header[0] = ADB_PACKET_PSEUDO;

switch( type ) {

	case kPERestartCPU:
            cmd.a_cmd.a_header[1] = ADB_PSEUDOCMD_RESTART_SYSTEM;
	    break;

	case kPEHaltCPU:
            cmd.a_cmd.a_header[1] = ADB_PSEUDOCMD_POWER_DOWN;
	    break;

	default:
	    return 1;
    }

return cuda_do_sync_request(gCuda, &cmd, true);
}


// **********************************************************************************
// In case this machine loses power, it will automatically reboot when power is
//   restored.  Only desktop machines have Cuda, so this feature will not affect
//   PowerBooks.
// **********************************************************************************
static int set_cuda_file_server_mode ( int command )
{ 
cuda_request_t cmd;
    
adb_init_request(&cmd); 

cmd.a_cmd.a_hcount = 3;
cmd.a_cmd.a_header[0] = ADB_PACKET_PSEUDO;
cmd.a_cmd.a_header[1] = ADB_PSEUDOCMD_FILE_SERVER_FLAG;
cmd.a_cmd.a_header[2] = command;
        
return cuda_do_sync_request(gCuda, &cmd, true);
}       

// **********************************************************************************
// Fix front panel power key (mostly on Yosemites) so that one press won't power
//   down the entire machine
//
// **********************************************************************************
static int set_cuda_power_message ( int command )
{
cuda_request_t cmd;

if (command >= kADB_powermsg_invalid)
	return 0;  //invalid Cuda power request

adb_init_request(&cmd);

cmd.a_cmd.a_hcount = 3;
cmd.a_cmd.a_header[0] = ADB_PACKET_PSEUDO;
cmd.a_cmd.a_header[1] = ADB_PSEUDOCMD_SET_POWER_MESSAGES;
cmd.a_cmd.a_header[2] = command;

return cuda_do_sync_request(gCuda, &cmd, true);
}


// **********************************************************************************
// Cuda_PE_write_IIC
//
// **********************************************************************************
static int Cuda_PE_write_IIC ( unsigned char addr, unsigned char reg, unsigned char data )
{
cuda_request_t cmd;

adb_init_request(&cmd);

cmd.a_cmd.a_header[0] = ADB_PACKET_PSEUDO;
cmd.a_cmd.a_header[1] = ADB_PSEUDOCMD_GET_SET_IIC;
cmd.a_cmd.a_header[2] = addr;
cmd.a_cmd.a_header[3] = reg;
cmd.a_cmd.a_header[4] = data;
cmd.a_cmd.a_hcount = 5;

return cuda_do_sync_request(gCuda, &cmd, true);
}

IOReturn
AppleCudaWriteIIC( UInt8 address, const UInt8 * buffer, IOByteCount * count )
{
    IOReturn	   ret;
    cuda_request_t cmd;
    
    if( !gCuda)
        return( kIOReturnUnsupported );

    adb_init_request(&cmd);

    cmd.a_cmd.a_header[0] = ADB_PACKET_PSEUDO;
    cmd.a_cmd.a_header[1] = ADB_PSEUDOCMD_GET_SET_IIC;
    cmd.a_cmd.a_header[2] = address;
    cmd.a_cmd.a_hcount    = 3;
    cmd.a_cmd.a_buffer    = (UInt8 *) buffer;
    cmd.a_cmd.a_bcount    = *count;

    ret = cuda_do_sync_request(gCuda, &cmd, true);

    *count = cmd.a_cmd.a_bcount;

    return( ret );
}

IOReturn
AppleCudaReadIIC( UInt8 address, UInt8 * buffer, IOByteCount * count )
{
    IOReturn	   ret;
    cuda_request_t cmd;
    
    if( !gCuda)
        return( kIOReturnUnsupported );

    adb_init_request(&cmd);

    cmd.a_cmd.a_header[0] = ADB_PACKET_PSEUDO;
    cmd.a_cmd.a_header[1] = ADB_PSEUDOCMD_GET_SET_IIC;
    cmd.a_cmd.a_header[2] = address;
    cmd.a_cmd.a_hcount    = 3;
    cmd.a_reply.a_buffer  = buffer;
    cmd.a_reply.a_bcount  = *count;

    ret = cuda_do_sync_request(gCuda, &cmd, true);
    *count = cmd.a_reply.a_bcount;

    return( ret );
}


// **********************************************************************************
// Cuda_PE_poll_input
//
// **********************************************************************************
static int Cuda_PE_poll_input ( unsigned int, char * c )
{
AppleCuda * 	self = gCuda;
int 		interruptflag;
UInt8		code;
cuda_packet_t *	response;	  //0123456789abcdef
static char	keycodes2ascii[] = "asdfhgzxcv_bqwer"	//00
				"yt123465=97-80]o"	//10
				"u[ip\nlj'k;_,/nm."	//20
				"\t_";			//30

*c = 0xff;

if( !self ) {
	return 1;
}

self->cuda_polled_mode = true;
interruptflag = *self->cuda_via_regs.interruptFlag & kCudaInterruptMask;
eieio();
if( interruptflag ) {
	cuda_interrupt(self);
}

if( self->inIndex != self->outIndex ) {
	response = &self->cuda_unsolicited[ self->outIndex ];
	if( ((response->a_header[2] >> 4) == 2)
		&&  (response->a_bcount > 1) ) {
		code = response->a_buffer[0];
		if( code < sizeof(keycodes2ascii) ) {
			*c = keycodes2ascii[ code ];
		}
	}
        self->outIndex = self->inIndex;
}

self->cuda_polled_mode = false;
return 0;
}


//
// internal
//


// **********************************************************************************
// cuda_send_request
//
// **********************************************************************************
static void cuda_send_request ( AppleCuda * self )
{

    // The data register must written with the data byte 25uS
    // after examining TREQ or we run the risk of getting out of sync
    // with Cuda. So call with disabled interrupts and spinlock held.

    // Check if we can commence with the packet transmission.  First, check if
    // Cuda can service our request now.  Second, check if Cuda wants to send
    // a response packet now.

if( !cuda_is_transfer_in_progress(self) ) {
    // Set the shift register direction to output to Cuda by setting
    // the direction bit.

        cuda_set_data_direction_to_output(self);

        // Write the first byte to the shift register
        cuda_write_data(self, self->cuda_request->a_cmd.a_header[0]);

        // Set up the transfer state info here.

        self->cuda_is_header_transfer = true;
        self->cuda_transfer_count = 1;

        // Make sure we're in idle state before transaction, and then
        // assert TIP to tell Cuda we're starting command
        cuda_neg_byte_ack(self);
        cuda_assert_transfer_in_progress(self);

        // The next state is going to be a transmit state, if there is
        // no collision.  This is a requested response but call it sync.

        self->cuda_interrupt_state = CUDA_STATE_TRANSMIT_EXPECTED;
        self->cuda_transaction_state = CUDA_TS_SYNC_RESPONSE;
} 

#if 0
else {
	IOLog("Req = %x, state = %x, TIP = %x\n", self->cuda_request,
        self->cuda_interrupt_state, cuda_is_transfer_in_progress(self));
}
#endif
}


// **********************************************************************************
// cuda_poll
//
// **********************************************************************************
static void cuda_poll( AppleCuda * self )
{
    do {
        cuda_wait_for_interrupt(self);
	cuda_interrupt(self);
    } while( self->cuda_interrupt_state != CUDA_STATE_IDLE );
}

//
//  cuda_process_response
//  Execute at secondary interrupt.
//


// **********************************************************************************
// cuda_process_response
//
// **********************************************************************************
static void cuda_process_response ( AppleCuda * self )
{
volatile cuda_request_t *	request;
unsigned int			newIndex;

    // Almost ready for the next state, which should be a Idle state.
    // Just need to notifiy the client.

if ( self->cuda_transaction_state == CUDA_TS_SYNC_RESPONSE ) {

        // dequeue reqeuest
        cuda_lock(self);
        request = self->cuda_request;
        if( NULL == (self->cuda_request = request->a_next) ) {
            self->cuda_last_request = NULL;
	}
        cuda_unlock(self);

        // wake the sync request thread
        if ( ((cuda_request_t *)request)->needWake ) {
            ((cuda_request_t *)request)->sync->signal();
	}

}
else {
	if ( self->cuda_transaction_state == CUDA_TS_ASYNC_RESPONSE ) {
        	newIndex = (self->inIndex + 1) & (NUM_AP_BUFFERS - 1);
        	if( newIndex != self->outIndex ) {
       			self->inIndex = newIndex;
        	}
		else {
            		// drop this packet, and reuse the buffer
        	}
        	if ( !self->cuda_polled_mode ) {
            		// wake thread to service autopolls
            		self->eventSrc->interruptOccurred(0, 0, 0);
		}
        }
}
return;
}


// **********************************************************************************
// cuda_interrupt
//
// **********************************************************************************
static void cuda_interrupt ( AppleCuda * self )
{
unsigned char interruptState;

    // Get the relevant signal in determining the cause of the interrupt:
    // the shift direction, the transfer request line and the transfer
    // request line.

interruptState = cuda_get_interrupt_state(self);

//kprintf("%02x",interruptState);

switch ( interruptState ) {
    case kCudaReceiveByte:
        cuda_receive_data(self);
        break;

    case kCudaReceiveLastByte:
        cuda_receive_last_byte(self);
        break;

    case kCudaTransmitByte:
        cuda_transmit_data(self);
        break;

    case kCudaUnexpectedAttention:
        cuda_unexpected_attention(self);
        break;

    case kCudaExpectedAttention:
        cuda_expected_attention(self);
        break;

    case kCudaIdleState:
        cuda_idle(self);
        break;

    case kCudaCollision:
        cuda_collision(self);
        break;

    // Unknown interrupt, clear it and leave.
    default:
        cuda_error(self);
        break;
}
}

//
//  TransmitCudaData
//  Executes at hardware interrupt level.
//

// **********************************************************************************
// cuda_transmit_data
//
// **********************************************************************************
static void cuda_transmit_data ( AppleCuda * self )
{
    // Clear the pending interrupt by reading the shift register.

if ( self->cuda_is_header_transfer ) {
        // There are more header bytes, write one out.
        cuda_write_data(self, self->cuda_request->a_cmd.a_header[self->cuda_transfer_count++]);

        // Toggle the handshake line.
        if ( self->cuda_transfer_count >= self->cuda_request->a_cmd.a_hcount ) {
            self->cuda_is_header_transfer = FALSE;
            self->cuda_transfer_count = 0;
        }

        cuda_toggle_byte_ack( self);
}
else {
	if ( self->cuda_transfer_count < self->cuda_request->a_cmd.a_bcount ) {
    		// There are more command bytes, write one out and update the pointer
        	cuda_write_data( self,
			*(self->cuda_request->a_cmd.a_buffer + self->cuda_transfer_count++));
		// Toggle the handshake line.
        	cuda_toggle_byte_ack(self);
    	}
	else {
        	(void)cuda_read_data(self);
        	// There is no more command bytes, terminate the send transaction.
      		// Cuda should send a expected attention interrupt soon.

       		cuda_neg_tip_and_byteack(self);

        	// The next interrupt should be a expected attention interrupt.

        	self->cuda_interrupt_state = CUDA_STATE_ATTN_EXPECTED;
	}
}
}

//
//  cuda_expected_attention
//  Executes at hardware interrupt level.
//


// **********************************************************************************
// cuda_expected_attention
//
// **********************************************************************************
static void cuda_expected_attention ( AppleCuda * self )
{
    // Clear the pending interrupt by reading the shift register.

(void)cuda_read_data(self);

    // Allow the VIA to settle directions.. else the possibility of
    // data corruption.
cuda_do_state_transition_delay(self);

if ( self->cuda_transaction_state ==  CUDA_TS_SYNC_RESPONSE ) {
        self->cuda_current_response = (cuda_packet_t*)&self->cuda_request->a_reply;
}
else {
        self->cuda_current_response = &self->cuda_unsolicited[ self->inIndex ];
        self->cuda_current_response->a_hcount = 0;
        self->cuda_current_response->a_bcount = MAX_AP_RESPONSE;
}

self->cuda_is_header_transfer = true;
self->cuda_is_packet_type = true;
self->cuda_transfer_count = 0;

    // Set the shift register direction to input.
cuda_set_data_direction_to_input(self);

    // Start the response packet transaction.
cuda_assert_transfer_in_progress(self);

    // The next interrupt should be a receive data interrupt.
self->cuda_interrupt_state = CUDA_STATE_RECEIVE_EXPECTED;
}

//
//  cuda_unexpected_attention
//  Executes at hardware interrupt level.
//


// **********************************************************************************
// cuda_expected_attention
//
// **********************************************************************************
static void cuda_unexpected_attention ( AppleCuda * self )
{
    // Clear the pending interrupt by reading the shift register.
(void)cuda_read_data(self);

    // Get ready for a unsolicited response.
self->cuda_current_response = &self->cuda_unsolicited[ self->inIndex ];
self->cuda_current_response->a_hcount = 0;
self->cuda_current_response->a_bcount = MAX_AP_RESPONSE;

self->cuda_is_header_transfer = TRUE;
self->cuda_is_packet_type = TRUE;
self->cuda_transfer_count = 0;

    // Start the response packet transaction, Transaction In Progress
cuda_assert_transfer_in_progress(self);

    // The next interrupt should be a receive data interrupt and the next
    // response should be an async response.

self->cuda_interrupt_state = CUDA_STATE_RECEIVE_EXPECTED;

self->cuda_transaction_state = CUDA_TS_ASYNC_RESPONSE;
}

//
//  cuda_receive_data
//  Executes at hardware interrupt level.
//


// **********************************************************************************
// cuda_receive_data
//
// **********************************************************************************
static void cuda_receive_data ( AppleCuda * self )
{
if ( self->cuda_is_packet_type ) {
        unsigned char packetType;

        packetType = cuda_read_data( self);
        self->cuda_current_response->a_header[self->cuda_transfer_count++] = packetType;

        if ( packetType == ADB_PACKET_ERROR) {
            self->cuda_current_response->a_hcount = 4;
        }
	else {
            self->cuda_current_response->a_hcount = 3;
        }

        self->cuda_is_packet_type = false;

        cuda_toggle_byte_ack(self);

}
else {


	if ( self->cuda_is_header_transfer ) {

        	self->cuda_current_response->a_header[self->cuda_transfer_count++] =
                	cuda_read_data(self);

        	if (self->cuda_transfer_count >= self->cuda_current_response->a_hcount) {
            		self->cuda_is_header_transfer = FALSE;
            		self->cuda_transfer_count = 0;
        	}

        	cuda_toggle_byte_ack(self);
    	}
	else {
		if ( self->cuda_transfer_count < self->cuda_current_response->a_bcount ) {
        		// Still room for more bytes. Get the byte and tell Cuda to continue.
        		// Toggle the handshake line, ByteAck, to acknowledge receive.

        		*(self->cuda_current_response->a_buffer + self->cuda_transfer_count++) =
                		cuda_read_data(self);
        		cuda_toggle_byte_ack(self);

    		}
		else {
        		// Cuda is still sending data but the buffer is full.
        		// Normally should not get here.  The only exceptions are open ended
        		// request such as  PRAM read...  In any event time to exit.

        		self->cuda_current_response->a_bcount = self->cuda_transfer_count;

        		cuda_read_data(self);

        		cuda_process_response(self);
        		cuda_neg_tip_and_byteack(self);
    		}
	}
}
}


//
//  cuda_receive_last_byte
//  Executes at hardware interrupt level.
//


// **********************************************************************************
// cuda_receive_last_byte
//
// **********************************************************************************
static void cuda_receive_last_byte ( AppleCuda * self )
{

if ( self->cuda_is_header_transfer ) {
        self->cuda_current_response->a_header[self->cuda_transfer_count++]  =
            cuda_read_data(self);

        self->cuda_transfer_count = 0;
    }
else {
	if ( self->cuda_transfer_count < self->cuda_current_response->a_bcount ) {
        	*(self->cuda_current_response->a_buffer + self->cuda_transfer_count++) =
            	cuda_read_data(self);
    	}
	else {
        	/* Overrun -- ignore data */
        	(void) cuda_read_data(self);
    	}
}
self->cuda_current_response->a_bcount = self->cuda_transfer_count;
    // acknowledge before response so polled mode can work
    //	from inside the handler
cuda_neg_tip_and_byteack(self);
cuda_process_response(self);
}


//
//  cuda_collision
//  Executes at hardware interrupt level.
//


// **********************************************************************************
// cuda_collision
//
// **********************************************************************************
static void cuda_collision ( AppleCuda * self )
{
// Clear the pending interrupt by reading the shift register.
(void)cuda_read_data(self);

// Negate TIP to abort the send.  Cuda should send a second attention
// interrupt to acknowledge the abort cycle.
cuda_neg_transfer_in_progress(self);

// The next interrupt should be an expected attention and the next
// response packet should be an async response.

self->cuda_interrupt_state = CUDA_STATE_ATTN_EXPECTED;
self->cuda_transaction_state = CUDA_TS_ASYNC_RESPONSE;

/* queue the request */
self->cuda_is_header_transfer = false;
self->cuda_transfer_count = 0;
}


//
//  
//  Executes at hardware interrupt level.
//


// **********************************************************************************
// cuda_idle
//
// **********************************************************************************
static void cuda_idle ( AppleCuda * self )
{

// Clear the pending interrupt by reading the shift register.
(void)cuda_read_data(self);

cuda_lock(self);
    // Set to the idle state.
self->cuda_interrupt_state = CUDA_STATE_IDLE;
    // See if there are any pending requests.
if( self->cuda_request ) {
        cuda_send_request(self);
}
cuda_unlock(self);
}


// **********************************************************************************
// cuda_error
//
// **********************************************************************************
static void cuda_error ( AppleCuda * self )
{
//printf("{Error %d}", self->cuda_transaction_state);

// Was looking at cuda_transaction_state - doesn't seem right

switch ( self->cuda_interrupt_state ) {
    case CUDA_STATE_IDLE:
        cuda_neg_tip_and_byteack(self);
        break;

    case CUDA_STATE_TRANSMIT_EXPECTED:
        if ( self->cuda_is_header_transfer && self->cuda_transfer_count <= 1 ) {
            cuda_do_state_transition_delay(self);
            cuda_neg_transfer_in_progress(self);
            cuda_set_data_direction_to_input(self);
            panic ("CUDA - TODO FORCE COMMAND BACK UP!\n");
        }
	else {
            self->cuda_interrupt_state = CUDA_STATE_ATTN_EXPECTED;
            cuda_neg_tip_and_byteack(self);
        }
        break;

    case CUDA_STATE_ATTN_EXPECTED:
        cuda_assert_transfer_in_progress(self);

        cuda_do_state_transition_delay(self);
        cuda_set_data_direction_to_input(self);
        cuda_neg_transfer_in_progress(self);
        panic("CUDA - TODO CHECK FOR TRANSACTION TYPE AND ERROR");
        break;

    case CUDA_STATE_RECEIVE_EXPECTED:
        cuda_neg_tip_and_byteack(self);
        panic("Cuda - todo check for transaction type and error");
        break;

    default:
        cuda_set_data_direction_to_input(self);
        cuda_neg_tip_and_byteack(self);
        break;
}
}

static void cuda_do_state_transition_delay( AppleCuda * self )
{
	AbsoluteTime	deadline;

	clock_absolutetime_interval_to_deadline(
							self->cuda_state_transition_delay, &deadline);
	clock_delay_until(deadline);
}
