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
 *  1 Dec 1998 suurballe  Created.
 */

#include "IOCudaADBController.h"
#include "AppleCuda.h"

#define super IOADBController
OSDefineMetaClassAndStructors(IOCudaADBController, IOADBController)

// **********************************************************************************
// init
//
// **********************************************************************************
bool IOCudaADBController::init ( OSDictionary * properties, AppleCuda * driver )
{

CudaDriver = driver;
pollList = 0;
autopollOn = false;

return super::init(properties);
}


// **********************************************************************************
// start
//
// **********************************************************************************
bool IOCudaADBController::start ( IOService *nub )
{

	CudaDriver->registerForADBInterrupts ( autopollHandler, this );
	if( !super::start(nub))
    		return false;
	return true;
}


// **********************************************************************************
// setAutoPollPeriod
//
// **********************************************************************************
IOReturn IOCudaADBController::setAutoPollPeriod ( int microsecs )
{
cuda_request_t cmd;

adb_init_request(&cmd);
ADB_BUILD_CMD3(&cmd, ADB_PACKET_PSEUDO, ADB_PSEUDOCMD_SET_AUTO_RATE,
		((microsecs + 999) / 1000));

return CudaDriver->doSyncRequest(&cmd);
}


// **********************************************************************************
// getAutoPollPeriod
//
// **********************************************************************************
IOReturn IOCudaADBController::getAutoPollPeriod ( int * microsecs )
{
IOReturn	err;
cuda_request_t  cmd;
UInt8		data;

adb_init_request(&cmd);
ADB_BUILD_CMD2(&cmd, ADB_PACKET_PSEUDO, ADB_PSEUDOCMD_GET_AUTO_RATE);
cmd.a_reply.a_buffer = &data;
cmd.a_reply.a_bcount = sizeof(UInt8);

err = CudaDriver->doSyncRequest(&cmd);

if ( err == kIOReturnSuccess ) {
	*microsecs = data * 1000;
}
return err;
}


// **********************************************************************************
// getAutoPollPeriod
//
// **********************************************************************************
IOReturn IOCudaADBController::setAutoPollList ( UInt16 activeAddressMask )
{
cuda_request_t cmd;

adb_init_request(&cmd);
ADB_BUILD_CMD2(&cmd, ADB_PACKET_PSEUDO, ADB_PSEUDOCMD_SET_DEVICE_LIST)

cmd.a_cmd.a_buffer = (UInt8 *) &activeAddressMask;
cmd.a_cmd.a_bcount = sizeof(UInt16);

return CudaDriver->doSyncRequest(&cmd);
}


// **********************************************************************************
// getAutoPollList
//
// **********************************************************************************
IOReturn IOCudaADBController::getAutoPollList ( UInt16 * activeAddressMask )
{
cuda_request_t cmd;

adb_init_request(&cmd);
ADB_BUILD_CMD2(&cmd, ADB_PACKET_PSEUDO, ADB_PSEUDOCMD_GET_DEVICE_LIST);
cmd.a_reply.a_buffer = (UInt8 *) activeAddressMask;
cmd.a_reply.a_bcount = sizeof(UInt16);

return CudaDriver->doSyncRequest(&cmd);
}


// **********************************************************************************
// setAutoPollEnable
//
// **********************************************************************************
IOReturn IOCudaADBController::setAutoPollEnable ( bool enable )
{
cuda_request_t cmd;

adb_init_request(&cmd);
ADB_BUILD_CMD3(&cmd, ADB_PACKET_PSEUDO, ADB_PSEUDOCMD_START_STOP_AUTO_POLL, (enable ? 1 : 0));

return CudaDriver->doSyncRequest(&cmd);
}


// **********************************************************************************
// resetBus
//
// **********************************************************************************
IOReturn IOCudaADBController::resetBus ( void )
{
cuda_request_t cmd;

adb_init_request(&cmd);
ADB_BUILD_CMD2(&cmd, ADB_PACKET_ADB, ADB_ADBCMD_RESET_BUS );

return CudaDriver->doSyncRequest(&cmd);
}


// **********************************************************************************
// cancelAllIO
//
// **********************************************************************************
IOReturn IOCudaADBController::cancelAllIO ( void )
{
    return kIOReturnSuccess;
}


// **********************************************************************************
// flushDevice
//
// **********************************************************************************
IOReturn IOCudaADBController::flushDevice ( IOADBAddress address )
{
cuda_request_t cmd;

adb_init_request(&cmd);
ADB_BUILD_CMD2(&cmd, ADB_PACKET_ADB, (ADB_ADBCMD_FLUSH_ADB | (address << 4)));

return CudaDriver->doSyncRequest(&cmd);
}



// **********************************************************************************
// readFromDevice
//
// **********************************************************************************
IOReturn IOCudaADBController::readFromDevice (IOADBAddress address, IOADBRegister adbRegister,
		UInt8 * data, IOByteCount * length )
{
IOReturn	err;
cuda_request_t	cmd;

adb_init_request(&cmd);
ADB_BUILD_CMD2(&cmd, ADB_PACKET_ADB,
		(ADB_ADBCMD_READ_ADB | (address << 4) | (adbRegister & 3)));

cmd.a_reply.a_buffer = data;
cmd.a_reply.a_bcount = *length;

err = CudaDriver->doSyncRequest(&cmd);

//IOLog("Read %d, Addr %x Reg %x = %04x\n", err, address, adbRegister, *((UInt16 *)data));

if( err == ADB_RET_OK ) {
	*length = cmd.a_reply.a_bcount;
}
else {
	*length = 0;
}

return err;
}


// **********************************************************************************
// writeToDevice
//
// **********************************************************************************
IOReturn IOCudaADBController::writeToDevice ( IOADBAddress address, IOADBRegister adbRegister,
		UInt8 * data, IOByteCount * length )
{
IOReturn	err;
cuda_request_t	cmd;

adb_init_request(&cmd);

ADB_BUILD_CMD2(&cmd, ADB_PACKET_ADB,
		(ADB_ADBCMD_WRITE_ADB | (address << 4) | (adbRegister & 3)));
cmd.a_cmd.a_buffer = data;
cmd.a_cmd.a_bcount = *length;

err = CudaDriver->doSyncRequest(&cmd);

//IOLog("Write %d, Addr %x Reg %x = %04x\n", err, address, adbRegister, *((UInt16 *)data));

if( err == ADB_RET_OK ) {
	*length = cmd.a_reply.a_bcount;
}
else {
	*length = 0;
}
return err;
}

