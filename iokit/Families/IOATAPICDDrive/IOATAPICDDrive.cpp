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
 * Copyright (c) 1999 Apple Computer, Inc.  All rights reserved. 
 *
 * IOATAPICDDrive.h - Generic ATAPI CD-ROM driver.
 *
 * HISTORY
 * Sep 2, 1999	jliu - Ported from AppleATAPIDrive.
 */

#include <IOKit/assert.h>
#include <IOKit/IOBufferMemoryDescriptor.h>
#include <IOKit/storage/ata/IOATAPICDDrive.h>
#include <IOKit/storage/ata/IOATAPICDDriveNub.h>

#define	super IOATAPIHDDrive
OSDefineMetaClassAndStructors( IOATAPICDDrive, IOATAPIHDDrive )

//---------------------------------------------------------------------------
// Looks for an ATAPI device which is a CD-ROM device.

bool
IOATAPICDDrive::matchATAPIDeviceType(UInt8 type, SInt32 * score)
{
	if (type == kIOATAPIDeviceTypeCDROM)
		return true;

    return false;
}

//---------------------------------------------------------------------------
// Instantiate an ATAPI specific subclass of IOCDBlockStorageDevice.

IOService *
IOATAPICDDrive::instantiateNub()
{
    IOService * nub = new IOATAPICDDriveNub;
    return nub;
}

//---------------------------------------------------------------------------
// Report whether media is write-protected.

IOReturn
IOATAPICDDrive::reportWriteProtection(bool * isWriteProtected)
{
	*isWriteProtected = true;
	return kIOReturnSuccess;
}

//---------------------------------------------------------------------------
// Returns the device type.

const char *
IOATAPICDDrive::getDeviceTypeName()
{
	return kIOBlockStorageDeviceTypeCDROM;
}

//---------------------------------------------------------------------------
// Read the Table of Contents.
//
// The LG DVD-ROM DRN8080B LAB8 drive returns a TOC Data Length field which
// describes the number of bytes *returned* in the transfer, not the number
// bytes available to be transferred like it should.  There is a workaround
// that addresses this problem here, however the workaround should be moved
// into a separate drive-specific subclass in the future.

#define LG_DVD_ROM_DRN8080B_SUPPORT

IOReturn
IOATAPICDDrive::readTOC(IOMemoryDescriptor * buffer)
{
	IOReturn       ret;
	IOATACommand * cmd;
	
	assert(buffer);

#ifdef LG_DVD_ROM_DRN8080B_SUPPORT
	IOMemoryDescriptor * bufferOrig = buffer;
	bool                 isLG_DVD_ROM_DRN8080B =
                           ( getVendorString()                               &&
                             getProductString()                              &&
	                         !strcmp(getVendorString(), "LG")                &&
	                         !strcmp(getProductString(), "DVD-ROM DRN8080B") );

	if (isLG_DVD_ROM_DRN8080B) {
		buffer = IOBufferMemoryDescriptor::withCapacity(
		                         max(4096, (bufferOrig->getLength()+1) & (~1)),
		                         kIODirectionIn);
		if (!buffer)
			return kIOReturnNoMemory;
	}
#endif LG_DVD_ROM_DRN8080B_SUPPORT
	
	cmd = atapiCommandReadTOC(buffer, true, 2, 0);
	if (!cmd)
		return kIOReturnNoMemory;

	// Execute the Read TOC command.
	//
    ret = syncExecute(cmd);  
    
#ifdef LG_DVD_ROM_DRN8080B_SUPPORT
	if (isLG_DVD_ROM_DRN8080B) {
		void * toc;
		UInt16 tocSize;
		ATAResults results;

		cmd->getResults(&results);
		toc = ((IOBufferMemoryDescriptor *)buffer)->getBytesNoCopy();
		tocSize = min(results.bytesTransferred, bufferOrig->getLength());

		if (bufferOrig->writeBytes(0, toc, tocSize) < bufferOrig->getLength())
			ret = (ret == kIOReturnSuccess) ? kIOReturnUnderrun : ret;
		else
			ret = (ret == kIOReturnUnderrun) ? kIOReturnSuccess : ret;

		buffer->release();
	}
#endif LG_DVD_ROM_DRN8080B_SUPPORT

	cmd->release();

	return ret;
}

//---------------------------------------------------------------------------
// Start analog audio play

IOReturn
IOATAPICDDrive::audioPlay(CDMSF timeStart,CDMSF timeStop)
{
 	IOATACommand *       cmd;
	IOReturn             ret;

	// IOLog("IOATAPICDDrive::audioPlay %x %x\n",timeStart,timeStop);
	cmd = atapiCommandPlayAudioMSF(timeStart, timeStop);
	if (!cmd)
		return kIOReturnNoMemory;

	// Execute the audio play command.
	//
    ret = syncExecute(cmd);  

	cmd->release();

	return ret;
}

IOReturn
IOATAPICDDrive::audioPause(bool pause)
{
	IOATACommand *       cmd;
	IOReturn             ret;

        // IOLog("IOATAPICDDrive::audioPause\n");
	cmd = atapiCommandPauseResume(!pause);
	if (!cmd)
		return kIOReturnNoMemory;

	// Execute the audio pause/resume command.
	//
    ret = syncExecute(cmd);  

	cmd->release();

	return ret;
}

IOReturn
IOATAPICDDrive::audioScan(CDMSF timeStart, bool reverse)
{
	IOATACommand *       cmd;
	IOReturn             ret;

	cmd = atapiCommandScan(timeStart, reverse);
	if (!cmd)
		return kIOReturnNoMemory;

	// Execute the audio scan command.
	//
    ret = syncExecute(cmd);  

	cmd->release();

	return ret;
}

IOReturn
IOATAPICDDrive::audioStop()
{
	IOATACommand *       cmd;
	IOReturn             ret;

	cmd = atapiCommandStopPlay();
	if (!cmd)
		return kIOReturnNoMemory;

	// Execute the audio stop play command.
	//
    ret = syncExecute(cmd);  

	cmd->release();

	return ret;
}

IOReturn
IOATAPICDDrive::getAudioVolume(UInt8 * leftVolume, UInt8 * rightVolume)
{
    UInt8 audio_control[24];
    IOReturn status;

    status = readModeSense(audio_control,sizeof(audio_control),(UInt32)0xe);

    if (status == kIOReturnSuccess) {
        assert((audio_control[0]       ) == 0x00);
        assert((audio_control[1]       ) == sizeof(audio_control) - 2);
        assert((audio_control[8] & 0x3f) == 0x0e); 
        assert((audio_control[9]       ) == 0x0e);

        *leftVolume  = audio_control[17];
        *rightVolume = audio_control[19];
    }

    return status;
}

IOReturn
IOATAPICDDrive::setAudioVolume(UInt8 leftVolume, UInt8 rightVolume)
{
    UInt8 audio_control[24];
    IOReturn status;

    // get current values
    status = readModeSense(audio_control,sizeof(audio_control),(UInt32)0xe);

    if (status == kIOReturnSuccess) {
        assert((audio_control[0]       ) == 0x00);
        assert((audio_control[1]       ) == sizeof(audio_control) - 2);
        assert((audio_control[8] & 0x3f) == 0x0e); 
        assert((audio_control[9]       ) == 0x0e);

        // set new values
        audio_control[17] = audio_control[21] = leftVolume;
        audio_control[19] = audio_control[23] = rightVolume;

        status = writeModeSelect(audio_control,sizeof(audio_control));
    }

    return status;
}

IOReturn
IOATAPICDDrive::readModeSense(UInt8 * buffer,
                              UInt32  length,
                              UInt8   pageCode,
                              UInt8   pageControl = 0)
{
    IOReturn             ret;
    IOATACommand *       cmd;
    IOMemoryDescriptor * senseDesc;
	
    assert(buffer);

    // IOLog("IOATAPICDDrive::readModeSense len=%d page=%d\n",length,pageCode);

    senseDesc = IOMemoryDescriptor::withAddress(buffer,
                                     length,
                                     kIODirectionIn);
    if (!senseDesc)
        return kIOReturnNoMemory;

    cmd = atapiCommandModeSense(senseDesc, pageCode, pageControl);
    if (!cmd)
        return kIOReturnNoMemory;

    // Execute the Mode Sense command.
    //
    ret = syncExecute(cmd);  

    // Release the memory descriptor.
    //
    senseDesc->release();

    cmd->release();

    return ret;
}

IOReturn
IOATAPICDDrive::writeModeSelect(UInt8 * buffer, UInt32 length)
{
    IOReturn             ret;
    IOATACommand *       cmd;
    IOMemoryDescriptor * selectDesc;
	
    // IOLog("IOATAPICDDrive::writeModeSelect %d %d\n",length);
    assert(buffer);

    selectDesc = IOMemoryDescriptor::withAddress(buffer,
                                     length,
                                     kIODirectionOut);
    if (!selectDesc)
        return kIOReturnNoMemory;

    cmd = atapiCommandModeSelect(selectDesc);
    if (!cmd)
        return kIOReturnNoMemory;

    // Execute the Mode Select command.
    //
    ret = syncExecute(cmd);  

    // Release the memory descriptor.
    //
    selectDesc->release();

    cmd->release();

    return ret;
}

IOReturn
IOATAPICDDrive::getAudioStatus(CDAudioStatus * status)
{
    UInt8 * channel_data;
    IOReturn ret;

    // init
    channel_data = (UInt8 *)IOMalloc(16);
    if (!channel_data) return kIOReturnNoMemory;

    // get audio status
    ret = readSubChannel(channel_data,16,0x01,0x00);

    if (ret == kIOReturnSuccess) {
        // state our assumptions
        assert(channel_data[2] == 0);
        assert(channel_data[3] == 12);
        assert(channel_data[4] == 1);
    
        // get current status
        status->status                     = channel_data[ 1];
    
        // get current track and track index
        status->position.track.number      = channel_data[ 6];
        status->position.track.index       = channel_data[ 7];
    
        // get current absolute address
        status->position.time.minute       = channel_data[ 9];
        status->position.time.second       = channel_data[10];
        status->position.time.frame        = channel_data[11];
    
        // get current relative address
        status->position.track.time.minute = channel_data[13];
        status->position.track.time.second = channel_data[14];
        status->position.track.time.frame  = channel_data[15];
    }
    
    // cleanup
    IOFree(channel_data,16);
    return ret;
}

IOReturn
IOATAPICDDrive::readMCN(CDMCN mcn)
{
    UInt8 * channel_data;
    IOReturn ret;

    // init
    channel_data = (UInt8 *)IOMalloc(24);
    if (!channel_data) return kIOReturnNoMemory;

    // get audio status
    ret = readSubChannel(channel_data,24,0x02,0x00);
    
    if (ret == kIOReturnSuccess) {
        // state our assumptions
        assert(channel_data[2] == 0);
        assert(channel_data[3] == 20);
        assert(channel_data[4] == 2);

        // check if found
        if ((channel_data[8] & 0x80)) {
            // copy the data
            bcopy(&channel_data[9],mcn,kCDMCNMaxLength);
            mcn[kCDMCNMaxLength] = '\0';
        } else {
            ret = kIOReturnNotFound;
        }
    }

    // cleanup
    IOFree(channel_data,24);
    return ret;
}

IOReturn
IOATAPICDDrive::readISRC(UInt8 track, CDISRC isrc)
{
    UInt8 * channel_data;
    IOReturn ret;

    // init
    channel_data = (UInt8 *)IOMalloc(24);
    if (!channel_data) return kIOReturnNoMemory;

    // get audio status
    ret = readSubChannel(channel_data,24,0x03,track);

    if (ret == kIOReturnSuccess) {
        // state our assumptions
        assert(channel_data[2] == 0);
        assert(channel_data[3] == 20);
        assert(channel_data[4] == 3);

        // check if found
        if ((channel_data[8] & 0x80)) {
            // copy the data
            bcopy(&channel_data[9],isrc,kCDISRCMaxLength);
            isrc[kCDISRCMaxLength] = '\0';
        } else {
            ret = kIOReturnNotFound;
        }
    }

    // cleanup
    IOFree(channel_data,24);
    return ret;
}

IOReturn
IOATAPICDDrive::readSubChannel(UInt8 * buffer,
                          UInt32 length,
                          UInt8 dataFormat,
                          UInt8 trackNumber)
{
    IOReturn             ret;
    IOATACommand *       cmd;
    IOMemoryDescriptor * readDesc;
	
    assert(buffer);

    // IOLog("IOATAPICDDrive::readSubChannel len=%d\n",length);

    readDesc = IOMemoryDescriptor::withAddress(buffer,
                                     length,
                                     kIODirectionIn);
    if (!readDesc)
        return kIOReturnNoMemory;

    cmd = atapiCommandReadSubChannel(readDesc, dataFormat, trackNumber);
    if (!cmd)
        return kIOReturnNoMemory;

    // Execute the Mode Sense command.
    //
    ret = syncExecute(cmd);  

    // Release the memory descriptor.
    //
    readDesc->release();

    cmd->release();

    return ret;
}

IOReturn
IOATAPICDDrive::doAsyncReadCD(IOMemoryDescriptor * buffer,
                              UInt32               block,
                              UInt32               nblks,
                              CDSectorArea         sectorArea,
                              CDSectorType         sectorType,
                              IOStorageCompletion  completion)
{
    IOReturn       ret;
    IOATACommand * cmd;

    cmd = atapiCommandReadCD(buffer,block,nblks,sectorArea,sectorType);

    if (!cmd)
        return kIOReturnNoMemory;

    ret = asyncExecute(cmd, completion);

    cmd->release();

    return ret;
}
