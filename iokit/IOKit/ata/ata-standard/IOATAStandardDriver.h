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
 *
 *    	IOATATStandardDriver.h
 *
 */
#ifndef _IOATASTANDARDDRIVER_H
#define _IOATASTANDARDDRIVER_H

class IOATAStandardDriver : public IOATAStandardController
{
    OSDeclareAbstractStructors( IOATAStandardDriver )

/*
 *	Methods that subclasses IOATAStandardDriver must implement.
 */
protected:
    virtual void		writeATAReg( UInt32 regIndex, UInt32 regValue ) 	= 0;
    virtual UInt32		readATAReg(  UInt32 regIndex ) 				= 0;

    virtual bool 		selectTiming( ATAUnit deviceNum, ATATimingProtocol timingProtocol ) = 0;

    virtual bool		programDma( IOATAStandardCommand *cmd );
    virtual bool		startDma( IOATAStandardCommand *cmd );
    virtual bool		stopDma( IOATAStandardCommand *cmd, UInt32 *transferCount );
    virtual bool		resetDma();
    virtual bool		checkDmaActive();

/*
 *	Methods that subclasses of IOATAStandardDriver can optionally implement. 
 */
    virtual void		newDeviceSelected( IOATAStandardDevice *newDevice );
    virtual bool 		getProtocolsSupported( ATAProtocol *forProtocol );

/*
 *	Methods provided to subclasses of IOATAStandardDriver.
 */
    virtual void		interruptOccurred();
   
    virtual void 		resetCommand( IOATAStandardCommand *cmd );
    virtual void 		executeCommand( IOATAStandardCommand *cmd );
    virtual void 		abortCommand( IOATAStandardCommand *cmd );
    virtual void 		cancelCommand(  IOATAStandardCommand *cmd );

/*------------------Methods private to the IOATAStandardDriver class----------------*/

private:
    void			processATAPioInt();
    void			processATADmaInt();
    void			processATAPIPioInt();
    void			processATAPIDmaInt();
    void 			processATADmaQueuedInt();

    ATAReturnCode		readATAPIDevice( UInt32 n );
    ATAReturnCode		writeATAPIDevice( UInt32 n );
    ATAReturnCode		sendATAPIPacket( IOATAStandardCommand *cmd );

    IOReturn			getIOReturnCode( ATAReturnCode code );		

    void			doProtocolSetRegs( IOATAStandardCommand *cmd );
    void 			doATAReset( IOATAStandardCommand *cmd );
    void                        checkATAResetComplete();
    void			doATAProtocolPio( IOATAStandardCommand *cmd );
    void			doATAProtocolDma( IOATAStandardCommand *cmd );
    void			doATAProtocolDmaQueued( IOATAStandardCommand *cmd );
    void			doATAPIProtocolPio( IOATAStandardCommand *cmd );
    void			doATAPIProtocolDma( IOATAStandardCommand *cmd );
    void			doProtocolNotSupported( IOATAStandardCommand *cmd );

    bool			selectDrive( UInt32 driveHeadReg );  

    void			completeCmd( IOATAStandardCommand *cmd, ATAReturnCode returnCode, UInt32 bytesTransferred = 0 );
    void			completeCmd( IOATAStandardCommand *cmd );

    void	 	        updateCmdStatus( IOATAStandardCommand *cmd, ATAReturnCode returnCode, UInt32 bytesTransferred );
	
    bool 			waitForStatus( UInt32 statusBitsOn, UInt32 statusBitsOff, UInt32 timeoutmS );
    bool 			waitForAltStatus( UInt32 statusBitsOn, UInt32 statusBitsOff, UInt32 timeoutmS );
    ATAReturnCode		waitForDRQ( UInt32 timeoutmS );

    bool			start(IOService *provider);
    IOReturn			setPowerState(unsigned long powerStateOrdinal, IOService* whatDevice);

protected:
    IOATAStandardDevice		*currentDevice;
    ATAUnit			currentUnit;
    ATAProtocol			currentProtocol;

private:
    IOMemoryDescriptor		*xferDesc;
    bool			xferIsWrite;
    UInt32			xferCount;
    UInt32			xferRemaining;
    bool			dmaActive;

    IOTimerEventSource          *resetPollEvent;
    IOATAStandardCommand        *resetCmd;
    AbsoluteTime                resetTimeout;

    bool                        wakingUpFromSleep;
};  


#endif
