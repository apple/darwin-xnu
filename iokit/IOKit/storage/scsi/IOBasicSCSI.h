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
/* =============================================================================
 * Copyright (c) 1999 Apple Computer, Inc.  All rights reserved. 
 *
 * IOBasicSCSI.h
 *
 * This class implements generic SCSI functionality.
 */

#ifndef	_IOBASICSCSI_H
#define	_IOBASICSCSI_H

#include <IOKit/IOTypes.h>
#include <IOKit/IOService.h>
#include <IOKit/IOSyncer.h>
#include <IOKit/scsi/IOSCSIDeviceInterface.h>
#include <IOKit/storage/IOStorage.h>

const int kMinInqSize		= 5;	/* minimal, supported by all devs */
const int kReadCapSize		= 8;
const int kModeSenseSize	= 64;
const int kMaxInqSize		= 256;

const int kCheckCondition = 0x02;
const int kUnitAttention = 0x06;

/* SCSI operation codes: */

const UInt8 	SOP_TUR		= 0x00;		/* test unit ready */
const UInt8 	SOP_INQUIRY	= 0x12;		/* inquiry */
const UInt8	SOP_MODESELECT	= 0x15;		/* mode select */
const UInt8	SOP_MODESENSE	= 0x1a;		/* mode sense */
const UInt8	SOP_READCAP	= 0x25;		/* read capacity */
const UInt8	SOP_READ10	= 0x28;		/* read  (10-byte) */
const UInt8	SOP_WRITE10	= 0x2a;		/* write (10-byte) */

struct IOTURcdb {
    UInt8	opcode;
    UInt8	lunbits;
    UInt8	reserved1;
    UInt8	reserved2;
    UInt8	reserved3;
    UInt8	ctlbyte;
};

struct IORWcdb {			/* CDB for read and write */
    UInt8	opcode;			/* read=0x28, write=0x2a */
    UInt8	lunbits;		/* lun and control bits */
    UInt8	lba_3;			/* logical block address: msb */
    UInt8	lba_2;
    UInt8	lba_1;
    UInt8	lba_0;			/* logical block address: lsb */
    UInt8	reserved;
    UInt8	count_msb;		/* block count: msb */
    UInt8	count_lsb;		/* block count: lsb */
    UInt8	ctlbyte;
};

struct IOInquirycdb {			/* inquiry */
    UInt8	opcode;			/* 0x12 */
    UInt8	lunbits;		/* lun and control bits */
    UInt8	pagecode;		/* page code/op code */
    UInt8	reserved;
    UInt8	len;			/* allocation length */
    UInt8	ctlbyte;
};

struct IOReadCapcdb {
    UInt8	opcode;
    UInt8	lunbits;
    UInt8	lba_3;
    UInt8	lba_2;
    UInt8	lba_1;
    UInt8	lba_0;
    UInt8	reserved1;
    UInt8	reserved2;
    UInt8	reserved3;
    UInt8	ctlbyte;
};

struct IOModeSensecdb {
    UInt8	opcode;
    UInt8	lunbits;		/* lun and control bits */
    UInt8	pagecode;
    UInt8	reserved;
    UInt8	len;			/* allocation length */
    UInt8	ctlbyte;
};

struct IOModeSelectcdb {
    UInt8	opcode;
    UInt8	lunbits;
    UInt8	reserved1;
    UInt8	reserved2;
    UInt8	paramlen;
    UInt8	ctlbyte;
};

/*!
 * @enum stateValues
 * @discussion
 * These state values are used to determin the state of an IO operation.
 * Some are simply for debugging use.
 * @constant kNone
 * Nothing happening.
 * @constant kAsyncReadWrite
 * Doing an asynchronous IO operation.
 * @constant kSimpleSynchIO
 * Doing a simple synchronous IO operation.
 * @constant kHandlingUnitAttention
 * Currently handling a Unit-Attention condition.
 * @constant kDoneHandlingUnitAttention
 * Done handling Unit Attention; command should be reissued.
 * @constant kAwaitingPower
 * Awaiting power.
 * @constant kMaxValidState
 * The maximum valid state value.
 * @constant kMaxStateValue
 * The maximum state value possible.
 */
enum stateValues {
    kNone				= 0,
    kAsyncReadWrite			= 1,
    kSimpleSynchIO			= 2,
    kHandlingUnitAttention		= 3,
    kHandlingRecoveryAfterBusReset	= 4,
    kAwaitingPower			= 5,

    kMaxValidState			= kAwaitingPower,

    kMaxStateValue			= 255
};
/*!
 * @typedef statevalue
 * @discussion
 * Shorthand for enum StateValues.
 */
typedef enum stateValues stateValue;

const bool kSync = true;		/* type info for requests awaiting power */
const bool kAsync = false;

const UInt32 kMaxRetries = 3;

/*!
 * @class
 * IOBasicSCSI : public IOService
 * @abstract
 * Basic SCSI support functions.
 * @discussion
 * IOBasicSCSI provides a set of basic SCSI functions and support
 * utilities. It is intended to be the base class for a SCSI Transport
 * Driver.
 */

class IOBasicSCSI : public IOService {

    OSDeclareAbstractStructors(IOBasicSCSI)

public:

    /*!
     * @struct completion
     * @field action
     * The C function called upon completion of the operation.
     * @field target
     * The C++ class pointer, passed to tha action function.
     * @field param
     * A value passed to the action function. This value is not touched.
     */
    /*!
     * @struct context
     * @discussion
     * The context structure contains all persistent information needed for a
     * synchronous or asynchronous IO operation.
     * @field completion
     * The completion information for an asynchronous read or write operation.
     * @field state
     * The current state of the operation.
     * @field step
     * The current step value, if we are handling a Unit Attention.
     * @field originalContext
     * A pointer to the context for the command that caused the Unit Attention
     * condition.
     * @field scsireq
     * A pointer to the IOSCSIRequest object.
     * @field memory
     * The data buffer for the operation. A pointer to an IOMemoryDescriptor.
     * @field scsiresult
     * A pointer to the IOSCSIResult object.
     * @field desiredPower
     * The desired power level for the operation to execute.
     * @field isSync
     * True if synchronous; False if asynchronous.
     * @field next
     * A pointer to a context structure, used as a queue forward-link.
     * @field sync
     * A syncer used to block a thread awaiting a power level, or for completion
     * of a synchronous operation.
     */
    struct context {

        /* Completion information for our client, used only for async operations.
         * Typically this information will only be used by subclasses.
         */
            IOStorageCompletion	completion;		/* function to call */

        /* Parameters used during an IO retry: */

        stateValue		state;			/* what state we're in */
        UInt32			step;
        struct context		*originalIOContext;	/* original SCSI IO if doing a retry */
        bool			retryInProgress;
        UInt32			retryCount;

        IOMemoryDescriptor	*memory;

        UInt32			desiredPower;		/* desired power level state */
        bool			isSync;			/* true if sync, false if async */
        struct context		*next;			/* for queue of requests pending power */
        /* Parameters to hand off to the SCSI provider: */
    
        IOSCSICommand		*scsireq;
        SCSISenseData		*senseData;  
        IOMemoryDescriptor	*senseDataDesc;  

        IOSyncer		*sync;		/* to wait for completion */
    };

    /* Overrides from IOService: */

    virtual void	free(void);

    virtual bool	init(OSDictionary * properties);

    /*!
     * @function message
     * @discussion
     * This override allows us to receive notification of Bus Reset events from
     * the SCSI Device.
     */
    virtual IOReturn	message(UInt32 type,IOService * provider,void * argument);
    
    /*!
     * @function probe
     * @abstract
     * Determine if device matches expected type.
     * @discussion
     * This method is responsible for matching the device type. It calls
     * doInquiry to issue a SCSI Inquiry command to the device, then calls
     * deviceTypeMatches to ensure that the device type matches the expected
     * type. (The Vendor, Product, and Revision strings are unconditionally
     * copied from the inquiry data). If deviceTypeMatches returns true, "this" is
     * returned. If the device type does not match, NULL is returned.
     * 
     * The default implementation passes the score parameter to deviceTypeMatches
     * so that method may alter the match score.
     */
    virtual IOService * probe(IOService * provider,SInt32 * score);
    
    virtual bool	start(IOService *provider);
    
    /* --- end of IOService overrides --- */

    /*!
     * @function deviceTypeMatches
     * @abstract
     * Determine if device type matches expected type.
     * @discussion
     * This method must be implemented by a device-specific subclass.
     * @param inqBuf
     * A pointer to the SCSI inquiry data for the device.
     * @param inqLen
     * The size of the data in the inquiry buffer.
     * @param score
     * A pointer to the match score, which will be returned by probe.
     * @result
     * True indicates a match; False indicates a failure.
     */
    virtual bool	deviceTypeMatches(UInt8 inqBuf[],UInt32 inqLen,SInt32 *score)		= 0;

    /*!
     * @function getAdditionalDeviceInfoString
     * @abstract
     * Return additional informational string for the device.
     * @result
     * A pointer to a static character string. The default implementation
     * returns "[SCSI]" .
     */
    virtual char *	getAdditionalDeviceInfoString(void);

    /*!
     * @function getVendorString
     * @abstract
     * Return Vendor Name string
     * @result
     * A pointer to a static character string, copied from the inquiry data.
     */
    virtual char *	getVendorString(void);

    /*!
     * @function getProductString
     * @abstract
     * Return Product Name string for the device.
     * @result
    A pointer to a static character string, copied from the inquiry data.
     */
    virtual char *	getProductString(void);

    /*!
     * @function getRevisionString
     * @abstract
     * Return Product Revision string for the device.
     * @result
     * A pointer to a static character string, copied from the inquiry data.
     */
    virtual char *	getRevisionString(void);

    /*!
     * @function reportBlockSize
     * @abstract
     * Report the block size for the device, in bytes.
     * @discussion
     * This method returns the block size for the media. The default
     * implementation obtains the block size from the SCSI Read Capacity
     * command. Since the result of the Read Capacity is used by this
     * method and reportMaxValidBlock, this method either returns a cached
     * value or calls doReadCapacity to issue the command and cache both
     * values.
     * @param blockSize
     * Pointer to returned block size value.
     */
    virtual IOReturn	reportBlockSize(UInt64 *blockSize);
    
    /*!
     * @function reportEjectability
     * @abstract
     * Report if the media is ejectable under software control.
     * @discussion
     * This method reports whether the media is ejectable under software
     * control. The default implementation always reports that removable
     * media is ejectable.
     * 
     * This method should only be called if the media is known to be removable.
     * @param isEjectable
     * Pointer to returned result. True indicates the media is ejectable, False indicates
     * the media cannot be ejected under software control.
     */
    virtual IOReturn	reportEjectability(bool *isEjectable);
    
    /*!
     * @function reportLockability
     * @abstract
     * Report if the media is lockable under software control.
     * @discussion
     * This method reports whether the media can be locked under software
     * control, to prevent the user from removing the media manually, e.g.
     * by pressing a button on the drive. This method is only called by
     * the generic driver when the media is known to be removable. The
     * default implementation always returns true.
     *  
     * This method should only be called if the media is known to be removable.
     * @param isLockable
     * Pointer to returned result. True indicates the media can be locked in place; False
     * indicates the media cannot be locked by software.
     */
    virtual IOReturn	reportLockability(bool *isLockable);
    
    /*!
     * @function reportMaxReadTransfer
     * @abstract
     * Report the maximum allowed byte transfer for read operations.
     * @discussion
     * Some devices impose a maximum data transfer size. Because this limit
     * may be determined by the size of a block-count field in a command, the limit may
     * depend on the block size of the transfer.
     * The default implementation reports blocksize * 65536, which is the maximum
     * number of bytes that can be transferred
     * in a SCSI command with a standard 16-bit block count field.
     * @param blockSize
     * The block size desired for the transfer.
     * @param max
     * Pointer to returned result.
     */
    virtual IOReturn	reportMaxReadTransfer (UInt64 blocksize,UInt64 *max);

    /*!
     * @function reportMaxValidBlock
     * @abstract
     * Report the highest valid block for the device.
     * @discussion
     * This method reports the maximum allowable block number. The default
     * implementation obtains the block number from the SCSI Read Capacity
     * command. Since the result of the Read Capacity is used by this
     * method and reportBlockSize, this method either returns a cached
     * value or calls doReadCapacity to issue the command and cache both
     * values.
     * @param maxBlock
     * Pointer to returned result
     */
    virtual IOReturn	reportMaxValidBlock(UInt64 *maxBlock);

    /*!
     * @function reportMaxWriteTransfer
     * @abstract
     * Report the maximum allowed byte transfer for write operations.
     * @discussion
     * Some devices impose a maximum data transfer size. Because this limit
     * may be determined by the size of a block-count field in a command, the limit may
     * depend on the block size of the transfer.
     * The default implementation reports blocksize * 65536, which is the maximum
     * number of bytes that can be transferred
     * in a SCSI command with a standard 16-bit block count field.
     * @param blockSize
     * The block size desired for the transfer.
     * @param max
     * Pointer to returned result.
     */
    virtual IOReturn	reportMaxWriteTransfer(UInt64 blocksize,UInt64 *max);
    
    /*!
     * @function reportPollRequirements
     * @abstract
     * Report if it's necessary to poll for media insertion, and if polling is expensive.
     * @discussion
     * This method reports whether the device must be polled to detect media
     * insertion, and whether a poll is expensive to perform.
     * 
     * The term "expensive" typically implies a device that must be spun-up to detect media,
     * as on a PC floppy. Most devices can detect media inexpensively.
     * 
     * The default implementation of this method always reports an
     * inexpensive poll (pollIsExpensive = false), and that all removable
     * media must be polled.
     * @param pollRequired
     * Pointer to returned result. True indicates that polling is required; False indicates
     * that polling is not required to detect media.
     * @param pollIsExpensive
     * Pointer to returned result. True indicates that the polling operation is expensive;
     * False indicates that the polling operation is cheap.
     */
    virtual IOReturn	reportPollRequirements(bool *pollRequired,bool *pollIsExpensive);
    
    /*!
     * @function reportRemovability
     * @abstract
     * Report whether the media is removable or not.
     * @discussion
     * This method reports whether the media is removable, but it does not
     * provide detailed information regarding software eject or lock/unlock capability.
     * 
     * The default implementation of this method examines the cached
     * Inquiry data to determine if media is removable.  If the RMB bit
     * (0x80 of Inquiry data byte 1) is set, the media is removable. If
     * there is no Inquiry data, the media is reported to be nonremovable.
     * 
     * This method also sets the instance variable _removable.
     * @param isRemovable
     * Pointer to returned result. True indicates that the media is removable; False
     * indicates the media is not removable.
     */
    virtual IOReturn	reportRemovability(bool *isRemovable);

    /*!
     * @function reportWriteProtection
     * @abstract
     * Report whether the media is write-protected or not.
     * @discussion
     * The default implementation of this method issues a SCSI Mode Sense
     * command to test the WP bit( 0x80 of byte 2 of the Mode Sense Header
     * data). A request is made for Mode Sense Page 1, though any  valid
     * page will return a header. If the bit is set, the media is considered
     * write-protected.
     * @param isWriteProtected
     * Pointer to returned result. True indicates that the media is write-protected (it
     * cannot be written); False indicates that the media is not write-protected (it
     * is permissible to write).
     */
    virtual IOReturn	reportWriteProtection(bool *isWriteProtected);

protected:

    /*!
     * @function createReadCdb
     * @abstract
     * Create a SCSI CDB for a read operation.
     * @discussion
     * Override this to control the cdb created for a read operation.
     * The default implementation creates a 10-byte read command with
     * disconnect allowed, 8-byte autosense, and a 2-second timeout.
     * @param cdb
     * A pointer to the CDB bytes.
     * @param cdbLength
     * The length of the CDB in bytes.
     * @param block
     * The device block to be read.
     * @param nblks
     *  The number of blocks to be transferred.
     * @param maxAutoSenseLength
     * The maximum size of the autosense data, in bytes. A value of zero
     * will disable autosense.
     * @param timeoutSeconds
     * The command timeout in seconds.
     * @result
     * The IOSCSICommandOptions returned will be used to issue the command.
     */
    virtual UInt32	createReadCdb(
                            UInt8 *cdb,			/* in  */
                            UInt32 *cdbLength,		/* out */
                            UInt32 block,		/* in  */
                            UInt32 nblks,		/* in  */
                            UInt32 *maxAutoSenseLength,	/* out */
                            UInt32 *timeoutSeconds);	/* out */

    /*!
     * @function createWriteCdb
     * @abstract
     * Create a SCSI CDB for a write operation.
     * @discussion
     * Override this to control the cdb created for a write operation.
     * The default implementation creates a 10-byte write command with
     * disconnect allowed, 8-byte autosense, and a 2-second timeout.
     * @param cdb
     * A pointer to the CDB bytes.
     * @param cdbLength
     * The length of the CDB in bytes.
     * @param block
     * The device block to be written.
     * @param nblks
     * The number of blocks to be transferred.
     * @param maxAutoSenseLength
     * The maximum size of the autosense data, in bytes. A value of zero
     * will disable autosense.
     * @param timeoutSeconds
     * The command timeout in seconds.
     * @result
     * The IOSCSICommandOptions returned will be used to issue the command.
     */
    virtual UInt32	createWriteCdb(
                            UInt8 *cdb,			/* in  */
                            UInt32 *cdbLength,		/* out */
                            UInt32 block,		/* in  */
                            UInt32 nblks,		/* in  */
                            UInt32 *maxAutoSenseLength,	/* out */
                            UInt32 *timeoutSeconds);	/* out */


    /*!
     * @function doInquiry
     * @abstract
     * Obtain SCSI Inquiry data from the device.
     * @discussion
     * This method issues a SCSI Inquiry command to the device, to obtain
     * the result in the supplied buffer. The method first issues an
     * inquiry with a 5-byte length, to obtain the full length of the
     * devices inquiry data. The second Inquiry command is issued to get
     * the full inquiry data (limited to maxLen, of course).
     * @param inqBuf
     * A pointer to the buffer.
     * @param maxLen
     * The maximum number of bytes the buffer can contain.
     * @param actualLen
     * A pointer to the returned byte count actually transferred.
     */
    virtual IOReturn	doInquiry(UInt8 *inqBuf,UInt32 maxLen,UInt32 *actualLen);

    /* ---------------- Internally used methods.  ---------------- */

    /*
     * @group
     * Internally Used Methods
     * @discussion
     * These methods are used internally, and will not generally be modified.
     */

    /*!
     * @function allocateContext
     * @abstract
     * Allocate a context structure for use with the current IO operation.
     */
    virtual struct context * allocateContext(void);

    /*!
     * @function allocateInquiryBuffer
     * @abstract
     * Allocate an inquiry buffer.
     * @param buf
     * A pointer for the returned buffer pointer.
     * @param size
     * The requested size of the buffer, in bytes.
     */
    virtual IOReturn	allocateInquiryBuffer(UInt8 **buf,UInt32 size);

    /*!
     * @function allocateTempBuffer
     * @abstract
     * Allocate a buffer for temporary use.
     * @param buf
     * A pointer for the returned buffer pointer.
     * @param size
     * The requested size of the buffer, in bytes.
     */
    virtual IOReturn	allocateTempBuffer(UInt8 **buf,UInt32 size);

    /*!
     * @function allocateReadCapacityBuffer
     * @abstract
     * Allocate a buffer for Read-Capacity data.
     * @param buf
     * A pointer for the returned buffer pointer.
     * @param size
     * The requested size of the buffer, in bytes.
     */
    virtual IOReturn	allocateReadCapacityBuffer(UInt8 **buf,UInt8 size);

    /*!
     * @function automaticRetry
     * @abstract
     * Return TRUE if we should automatically retry the command just completed.
     * @discussion
     * The default implementation of this method reacts to Unit Attention and
     * Bus Reset conditions, possibly starting the recovery processes for those
     * conditions and arranging that the subject command is retried after
     * the recovery procedure finishes.
     * @param cx
     * A pointer to the context for the command just completed.
     */
    virtual bool	automaticRetry(struct context *cx);

    /*!
     * @function beginBusResetRecovery
     * @abstract
     * Begin the Bus Reset recovery process.
     * @discussion
     * This method can be overridden to issue the first command necessary
     * to perform the Bus Reset recovery process for the device.
     *
     * The default implementation does nothing and simply calls finishBusResetRecovery.
     */
    virtual void	beginBusResetRecovery(void);

    /*!
     * @function beginUnitAttentionRecovery
     * @abstract
     * Begin the Unit Attention recovery process.
     * @discussion
     * This method can be overridden to issue the first command necessary
     * to perform the Bus Reset recovery process for the device.
     *
     * The default implementation does nothing and simply calls finishUnitAttentionRecovery.
     */
    virtual void	beginUnitAttentionRecovery(void);
                                  
    /*!
     * @function busResetRecoveryCommandComplete
     * @abstract
     * Handle a command completion during the Bus Reset recovery process.
     * @discussion
     * This method can be overridden to check the result of each command issued
     * during the Bus Reset recovery process for the device. Typically it would
     * bump the "step" value and issue the next command, calling finishBusResetRecovery
     * when the process is complete.
     *
     * The default implementation does nothing.
     */
    virtual void	busResetRecoveryCommandComplete(struct context *cx);

    /*!
     * @function customAutomaticRetry
     * @abstract
     * Return TRUE if we should automatically retry the command just completed.
     * @discussion
     * This method should be overridden to allow checking for, and causing, an
     * automatic retry of a command.
     *
     * The default implementation of this method does nothing except return FALSE.
     * @param cx
     * A pointer to the context for the command just completed.
     */
    virtual bool	customAutomaticRetry(struct context *cx);

    /*!
     * @function deleteContext
     * @abstract
     * Delete a context structure.
     * @discussion
     * This method also issues a "release" for the IO buffer and/or lock, if any.
     * @param cx
     * A pointer to the context structure to be deleted.
     */
    virtual void	deleteContext(struct context *cx);

    /*!
     * @function deleteInquiryBuffer
     * @abstract
     * Delete an inquiry data buffer.
     * @param buf
     * A pointer to the buffer.
     * @param size
     * The requested size of the buffer, in bytes.
     */
    virtual void	deleteInquiryBuffer(UInt8 *buf,UInt32 size);

    /*!
     * @function deleteTempBuffer
     * @abstract
     * Delete a temporary data buffer.
     * @param buf
     * A pointer to the buffer.
     * @param len
     * The requested size of the buffer, in bytes.
     */
    virtual void	deleteTempBuffer(UInt8 *buf,UInt32 len);

    /*!
     * @function deleteReadCapacityBuffer
     * @abstract
     * Delete a Read-Capacity data buffer.
     * @param buf
     * A pointer to the buffer.
     * @param len
     * The requested size of the buffer, in bytes.
     */
    virtual void	deleteReadCapacityBuffer(UInt8 *buf,UInt32 len);

    /*!
     * @function doReadCapacity
     * @abstract
     * @discussion
     * The default implementation of this method issues a standard SCSI
     * Read Capacity command. The block size and maximum valid block are
     * extracted from the returned data in an endian-neutral way.
     * @param blockSize
     * A pointer to the returned block size value.
     * @param maxBlock
     * A pointer to the returned maximum block number.
     */
    virtual IOReturn	doReadCapacity(UInt64 *blockSize,UInt64 *maxBlock);

    /*!
     * @function finishBusResetRecovery
     * @abstract
     * Finish up after the Bus Reset recovery process is complete.
     * @discussion
     * This method would usually not require an override.
     */
    virtual void	finishBusResetRecovery(void);

    /*!
     * @function finishUnitAttentionRecovery
     * @abstract
     * Finish up after the Unit Attention recovery process is complete.
     * @discussion
     * This method would usually not require an override.
     */
    virtual void	finishUnitAttentionRecovery(void);

    /*!
     * @function getBlockSize
     * @abstract
     * Return the device block size.
     * @discussion
     * This method obtains the block size from the Read-Capacity data. If RC data is
     * not yet cached, a call is made to doReadCapacity to obtain the data.
     */
    virtual UInt64	getBlockSize(void);


    /*!
     * @function dequeueCommands
     * @abstract
     * Dequeue commands previously enqueued awaiting the proper device power level.
     * @discussion
     * This method is called when a command is queued (from queueCommand), when a call
     * completes (from RWCompletion), and when the device power level changes. All commands
     * for which the device power level is proper are immediately dequeued.
     * 
     * Queued synchronous commands are simply "awakened" by unlocking a lock. The originating
     * thread then continues and issues the command. Asynchronous commands are immediately
     * dispatched via a call to standardAsyncReadWriteExecute.
     */
    virtual void	dequeueCommands(void);

    /*!
     * @function queueCommand
     * @abstract
     * Queue commands awaiting the proper device power level.
     * @discussion
     * This method is called prior to issuing any IO command, so that each command can
     * be enqueued awaiting its desired device power level. After queuing the command, a
     * call is made to dequeueCommands to attempt to dequeue any available command that can
     * be executed (including the one just queued). Putting commands into the queue ensures
     * that the proper sequence is maintained.
     * @param cx
     * The context for the command being queued.
     * @param isSync
     * True if the command is synchronous; False if the command is asynchronous.
     * @param desiredPower
     * The device power level needed before the command can execute.
     */
    virtual void	queueCommand(struct context *cx,bool isSync,UInt32 desiredPower);

    /*!
     * @function RWCompletion
     * @abstract
     * Asynchronous read/write completion routine.
     * @discussion
     * A subclass must implement the read-write completion, called upon completion
     * of an IO started by doAsyncReadWrite.
     * @param cx
     * A pointer to the context structure for the completing command.
     */
    virtual void	RWCompletion(struct context *cx)				= 0;

    /*!
     * @function setupBusResetRecovery
     * @abstract
     * Set up to begin Bus Reset recovery.
     * @discussion
     * This method would usually not require an override.
     */
    virtual void	setupBusResetRecovery(void);
                                  
    /*!
     * @function setupUnitAttentionRecovery
     * @abstract
     * Set up to begin Unit Attention recovery.
     * @discussion
     * This method would usually not require an override.
     */
    virtual void	setupUnitAttentionRecovery(struct context *cx);
                                  
    /*!
     * @function simpleAsynchIO
     * @abstract
     * Issue a simple asynchronous SCSI command.
     * @discussion
     * This method issues a single SCSI command.
     * The SCSI command must already be set up in the context structure.
     * @param cx
     * A pointer to the context structure for the command.
     */
    virtual IOReturn	simpleAsynchIO(struct context *cx);

    /*!
     * @function simpleSynchIO
     * @abstract
     * Issue a simple synchronous SCSI command.
     * @discussion
     * This method issues a single SCSI command and waits for the command
     * to complete. The SCSI command must already be set up in the context
     * structure.
     * @param cx
     * A pointer to the context structure for the command.
     */
    virtual IOReturn	simpleSynchIO(struct context *cx);

    /*!
     * @function standardAsyncReadWrite
     * @abstract
     * Start an asynchronous read or write operation.
     * @discussion
     * This method starts an asynchronous read or write operation. No
     * incoming parameters are validated. The default implementation
     * calls createReadCdb or createWriteCdb,
     * then issues a SCSI command to IOSCSIDevice. If the command is
     * accepted, then the completion will be called at some future time.
     * @result
     * The only possible returns from this method are:
     * 
     * kIOReturnSuccess, meaning that the IO was accepted by the transport
     * drivers provider (e.g.  IOSCSIDevice), and that the completion
     * function will be called when the IO completes, i.e.  target->action(param).
     *  
     * kIOReturnNoMemory, meaning that memory allocation failed.
     * 
     * Other kIOReturn codes from the provider which occurred
     * because the IO was not accepted in that provider's queue. This
     * might indicate a full queue or bad parameter.
     * @param buffer
     * An IOMemoryDescriptor describing the data-transfer buffer. The data direction
     * is contained in the IOMemoryDescriptor. Responsiblity for releasing the descriptor
     * rests with the caller.
     * @param block
     * The starting block number of the data transfer.
     * @param nblks
     * The integral number of blocks to be transferred.
     * @param action
     * The C function called upon completion of the data transfer.
     * @param target
     * The C++ class "this" pointer, passed as an argument to "action."
     * @param param
     * This value is passed as an argument to "action." It is not validated or modified.
     */
    virtual IOReturn	standardAsyncReadWrite(IOMemoryDescriptor *buffer,
                                            UInt32 block,UInt32 nblks,
                                            IOStorageCompletion completion);

    /*!
     * @function standardAsyncReadWriteExecute
     * @abstract
     * Issue an asynchronous read/write operation after dequeuing.
     * @param cx
     * A pointer to the context structure for the command.
     */
    virtual IOReturn	standardAsyncReadWriteExecute(struct context *cx);

    /*!
     * @function standardSyncReadWrite
     * Perform a synchronous read or write operation.
     * @param buffer
     * An IOMemoryDescriptor describing the data-transfer buffer. The data direction
     * is contained in the IOMemoryDescriptor. Responsiblity for releasing the descriptor
     * rests with the caller.
     * @param block
     * The starting block number of the data transfer.
     * @param nblks
     * The integral number of blocks to be transferred.
     */
    virtual IOReturn	standardSyncReadWrite(IOMemoryDescriptor *buffer,UInt32 block,UInt32 nblks);

    /*!
     * @function stringFromState
     * @abstract
     * Return a string description of a state value.
     * @discussion
     * Used for debugging.
     * @param state
     * The state to be converted to a string description.
     */
    virtual char *	stringFromState(stateValue state);

    /*!
     * @function unitAttentionRecoveryCommandComplete
     * @abstract
     * Handle a command completion during the Unit Attention recovery process.
     * @discussion
     * This method can be overridden to check the result of each command issued
     * during the Unit Attention recovery process for the device. Typically it would
     * bump the "step" value and issue the next command, calling finishUnitAttentionRecovery
     * when the process is complete.
     *
     * The default implementation does nothing.
     */
    virtual void	unitAttentionRecoveryCommandComplete(struct context *cx);

    /*!
     * @function unitAttentionDetected
     * @abstract
     * Determine if a Unit Attention condition occurred.
     * @param cx
     * A pointer to the context structure for the command just executed.
     */
    virtual bool	unitAttentionDetected(struct context *cx);

public:

    /*!
     * @function genericCompletion
     * @abstract
     * Generic IO completion function.
     * @discussion
     * This method handles completion of a SCSI command. It implements a
     * simple state machine to handle a Unit Attention condition on a
     * command.
     * 
     * This method must be public so we can reach it from
     * the C-language callback "glue" routine. It should not be called
     * from outside this class.
     *
     * 
     *
     * If a Unit Attention condition occurs, we set the state to
     * kHandlingUnitAttention and call handleUnitAttention to do whatever
     * is necessary to clear the condition. Eventually, handleUnitAttention
     * resets the state to kDoneHandlingUnitAttention, which will allow
     * the state machine to reissue the original command.
     * 
     * If we are already processing a Unit Attention, then genericCompletion
     * increments a step counter and calls handleUnitAttention.  The step
     * counter allows handleUnitAttention to issue multiple SCSI commands
     * to clear the condition. The handleUnitAttention method is called
     * repeatedly, until the state is set to kDoneHandlingUnitAttention.
     * 
     * If this operation is a normal asynchronous read or write (usually
     * started by standardAsyncReadWrite, though this is not required),
     * then a call is made to RWCompletion, followed by deletion of the
     * context structure for the command. RWCompletion is  implemented by
     * the subclass of IOBasicSCSI, for example in IOSCSIHDDrive.
     * @param cx
     * A pointer to the context structure for the command.
     */
    virtual void	genericCompletion(struct context *cx);

    /*
     * @endgroup
     */

protected:

    /*
     * @group
     * Power Management Methods
     * @discussion
     * A subclass must implement these to report the power level required to do various commands.
     */

    /*!
     * @function getExecuteCDBPowerState
     * @abstract
     * Return the required device power level to execute a client CDB.
     */
    virtual UInt32	getExecuteCDBPowerState(void)					= 0;

    /*!
     * @function getInquiryPowerState
     * @abstract
     * Return the required device power level to issue an Inquiry command.
     */
    virtual UInt32	getInquiryPowerState(void)					= 0;

    /*!
     * @function getReadCapacityPowerState
     * @abstract
     * Return the required device power level to issue a Read Capacity command.
     */
    virtual UInt32	getReadCapacityPowerState(void)					= 0;

    /*!
     * @function getReadWritePowerState
     * @abstract
     * Return the required device power level to issue a data read or write.
     */
    virtual UInt32	getReadWritePowerState(void)					= 0;

    /*!
     * @function getReportWriteProtectionPowerState
     * @abstract
     * Return the required device power level to determine media write protection.
     */
    virtual UInt32	getReportWriteProtectionPowerState(void)			= 0;

    /*!
     * @function powerTickle
     * @abstract
     * Check for the device power state currently being in the desired state.
     * @discussion
     * A subclass must implement powerTickle, which is called when we desire power to
     * execute a command. PowerTickle may handle generic or a subclass-expanded set of
     * power states. The implementation will usually relay the call to the Power Management
     * subsystem function activityTickle. For a device without power management capability,
     * the implementation should always return True.
     * @param desiredState
     * The desired device power level.
     * @result
     * True if power is in the desired state (or better); False if the caller must wait
     * until power is available.
     */
    virtual bool	powerTickle(UInt32 desiredState)				= 0;

    /*
     * @endgroup
     */
    
    /*!
     * @var _provider
     * A pointer to our provider.
     */
    IOSCSIDevice *	_provider;

    /*!
     * @var _busResetContext
     * A pointer to a context struct to be used by recoverAfterBusReset.
     */
    struct context *	_busResetContext;

    /*!
     * @var _unitAttentionContext
     * A pointer to a context struct to be used by handleUnitAttention.
     */
    struct context *	_unitAttentionContext;
                                  
    /*!
     * @var _busResetRecoveryInProgress
     * True if recovery from Bus Reset is in progress.
     */
    bool		_busResetRecoveryInProgress;

    /*!
     * @var _unitAttentionRecoveryInProgress
     * True if recovery from Unit Attention is in progress.
     */
    bool		_unitAttentionRecoveryInProgress;

    /* Device information : */
    
    /*!
     * @var _inqBuf
     * A pointer to the allocate Inquiry Data buffer.
     */
    UInt8 *		_inqBuf;		/* the Inquiry data buffer */

    /*!
     * @var _inqBufSize
     * The size of the inquiry data buffer, in bytes.
     */
    UInt32		_inqBufSize;		/* size of the buffer */

    /*!
     * @var _inqLen
     * The number of valid bytes of inquiry data.
     */
    UInt32		_inqLen;		/* valid bytes in buffer */
    
    /*!
     * @var _vendor
     * The Vendor Name string from the inquiry data, null-terminated.
     */
    char		_vendor[9];		/* info from Inquiry data */

    /*!
     * @var _product
     * The Product Name string from the inquiry data, null-terminated.
     */
    char		_product[17];

    /*!
     * @var _rev
     * The Product Revision string from the inquiry data, null-terminated.
     */
    char		_rev[5];

    /* Since we get both of these items from the same command, we
     * just cache both values if we get either call, so we only
     * have to issue the command once.
     */

    /*!
     * @var _readCapDone
     * True if we have issued a Read-Capacity command to obtain the
     * values for _maxBlock and _blockSize.
     */
    bool		_readCapDone;

    /*!
     * @var _removable
     * True if the media is removable; False if the media is fixed.
     */
    bool		_removable;

    /*!
     * @var _maxBlock
     * The highest valid block on the media, relative to zero.
     */
    UInt64		_maxBlock;

    /*!
     * @var _blockSize
     * The block size of the media in bytes.
     */
    UInt64		_blockSize;

    /* The queue of pending requests awaiting power: */

    /*!
     * @struct queue
     * @discussion
     * A data structure for a queue.
     * @field head
     * A pointer to the head item.
     * @field tail
     * A pointer to the tail item.
     * @field lock
     * A lock used to protect the queue during changes.
     */
    /*!
     * @var _powerQueue
     * A queue structure containing operations queued awaiting power level.
     */
    struct queue {
        struct context * head;
        struct context * tail;
        IOLock *	 lock;
    }			_powerQueue;
    
};
#endif
