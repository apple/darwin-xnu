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

#include <IOKit/IOLib.h>
#include <IOKit/IOReturn.h>
#include <IOKit/scsi/IOSCSIDeviceInterface.h>
#include <IOKit/scsi/scsi-device/SCSIDevice.h>
#include <IOKit/storage/scsi/IOBasicSCSI.h>

#define	super	IOService
OSDefineMetaClass(IOBasicSCSI,IOService)
OSDefineAbstractStructors(IOBasicSCSI,IOService)

void IOBasicSCSI_gc_glue(void *object,void *param);

/* Allocate a new context struct. A return of NULL means we couldn't
 * allocate either the context itself or one of its members.
 */
struct IOBasicSCSI::context *
IOBasicSCSI::allocateContext(void)
{
    struct context *cx;

    //xxx IOLog("allocateContext entered\n");

    /* First, the context structure itself. */
    
     cx = IONew(struct context,1);
    if (cx == NULL) {
        return(NULL);
    }

    bzero(cx,sizeof(struct context));

    /* Allocate all the structs and objects we need. If any allocation
     * fails, we can simply call deleteContext() to free anything
     * allocated so far.
     */

    cx->scsireq = _provider->allocCommand(kIOSCSIDevice, 0);
    if (cx->scsireq == NULL) {
        deleteContext(cx);
        return(NULL);
    }


    /* Preset the completion parameters, which are the same for
     * all SCSI requests we issue. Only the target function changes.
     */

    cx->senseData = (SCSISenseData *)IOMalloc(256);
    if (cx-> senseData == NULL) {
        deleteContext(cx);
        return(NULL);
    }

    bzero(cx->senseData, 256 );

    cx->senseDataDesc = IOMemoryDescriptor::withAddress(cx->senseData,
                                                 256,
                                                 kIODirectionIn);


    cx->sync = IOSyncer::create(false);
    if (cx->sync == NULL) {
        deleteContext(cx);
        return(NULL);
    }

    cx->retryInProgress = false;
    
    /* We defer allocation of the Memory Descriptor till later;
     * it will be allocated where it's needed.
     */
    
    // IOLog("allocateContext returning cx = %08x\n",(unsigned int)cx);

    return(cx);
}

IOReturn
IOBasicSCSI::allocateInquiryBuffer(UInt8 **buf,UInt32 size)
{
    *buf = (UInt8 *)IOMalloc(size);
    if (*buf == NULL) {
        return(kIOReturnNoMemory);
    }

    bzero(*buf,size);
        
    return(kIOReturnSuccess);
}

IOReturn
IOBasicSCSI::allocateTempBuffer(UInt8 **buf,UInt32 size)
{
    *buf = (UInt8 *)IOMalloc(size);
    if (*buf == NULL) {
        return(kIOReturnNoMemory);
    }

    bzero(*buf,size);
        
    return(kIOReturnSuccess);    
}

IOReturn
IOBasicSCSI::allocateReadCapacityBuffer(UInt8 **buf,UInt8 size)
{
    *buf = (UInt8 *)IOMalloc(size);
    if (*buf == NULL) {
        return(kIOReturnNoMemory);
    }

    bzero(*buf,size);
        
    return(kIOReturnSuccess);
}

UInt32 
IOBasicSCSI::createReadCdb(UInt8 *cdb,UInt32 *cdbLength,
                          UInt32 block,UInt32 nblks,
                          UInt32 *maxAutoSenseLength,
                          UInt32 *timeoutSeconds)
{
    struct IORWcdb *c;

    c = (struct IORWcdb *)cdb;
    
    c->opcode = SOP_READ10;
    c->lunbits = 0;
    
    c->lba_3 = block >> 24;
    c->lba_2 = block >> 16;
    c->lba_1 = block >>  8;
    c->lba_0 = block  & 0xff;

    c->reserved = 0;

    c->count_msb = nblks >> 8;
    c->count_lsb = nblks  & 0xff;

    c->ctlbyte = 0;

    *cdbLength = 10;
    *maxAutoSenseLength = 8;		/* do the sense */
    *timeoutSeconds = 60;
    return(0);
}

UInt32 
IOBasicSCSI::createWriteCdb(UInt8 *cdb,UInt32 *cdbLength,
                          UInt32 block,UInt32 nblks,
                          UInt32 *maxAutoSenseLength,
                          UInt32 *timeoutSeconds)
{
    struct IORWcdb *c;

    c = (struct IORWcdb *)cdb;
    
    c->opcode = SOP_WRITE10;
    c->lunbits = 0;
    
    c->lba_3 = block >> 24;
    c->lba_2 = block >> 16;
    c->lba_1 = block >>  8;
    c->lba_0 = block  & 0xff;

    c->reserved = 0;

    c->count_msb = nblks >> 8;
    c->count_lsb = nblks  & 0xff;

    c->ctlbyte = 0;

    *cdbLength = 10;
    *maxAutoSenseLength = sizeof( SCSISenseData );      	/* do the sense */
    *timeoutSeconds = 60;
    return(0);
}

void
IOBasicSCSI::deleteContext(struct context *cx)
{
    // IOLog("deleteContext %08x\n",(unsigned int)cx);

    if (cx->scsireq) {
       cx->scsireq->release();
    }
    
//    if (cx->scsiresult) {
//       IODelete(cx->scsiresult,struct IOSCSIResult,1);
//    }

    if (cx->senseData)
    { 
        IOFree( cx->senseData, 256 );
    }

    if ( cx->senseDataDesc )
    {
        cx->senseDataDesc->release();
    }

    if (cx->memory) {
        cx->memory->release();
    }
    
    if (cx->sync) {
        cx->sync->release();
    }
    
    IODelete(cx,struct context,1);
}

void
IOBasicSCSI::deleteInquiryBuffer(UInt8 *buf,UInt32 size)
{
    IOFree((void *)buf,size);
}

void
IOBasicSCSI::deleteTempBuffer(UInt8 *buf,UInt32 len)
{
    IOFree((void *)buf,len);
}

void
IOBasicSCSI::deleteReadCapacityBuffer(UInt8 *buf,UInt32 len)
{
    IOFree((void *)buf,len);
}

IOReturn
IOBasicSCSI::doInquiry(UInt8 *inqBuf,UInt32 maxLen,UInt32 *actualLen)
{
    _provider->getInquiryData( inqBuf, maxLen, actualLen );
    return kIOReturnSuccess;
}    

IOReturn
IOBasicSCSI::doReadCapacity(UInt64 *blockSize,UInt64 *maxBlock)
{
    struct context *cx;
    struct IOReadCapcdb *c;
    IOSCSICommand *req;
    SCSICDBInfo	scsiCDB;
    UInt8 *buf;
    IOReturn result;
    
    cx = allocateContext();
    if (cx == NULL) {
        return(kIOReturnNoMemory);
    }

    req = cx->scsireq;

    bzero( &scsiCDB, sizeof(SCSICDBInfo) );

    c = (struct IOReadCapcdb *)&scsiCDB.cdb;
    c->opcode = SOP_READCAP;
    c->lunbits = 0;
    c->lba_3 = 0;
    c->lba_2 = 0;
    c->lba_1 = 0;
    c->lba_0 = 0;
    c->reserved1 = 0;
    c->reserved2 = 0;
    c->reserved3 = 0;    
    c->ctlbyte = 0;
    
    scsiCDB.cdbLength = 10;

    req->setCDB( &scsiCDB );
    req->setPointers( cx->senseDataDesc, sizeof(SCSISenseData), false, true );

    req->setTimeout( 30000 );

    *blockSize = 0;
    *maxBlock = 0;
    
    result = allocateReadCapacityBuffer(&buf,kReadCapSize);
    
    if (result == kIOReturnSuccess) {

        cx->memory = IOMemoryDescriptor::withAddress((void *)buf,
                                                     kReadCapSize,
                                                     kIODirectionIn);
    
        req->setPointers( cx->memory, kReadCapSize, false );

	/* We force the drive to be completely powered-up, including the mechanical
	 * components, because some drives (e.g. CDs) access the media.
	 */

	queueCommand(cx,kSync,getReadCapacityPowerState());	/* queue the operation, sleep awaiting power */

        result = simpleSynchIO(cx);

        if (result == kIOReturnSuccess) {

            *blockSize = (buf[4] << 24) |	/* endian-neutral */
                        (buf[5] << 16) |
                        (buf[6] <<  8) |
                        (buf[7]      );

            *maxBlock  = (buf[0] << 24) |	/* endian-neutral */
                        (buf[1] << 16) |
                        (buf[2] <<  8) |
                        (buf[3]      );
        }
        
        deleteReadCapacityBuffer(buf,kReadCapSize);
    }

    deleteContext(cx);

    return(result);
}

void
IOBasicSCSI::free(void)
{
    if (_inqBuf) {
        deleteInquiryBuffer(_inqBuf,_inqBufSize);
        _inqBuf = NULL;
    }

#ifdef DISKPM
    if (_powerQueue.lock) {
        IOLockFree(_powerQueue.lock);
    }
#endif

    if (_busResetContext) {
        deleteContext(_busResetContext);
    }
    if (_unitAttentionContext) {
        deleteContext(_unitAttentionContext);
    }

    super::free();
}

/* The Callback (C) entry from the SCSI provider. We just glue
 * right into C++.
 */

void
IOBasicSCSI_gc_glue(void *object,void *param)
{
    IOBasicSCSI *self;
    struct IOBasicSCSI::context *cx;

    self = (IOBasicSCSI *)object;
    cx = (struct IOBasicSCSI::context *)param;
    self->genericCompletion(cx);    	/* do it in C++ */
}

void
IOBasicSCSI::setupBusResetRecovery(void)
{
    IOLog("%s[IOBasicSCSI]: SCSI bus reset occurred; begin recovery.\n",getName());
    
    _busResetContext->step = 1;
    _busResetRecoveryInProgress = true;
    _provider->holdQueue(kQTypeNormalQ);
    // _provider->flushQueue(kQTypeNormalQ,kIOReturnAborted);
}

void
IOBasicSCSI::beginBusResetRecovery(void)
{
    /* In this method, we issue the first command necessary to recover
     * from the Bus Reset condition. Its completion will call
     * busResetRecoveryCommandComplete, which is respnsible for starting
     * the next command, until all have been executed.
     *
     * The default implementation of this method does nothing, except
     * to call finishBusResetRecovery immediately.
     */

    // IOLog("%s[IOBasicSCSI]: beginBusReset\n",getName());
    finishBusResetRecovery();
}

void
IOBasicSCSI::busResetRecoveryCommandComplete(struct IOBasicSCSI::context *cx)
{
    /* We are entered for each command completion during bus reset recovery.
     *
     * Do whatever we have to upon completion of one of our commands.
     *
     * Typically we would increment "step" then start another asynchronous
     * command. When we have finished running off the whole set of required
     * operations then we call finishBusResetRecovery.
     *
     * The default implementation does nothing.
     */
}

void
IOBasicSCSI::finishBusResetRecovery(void)
{
    /* Release the IO queue so that any pending commands can start. */
    
    IOLog("%s[IOBasicSCSI]: SCSI bus reset recovery complete.\n",getName());
    _provider->releaseQueue(kQTypeNormalQ);
    _busResetRecoveryInProgress = false;
}

bool
IOBasicSCSI::unitAttentionDetected(struct IOBasicSCSI::context *cx)
{
    SCSIResults scsiResults;

    /* We're not currently handling a Unit Attention: see if
     * we just got a one to handle. Note that we do NOT have to
     * detect Bus Reset here, because we receive notification of
     * that event asynchronously via the message() method.
     */

    cx->scsireq->getResults(&scsiResults);

    /* A special case is Unit Attention, which can happen at any time. We begin
     * the Unit Attention recovery procedure which issues multiple asynch commands
     * to restore the device condition. After the recovery procedure completes,
     * it causes a retry of the original command.
     */
    
    if (scsiResults.requestSenseDone == true) {        		/* an error occurred */

        // IOLog("%s[IOBasicSCSI]::unitAttentionDetected: sense code %02x\n",
            // getName(),cx->scsiresult->scsiSense[02]);

        if ((cx->senseData->senseKey & 0x0f) == kUnitAttention) {	/* it's a UA */

            // IOLog("%s[IOBasicSCSI]::unitAttentionDetected: detected UnitAttention\n",
            //    getName());

            return(true);
        }

    }			/* no sense data, therefore NOT a Unit Attention */

    return(false);
}

void
IOBasicSCSI::setupUnitAttentionRecovery(struct IOBasicSCSI::context *cx)
{
    if (!_unitAttentionRecoveryInProgress) {

        /* Save original IO context and set step. */

        _unitAttentionContext->originalIOContext = cx;

        _unitAttentionContext->step = 1;

        _unitAttentionRecoveryInProgress = true;

        beginUnitAttentionRecovery();
    }
}

void
IOBasicSCSI::beginUnitAttentionRecovery(void)
{
    /* In this method, we issue the first command necessary to recover
     * from the Unit Attention condition. Its completion will call
     * unitAttentionCommandComplete, which is respnsible for starting
     * the next command, until all have been executed.
     *
     * The default implementation of this method does nothing, except
     * to call finishUnitAttentionRecovery immediately.
     */

    finishUnitAttentionRecovery();
}

void
IOBasicSCSI::unitAttentionRecoveryCommandComplete(struct IOBasicSCSI::context *cx)
{
    /* We are entered for each command completion during Unit Attention recovery.
     *
     * Do whatever we have to upon completion of one of our commands.
     *
     * Typically we would increment "step" then start another asynchronous
     * command. When we have finished running off the whole set of required
     * operations then we call finishUnitAttentionRecovery.
     *
     * The default implementation does nothing.
     */
}

void
IOBasicSCSI::finishUnitAttentionRecovery(void)
{
    /* When we're done, we reissue the command that caught the Unit Attention. */

    _unitAttentionRecoveryInProgress = false;
    _unitAttentionContext->originalIOContext->scsireq->execute();
}

bool
IOBasicSCSI::automaticRetry(struct IOBasicSCSI::context *cx)
{
    SCSIResults scsiResults;

    if (unitAttentionDetected(cx)) {		/* do an automatic retry for Unit Attention */
        setupUnitAttentionRecovery(cx);
        return(true);
    }
    
    cx->scsireq->getResults(&scsiResults);
    
    if (scsiResults.returnCode != kIOReturnSuccess &&
        scsiResults.returnCode != kIOReturnError) {
        /**
         IOLog("%s[IOBasicSCSI]: retcode = %08lx / %s\n",
            getName(),scsiResults.returnCode,stringFromReturn(scsiResults.returnCode));
        **/
    }
    
    if (scsiResults.returnCode == kIOReturnAborted	||
        scsiResults.returnCode == kIOReturnTimeout)		{	/* must be a Bus Reset abort */
        if (!cx->retryInProgress) {		/* start a retry if not already doing one */
            cx->retryInProgress = true;
            cx->retryCount = kMaxRetries;
        }
        if (cx->retryCount > 0) {		/* OK to continue retrying */
            IOLog("%s[IOBasicSCSI]: AutoRetry cx @ %08lx, cmd @ %08lx; %ld retries to go.\n",
                        getName(),(unsigned long)cx,(unsigned long)cx->scsireq,cx->retryCount);
            cx->retryCount--;
            cx->scsireq->execute();
            return(true);
        } else {
            cx->retryInProgress = false;
            return(false);
        }
    }

    return(customAutomaticRetry(cx));
}

bool
IOBasicSCSI::customAutomaticRetry(struct IOBasicSCSI::context *cx)
{
    return(false);				/* the default does nothing special */
}

void
IOBasicSCSI::genericCompletion(struct IOBasicSCSI::context *cx)
{

    /* We dispatch the completion depending on our state. */

     // IOLog("%s[IOBasicSCSI]::genericCompletion: dispatching, state = %s\n",
           // getName(),stringFromState(cx->state));

    switch (cx->state) {

        case kSimpleSynchIO :
                if (!automaticRetry(cx)) {
                    cx->sync->signal(kIOReturnSuccess,false);	/* Just wake up the waiting thread: */
                }
                break;

        case kAsyncReadWrite :			/* normal r/w completion */
                if (!automaticRetry(cx)) {
                    RWCompletion(cx);
                    deleteContext(cx);
                }
                break;

        case kHandlingRecoveryAfterBusReset :	/* still handling recovery after reset */
                if (!automaticRetry(cx)) {
                    busResetRecoveryCommandComplete(cx);
                }
                break;				/* just wait for next completion */

        case kHandlingUnitAttention :		/* still handling UA */
                unitAttentionRecoveryCommandComplete(cx);
                break;				/* just wait for next completion */

        case kNone :				/* undefined */
        case kMaxStateValue :
        case kAwaitingPower :
                break;
    }
        
    return;
}

char *
IOBasicSCSI::getAdditionalDeviceInfoString(void)
{
    return("[SCSI]");
}

UInt64
IOBasicSCSI::getBlockSize(void)
{
    return(_blockSize);
}

char *
IOBasicSCSI::getProductString(void)
{
    return(_product);
}

char *
IOBasicSCSI::getRevisionString(void)
{
    return(_rev);
}

char *
IOBasicSCSI::getVendorString(void)
{
    return(_vendor);
}

bool
IOBasicSCSI::init(OSDictionary * properties)
{
    _inqBuf	= NULL;
    _inqBufSize	= 0;
    _inqLen	= 0;
    
    _vendor[8]		= '\0';
    _product[16]	= '\0';
    _rev[4]		= '\0';

    _readCapDone	= false;
    _blockSize		= 0;
    _maxBlock		= 0;
    _removable		= false;

#ifdef DISKPM
    _powerQueue.head   	= NULL;
    _powerQueue.tail	= NULL;
    _powerQueue.lock	= IOLockAlloc();
    if (_powerQueue.lock == NULL) {
        return(false);
    }
#endif
    
    return(super::init(properties));
}

IOReturn
IOBasicSCSI::message(UInt32 type,IOService * provider,void * argument)
{
   // IOLog("%s[IOBasicSCSI]: message: type = %lx\n",getName(),type);
   switch (type) {
        case kSCSIClientMsgBusReset :			/* Bus Reset has begun */
            if (!_busResetRecoveryInProgress) {		/* try to avoid reset-within-reset recovery */
                setupBusResetRecovery();		/* indicate recovery will be in progress */
            }
            break;					/* now wait till reset is done */

        case (kSCSIClientMsgBusReset | kSCSIClientMsgDone) :	/* Bus Reset is finished */
            beginBusResetRecovery();			/* now start the actual recovery process */
            break;
            
        default :
            return(super::message(type,provider,argument));	/* not one of ours */
    }

    return(kIOReturnSuccess);
}

IOService *
IOBasicSCSI::probe(IOService * provider,SInt32 * score)
{
    IOReturn result;
    OSString * string;

    if (!super::probe(provider,score)) {
        return(NULL);
    }

    _provider = (IOSCSIDevice *)provider;

    /* Do an inquiry to get the device type. The inquiry buffer will
     * be deleted by free().
     */

    _inqBufSize = kMaxInqSize;
    result = allocateInquiryBuffer(&_inqBuf,_inqBufSize);
    if (result != kIOReturnSuccess) {
        return(NULL);
    }

    result = doInquiry(_inqBuf,_inqBufSize,&_inqLen);
    if (result != kIOReturnSuccess) {
        return(NULL);
    }

#ifdef notdef
    // xxx NEVER match for ID=0, the boot disk. This lets us
    // test this driver on other disk drives.
    //
    if (_provider->getTarget() == 0) {
	IOLog("**%s[IOBasicSCSI]:probe; ignoring SCSI ID %d\n",
	    getName(),(int)_provider->getTarget());
	return(NULL);
    }
#endif

    // Fetch SCSI device information from the nub.

    string = OSDynamicCast(OSString,
                    _provider->getProperty(kSCSIPropertyVendorName));
    if (string) {
        strncpy(_vendor, string->getCStringNoCopy(), 8);
        _vendor[8] = '\0';
    }

    string = OSDynamicCast(OSString,
                    _provider->getProperty(kSCSIPropertyProductName));
    if (string) {
        strncpy(_product, string->getCStringNoCopy(), 16);
        _product[16] = '\0';
    }

    string = OSDynamicCast(OSString,
                    _provider->getProperty(kSCSIPropertyProductRevision));
    if (string) {
        strncpy(_rev, string->getCStringNoCopy(), 4);
        _rev[4] = '\0';
    }

    if (deviceTypeMatches(_inqBuf,_inqLen,score)) {

/***
	IOLog("**%s[IOBasicSCSI]::probe; accepting %s, %s, %s, %s; SCSI ID %d\n",
            getName(),getVendorString(),getProductString(),getRevisionString(),
            getAdditionalDeviceInfoString(),
	    (int)_provider->getTarget());
***/        
        return(this);

    } else {
        return(NULL);
    }
}

void
IOBasicSCSI::dequeueCommands(void)
{
#ifdef DISKPM
    struct queue *q;
    IOReturn result;

    q = &_powerQueue;

    IOLockLock(q->lock);

    /* Dequeue and execute all requests for which we have the proper power level. */

    while (q->head) {
        cx = q->head;
        if (pm_vars->myCurrentState != cx->desiredPower) {
            break;
        }
        q->head = cx->next;		/* remove command from the queue */
        if (q->head == NULL) {
            q->tail = NULL;
        }

        cx->state = kNone;
        
        /* If the queued request was synchronous, all we have to do is wake it up. */

        if (cx->isSync) {
            cx->sync->signal(kIOReturnSuccess, false);		/* Just wake up the waiting thread: */

        } else {				/* it's async; fire it off! */
            result = standardAsyncReadWriteExecute(cx);	/* execute the async IO */
            if (result != kIOReturnSuccess) {	/* provider didn't accept it! */
                RWCompletion(cx);		/* force a completion */
            }
        }
    };

    IOLockUnlock(q->lock);
#endif
}

void
IOBasicSCSI::queueCommand(struct context *cx,bool isSync,UInt32 desiredPower)
{
#ifndef DISKPM	//for now, just return immediately without queueing
    /* If we're ifdefed out, we have to start async requests. Sync requests
     * will just return immediately without any delay for power.
     */
    if (isSync == kAsync) {
        (void)standardAsyncReadWriteExecute(cx);	/* execute the async IO */
    }
#else
    struct queue *q;

    /* First, we enqueue the request to ensure sequencing with respect
     * to other commands that may already be in the queue.
     */
    
    q = &_powerQueue;

    cx->next = NULL;
    cx->state = kAwaitingPower;

    IOLockLock(q->lock);

    if (q->head == NULL) {			/* empty queue */
        q->head = cx;
        q->tail = q->head;
        
    } else {					/* not empty; add after tail */
        q->tail->next = cx;
        q->tail = cx;
    }

    /* If the command is synchronous, start by assuming we'll have to sleep
     * awaiting power (and subsequent dequeuing). If, however, power is already
     * right, then dequeuCommands will unlock the lock and we will continue,
     * returning inline to the call site, exactly as if we were awakened.
     *
     * An async request will call dequeueCommands and always return immediately.
     */

    IOLockUnlock(q->lock);

    /* Now we try to dequeue pending commands if the power's right. */

    dequeueCommands();

    /* If we're synchronous, we'll wait here till dequeued. If we were
     * dequeued above (and unlocked), then we'll return to allow the
     * caller to continue with the command execution.
     */

    if (isSync) {
	cx->sync->wait(false);		/* waits here till awakened */
    }
#endif //DISKPM
}

IOReturn
IOBasicSCSI::reportBlockSize(UInt64 *blockSize)
{
    IOReturn result;

    *blockSize = 0;
    result = kIOReturnSuccess;

    if (_readCapDone == false) {
	result = doReadCapacity(&_blockSize,&_maxBlock);
	_readCapDone = true;
    }

    if (result == kIOReturnSuccess) {
	*blockSize = _blockSize;
    }

    return(result);
}

IOReturn
IOBasicSCSI::reportEjectability(bool *isEjectable)
{
    *isEjectable = true;		/* default: if it's removable, it's ejectable */
    return(kIOReturnSuccess);
}

IOReturn
IOBasicSCSI::reportLockability(bool *isLockable)
{
    *isLockable = true;		/* default: if it's removable, it's lockable */
    return(kIOReturnSuccess);
}

IOReturn
IOBasicSCSI::reportMaxReadTransfer (UInt64 blocksize,UInt64 *max)
{
    *max = blocksize * 65536;		/* max blocks in a SCSI transfer */
    return(kIOReturnSuccess);
}

IOReturn
IOBasicSCSI::reportMaxValidBlock(UInt64 *maxBlock)
{
    IOReturn result;

    *maxBlock = 0;
    result = kIOReturnSuccess;

    if (_readCapDone == false) {
	result = doReadCapacity(&_blockSize,&_maxBlock);
	_readCapDone = true;
    }

    if (result == kIOReturnSuccess) {
	*maxBlock = _maxBlock;
    }
    return(result);
}

IOReturn
IOBasicSCSI::reportMaxWriteTransfer(UInt64 blocksize,UInt64 *max)
{
    *max = blocksize * 65536;		/* max blocks in a SCSI transfer */
    return(kIOReturnSuccess);
}

IOReturn
IOBasicSCSI::reportPollRequirements(bool *pollRequired,bool *pollIsExpensive)
{
    *pollIsExpensive = false;
    *pollRequired = _removable;		/* for now, all removables need polling */
    return(kIOReturnSuccess);
}

IOReturn
IOBasicSCSI::reportRemovability(bool *isRemovable)
{
    if (_inqLen > 0) {			/* inquiry byte exists to check */
        if (_inqBuf[1] & 0x80) {		/* it's removable */
            *isRemovable = true;
            _removable = true;
        } else {			/* it's not removable */
            *isRemovable = false;
            _removable = false;
        }
    } else {				/* no byte? call it nonremovable */
        *isRemovable = false;
    }

    return(kIOReturnSuccess);
}

/* Issue a Mode Sense to get the Mode Parameter Header but no pages.
 * Since we're only interested in the Mode Parameter Header, we just
 * issue a standard SCSI-1 6-byte command, nothing fancy.
 */
IOReturn
IOBasicSCSI::reportWriteProtection(bool *writeProtected)
{
    struct context *cx;
    struct IOModeSensecdb *c;
    IOSCSICommand *req;
    SCSICDBInfo scsiCDB;
    SCSIResults	scsiResults;
    UInt8 *buf;
    IOReturn result;

    cx = allocateContext();
    if (cx == NULL) {
        return(kIOReturnNoMemory);
    }

    req = cx->scsireq;

    bzero( &scsiCDB, sizeof(SCSICDBInfo) );
  
    c = (struct IOModeSensecdb *)&scsiCDB.cdb;
    c->opcode = SOP_MODESENSE;
    c->lunbits = 0;
    c->pagecode = 0 | 0x01;	 	/* get current settings; any page will work */
    c->reserved = 0;
    c->len = kModeSenseSize;
    c->ctlbyte = 0;

    scsiCDB.cdbLength = 6;

    req->setCDB( &scsiCDB );
    req->setPointers( cx->senseDataDesc, sizeof(SCSISenseData), false, true );

    req->setTimeout( 30000 );

    result = allocateTempBuffer(&buf,kModeSenseSize);
    
    if (result == kIOReturnSuccess) {

        cx->memory = IOMemoryDescriptor::withAddress((void *)buf,
                                                     kModeSenseSize,
                                                     kIODirectionIn);

        req->setPointers( cx->memory, kModeSenseSize, false );

        queueCommand(cx,kSync,getReportWriteProtectionPowerState()); /* queue the op, sleep awaiting power */
    
        result = simpleSynchIO(cx);

        if (result == kIOReturnUnderrun) {
	    cx->scsireq->getResults( &scsiResults );
	    if (scsiResults.bytesTransferred >= 4)
		result = kIOReturnSuccess;
        }

        if (result == kIOReturnSuccess) {
            if (buf[2] & 0x80) {
                *writeProtected = true;
            } else {
                *writeProtected = false;
            }
        }
        
        deleteTempBuffer(buf,kModeSenseSize);
    }

    deleteContext(cx);

    return(result);
}

/* Issue a simple, asynchronous SCSI operation. The caller's supplied context
 * contains a SCSI command and Memory Descriptor. The caller is responsible
 * for deleting the context.
 */

IOReturn
IOBasicSCSI::simpleAsynchIO(struct IOBasicSCSI::context *cx)
{
    IOSCSICommand *req;
    IOReturn result;

    if (cx == NULL) {			/* safety check */
        return(kIOReturnNoMemory);
    }

    /* Set completion to return to genericCompletion: */

    req = cx->scsireq;
    req->setCallback( (void *)this, (CallbackFn)IOBasicSCSI_gc_glue, (void *)cx ); 

    cx->state = kSimpleSynchIO;

    /* Start the scsi request: */

    result = req->execute();

    if (result == true ) {
	result = req->getResults((SCSIResults *) 0);
    }

    return(result);    
}

/* Issue a simple, synchronous SCSI operation. The caller's supplied context
 * contains a SCSI command and Memory Descriptor. The caller is responsible
 * for deleting the context.
 */

IOReturn
IOBasicSCSI::simpleSynchIO(struct context *cx)
{
    IOSCSICommand *req;
    IOReturn result;

    if (cx == NULL) {			/* safety check */
        return(kIOReturnNoMemory);
    }

    /* Set completion to return to genericCompletion: */

    req = cx->scsireq;
    req->setCallback( (void *)this, (CallbackFn)IOBasicSCSI_gc_glue, (void *)cx ); 

    cx->state = kSimpleSynchIO;

/**
    IOLog("%s[IOBasicSCSI]::simpleSynchIO; issuing SCSI cmd %02x\n",
          getName(),req->cdb.byte[0]);
**/
    /* Start the scsi request: */

    //IOLog("IOBasicSCSI::simpleSynchIO, lock initted, calling SCSI\n");

    result = req->execute();

    if (result == true ) {

//	IOLog("IOBasicSCSI::simpleSynchIO, SCSI req accepted\n");

	/* Wait for it to complete by attempting to acquire a read-lock, which
	 * will block until the write-lock is released by the completion routine.
	 */

	cx->sync->wait(false);	/* waits here till unlocked at completion */

	/* We're back: */
      
	result = req->getResults((SCSIResults *) 0);

/**
	if ((result != kIOReturnSuccess) ) {
	    IOLog("%s[IOBasicSCSI]::simpleSynchIO; err '%s' from completed req\n",
                getName(),stringFromReturn(result));
	}
**/
    } else {
/**
	IOLog("%s[IOBasicSCSI]:simpleSynchIO; err '%s' queueing SCSI req\n",
            getName(),stringFromReturn(result));
**/
    }

//    IOLog("IOBasicSCSI: completed; result '%s'\n",stringFromReturn(result));

    return(result);    
}

IOReturn
IOBasicSCSI::standardAsyncReadWrite(IOMemoryDescriptor *buffer,
                                            UInt32 block,UInt32 nblks,
                                            IOStorageCompletion completion)
{  
    struct context *cx;
    IOSCSICommand *req;
    SCSICDBInfo scsiCDB;
    UInt32	reqSenseLength;
    UInt32	timeoutSeconds;
    UInt8 *cdb;
    bool isWrite;

    cx = allocateContext();

    if (cx == NULL) {
        return(kIOReturnNoMemory);
    }

    buffer->retain();			/* bump the retain count */
    
    cx->memory = buffer;
    if (buffer->getDirection() == kIODirectionOut) {
        isWrite = true;
    } else {
        isWrite = false;
    }

/**
    IOLog("%s[IOBasicSCSI]::standardAsyncReadWrite; (%s) blk %ld nblks %ld\n",
        getName(),(isWrite ? "write" : "read"),block,nblks);
**/
    req = cx->scsireq;

    /* Set completion to return to rwCompletion: */    
    cx->completion = completion;

    bzero( &scsiCDB, sizeof(scsiCDB) );
    
    req->setPointers( buffer, nblks * getBlockSize(), isWrite );

    req->setCallback( this, IOBasicSCSI_gc_glue, cx );

    cx->state = kAsyncReadWrite;
    
    cdb = (UInt8 *) &scsiCDB.cdb;

    /* Allow a subclass to override the creation of the cdb and specify
     * other parameters for the operation.
     */
    
    if (isWrite) {
        scsiCDB.cdbFlags |= createWriteCdb(cdb,&scsiCDB.cdbLength,
                                    block,nblks,
                                    &reqSenseLength,
                                    &timeoutSeconds);
        
    } else {
        
        scsiCDB.cdbFlags |= createReadCdb(cdb,&scsiCDB.cdbLength,
                                    block,nblks,
                                    &reqSenseLength,
                                    &timeoutSeconds);
    }

    req->setCDB( &scsiCDB );
    req->setPointers( cx->senseDataDesc, reqSenseLength, false, true );
    req->setTimeout( timeoutSeconds * 1000 );

    /* Queue the request awaiting power and return. When power comes up,
     * the request will be passed to standardAsyncReadWriteExecute.
     */
    queueCommand(cx,kAsync,getReadWritePowerState());	/* queue and possibly wait for power */
    
    return(kIOReturnSuccess);
}

IOReturn
IOBasicSCSI::standardAsyncReadWriteExecute(struct context *cx)
{
    return(cx->scsireq->execute());
}

IOReturn
IOBasicSCSI::standardSyncReadWrite(IOMemoryDescriptor *buffer,UInt32 block,UInt32 nblks)
{
    struct context *cx;
    IOSCSICommand *req;
    SCSICDBInfo scsiCDB;
    UInt32 reqSenseLength;
    UInt32 reqTimeoutSeconds;
    UInt8 *cdb;
    bool isWrite;
    IOReturn result;

    cx = allocateContext();

    if (cx == NULL) {
        return(kIOReturnNoMemory);
    }

    cx->memory = buffer;
    buffer->retain();			/* bump the retain count */
    
    if (buffer->getDirection() == kIODirectionOut) {
        isWrite = true;
    } else {
        isWrite = false;
    }

/**
    IOLog("%s[IOBasicSCSI]::standardSyncReadWrite; (%s) blk %ld nblks %ld\n",
        getName(),(isWrite ? "write" : "read"),block,nblks);
**/

    bzero(&scsiCDB,sizeof(scsiCDB));

    req = cx->scsireq;
    req->setPointers(buffer,(nblks * getBlockSize()),isWrite);
 
    cdb = (UInt8 *)&scsiCDB.cdb;

    /* Allow a subclass to override the creation of the cdb and specify
     * other parameters for the operation.
     */
    
    if (isWrite) {
        scsiCDB.cdbFlags |= createWriteCdb(cdb,&scsiCDB.cdbLength,
                                    block,nblks,
                                    &reqSenseLength,
                                    &reqTimeoutSeconds);
        
    } else {
        
        scsiCDB.cdbFlags |= createReadCdb(cdb,&scsiCDB.cdbLength,
                                    block,nblks,
                                    &reqSenseLength,
                                    &reqTimeoutSeconds);
    }


    req->setCDB(&scsiCDB);
    req->setPointers(cx->senseDataDesc,reqSenseLength,false,true);
    req->setTimeout(reqTimeoutSeconds * 1000);

    queueCommand(cx,kSync,getReadWritePowerState());	/* queue the operation, sleep awaiting power */

    result = simpleSynchIO(cx);		/* issue a simple command */

    deleteContext(cx);
    return(result);
}

bool
IOBasicSCSI::start(IOService *provider)
{
    bool result;
    
    _busResetContext = allocateContext();
    if (_busResetContext == NULL) {
        return(false);
    }
    _busResetContext->state = kHandlingRecoveryAfterBusReset;
    _busResetRecoveryInProgress = false;
    
    _unitAttentionContext = allocateContext();
    if (_unitAttentionContext == NULL) {
        return(false);
    }
    _unitAttentionContext->state = kHandlingUnitAttention;
    _unitAttentionRecoveryInProgress = false;
    
    result = provider->open(this,0,0);	/* set up to receive message() notifications */
    if (result != true) {
        IOLog("open result is false\n");
    }

    return(true);
}

char *
IOBasicSCSI::stringFromState(stateValue state)
{
    static char *stateNames[] = {
					"kNone",
					"kAsyncReadWrite",
					"kSimpleSynchIO",
					"kHandlingUnitAttention",
					"khandlingRecoveryAfterBusReset"
				};

    if (state < 0 || state > kMaxValidState) {
	return("invalid");
    }

    return(stateNames[state]);
}
