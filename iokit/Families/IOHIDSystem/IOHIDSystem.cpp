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
/* 	Copyright (c) 1992 NeXT Computer, Inc.  All rights reserved. 
 *
 * EventDriver.m - Event System module, ObjC implementation.
 *
 *		The EventDriver is a pseudo-device driver.
 *
 * HISTORY
 * 31-Mar-92    Mike Paquette at NeXT 
 *      Created. 
 * 04-Aug-93	Erik Kay at NeXT
 *		minor API cleanup
 * 12-Dec-00	bubba at Apple.
 *		Handle eject key cases on Pro Keyboard.
*/

#include <IOKit/system.h>
#include <IOKit/assert.h>

#include <libkern/c++/OSContainers.h>
#include <libkern/c++/OSCollectionIterator.h>

#include <IOKit/IOTimerEventSource.h>
#include <IOKit/IOCommandQueue.h>
#include <IOKit/IOMessage.h>
#include <IOKit/IOWorkLoop.h>
#include <IOKit/hidsystem/IOHIDevice.h>
#include <IOKit/hidsystem/IOHIDShared.h>
#include <IOKit/hidsystem/IOHIDSystem.h>
#include <IOKit/hidsystem/IOHIKeyboard.h>
#include <IOKit/hidsystem/IOHIPointing.h>
#include <IOKit/hidsystem/IOHIDParameter.h>

#include <IOKit/hidsystem/ev_private.h>	/* Per-machine configuration info */ 
#include "IOHIDUserClient.h"

#include <sys/kdebug.h>

#ifdef __cplusplus
    extern "C"
    {
        #include <UserNotification/KUNCUserNotifications.h>
    }
#endif

bool displayWranglerUp( OSObject *, void *, IOService * );

static IOHIDSystem * evInstance = 0;
MasterAudioFunctions *masterAudioFunctions = 0;

#define xpr_ev_cursor(x, a, b, c, d, e)
#define PtInRect(ptp,rp) \
	((ptp)->x >= (rp)->minx && (ptp)->x <  (rp)->maxx && \
	(ptp)->y >= (rp)->miny && (ptp)->y <  (rp)->maxy)



static inline unsigned AbsoluteTimeToTick( AbsoluteTime * ts )
{
    UInt64	nano;
    absolutetime_to_nanoseconds(*ts, &nano);
    return( nano >> 24 );
}

static inline void TickToAbsoluteTime( unsigned tick, AbsoluteTime * ts )
{
    UInt64	nano = ((UInt64) tick) << 24;
    nanoseconds_to_absolutetime(nano, ts);
}

#define EV_NS_TO_TICK(ns)	AbsoluteTimeToTick(ns)
#define EV_TICK_TO_NS(tick,ns)	TickToAbsoluteTime(tick,ns)


#define super IOService
OSDefineMetaClassAndStructors(IOHIDSystem, IOService);

/* Return the current instance of the EventDriver, or 0 if none. */
IOHIDSystem * IOHIDSystem::instance()
{
  return evInstance;
}

bool IOHIDSystem::init(OSDictionary * properties)
{
  if (!super::init(properties))  return false;

  /*
   * Initialize minimal state.
   */

  driverLock       = NULL;
  kickConsumerLock = NULL;
  evScreen         = NULL;
  timerES          = 0;
  cmdQ             = 0;
  workLoop         = 0;

  return true;
}

IOHIDSystem * IOHIDSystem::probe(IOService * 	provider,
				 SInt32 *	score)
{
  if (!super::probe(provider,score))  return 0;

  return this;
}

/*
 * Perform reusable initialization actions here.
 */
IOWorkLoop * IOHIDSystem::getWorkLoop() const
{
    return workLoop;
}

bool IOHIDSystem::start(IOService * provider)
{
  bool iWasStarted = false;

  do {
    if (!super::start(provider))  break;

    evInstance = this;

    driverLock = IOLockAlloc();	// Event driver data protection lock
    kickConsumerLock = IOLockAlloc();

    /* A few details to be set up... */
    pointerLoc.x = INIT_CURSOR_X;
    pointerLoc.y = INIT_CURSOR_Y;

    pointerDelta.x = 0;
    pointerDelta.y = 0;

    evScreenSize = sizeof(EvScreen) * 6;	// FIX
    evScreen = (void *) IOMalloc(evScreenSize);

    if (!driverLock       ||
        !kickConsumerLock ||
        !evScreenSize)  break;

    IOLockInit(driverLock);
    IOLockInit(kickConsumerLock);
    bzero(evScreen, evScreenSize);

    /*
     * Start up the work loop
     */
    workLoop = IOWorkLoop::workLoop();
    cmdQ = IOCommandQueue::commandQueue
        (this, (IOCommandQueueAction) &_doPerformInIOThread );
    timerES = IOTimerEventSource::timerEventSource
        (this, (IOTimerEventSource::Action) &_periodicEvents );

    if (!workLoop || !cmdQ || !timerES)
        break;

    if ((workLoop->addEventSource(cmdQ)    != kIOReturnSuccess)
    ||  (workLoop->addEventSource(timerES) != kIOReturnSuccess))
        break;

    publishNotify = addNotification(
        gIOPublishNotification, serviceMatching("IOHIDevice"),
        (IOServiceNotificationHandler) &publishNotificationHandler,
        this, 0 );

    if (!publishNotify) break;

    /*
     * IOHIDSystem serves both as a service and a nub (we lead a double
     * life).  Register ourselves as a nub to kick off matching.
     */

    registerService();

    addNotification( gIOPublishNotification,serviceMatching("IODisplayWrangler"),	// look for the display wrangler
                     (IOServiceNotificationHandler)displayWranglerUp, this, 0 );

    iWasStarted = true;
  } while(false);

  if (!iWasStarted)  evInstance = 0;

  return iWasStarted;
}

// **********************************************************************************
// displayWranglerUp
//
// The Display Wrangler has appeared.  We will be calling its
// activityTickle method when there is user activity.
// **********************************************************************************
bool displayWranglerUp( OSObject * us, void * ref, IOService * yourDevice )
{
  if ( yourDevice != NULL ) {
      ((IOHIDSystem *)us)->displayManager = yourDevice;
      ((IOHIDSystem *)us)->displayState = yourDevice->registerInterestedDriver((IOService *)us);
  }
  return true;
}


//*********************************************************************************
// powerStateDidChangeTo
//
// The display wrangler has changed state, so the displays have changed
// state, too.  We save the new state.
//*********************************************************************************

IOReturn IOHIDSystem::powerStateDidChangeTo ( IOPMPowerFlags theFlags, unsigned long, IOService*)
{
    displayState = theFlags;
    return IOPMNoErr;
}



bool IOHIDSystem::publishNotificationHandler(
			IOHIDSystem * self,
			void * /* ref */,
			IOService * newService )
{
    self->attach( newService );

//    IOTakeLock( self->driverLock);
    if( self->eventsOpen
	&& OSDynamicCast(IOHIDevice, newService)) {
	       	self->registerEventSource((IOHIDevice *) newService);
    }
//    IOUnlock( self->driverLock);

    return true;
}


/*
 * Free locally allocated resources, and then ourselves.
 */
void IOHIDSystem::free()
{
    /* Initiates a normal close if open & inited */
    if( driverLock)
        evClose();

    if (evScreen) IOFree( (void *)evScreen, evScreenSize );
    evScreen = (void *)0;
    evScreenSize = 0;

    if (timerES)  	timerES->release();
    if (cmdQ)     	cmdQ->release();
    if (workLoop) 	workLoop->release();
    if (publishNotify) 	publishNotify->release();

    /* Release locally allocated resources */
    if (kickConsumerLock) IOLockFree( kickConsumerLock);
    if (driverLock)       IOLockFree( driverLock);

    super::free();
}



/*
 * Open the driver for business.  This call must be made before
 * any other calls to the Event driver.  We can only be opened by
 * one user at a time.
 */
IOReturn IOHIDSystem::evOpen(void)
{
	IOReturn r = kIOReturnSuccess;
	
	if ( evOpenCalled == true )
	{
		r = kIOReturnBusy;
		goto done;
	}
	evOpenCalled = true;

	if (!evInitialized)
	{
	    evInitialized = true;
	    curBright = EV_SCREEN_MAX_BRIGHTNESS; // FIXME: Set from NVRAM?
	    curVolume = EV_AUDIO_MAX_VOLUME / 2; // FIXME: Set from NVRAM?
	    // Put code here that is to run on the first open ONLY.
	}

done:
	return r;
}

IOReturn IOHIDSystem::evClose(void)
{
	IOTakeLock( driverLock);
	if ( evOpenCalled == false )
	{
		IOUnlock( driverLock);
		return kIOReturnBadArgument;
	}
	// Early close actions here
	forceAutoDimState(false);
	if( cursorEnabled)
            hideCursor();
	cursorStarted = false;
	cursorEnabled = false;
	IOUnlock( driverLock);

	// Release the input devices.
	detachEventSources();

	// Tear down the shared memory area if set up
//	if ( eventsOpen == true )
//	    unmapEventShmem(eventPort);

	IOTakeLock( driverLock);
	// Clear screens registry and related data
	if ( evScreen != (void *)0 )
	{
	    screens = 0;
	    lastShmemPtr = (void *)0;
	}
	// Remove port notification for the eventPort and clear the port out
	setEventPort(MACH_PORT_NULL);
//	ipc_port_release_send(event_port);

	// Clear local state to shutdown
	evOpenCalled = false;
	eventsOpen = false;

	IOUnlock( driverLock);

	return kIOReturnSuccess;
}

//
// Dispatch state to screens registered with the Event Driver
// Pending state changes for a device may be coalesced.
//
//
// On entry, the  driverLock should be set.
//
void IOHIDSystem::evDispatch(
               /* command */ EvCmd evcmd)
{
    Point p;

    if( !eventsOpen)
	return;

    for( int i = 0; i < screens; i++ ) {

        EvScreen *esp = &((EvScreen*)evScreen)[i];
    
        if ( esp->instance )
        {
            p.x = evg->cursorLoc.x;	// Copy from shmem.
            p.y = evg->cursorLoc.y;

            bool onscreen = (0 != (cursorScreens & (1 << i)));
    
            switch ( evcmd )
            {
                case EVMOVE:
                    if (onscreen)
                        esp->instance->moveCursor(&p, evg->frame);
                    break;
    
                case EVSHOW:
                    if (onscreen)
                        esp->instance->showCursor(&p, evg->frame);
                    break;
    
                case EVHIDE:
                    if (onscreen)
                        esp->instance->hideCursor();
                    break;
    
                case EVLEVEL:
                case EVNOP:
                    /* lets keep that compiler happy */
                    break;
            }
        }
    }
}

//
// Dispatch mechanism for special key press.  If a port has been registered,
// a message is built to be sent out to that port notifying that the key has
// changed state.  A level in the range 0-64 is provided for convenience.
//
void IOHIDSystem::evSpecialKeyMsg(unsigned key,
		  /* direction */ unsigned dir,
		  /* flags */     unsigned f,
		  /* level */     unsigned l)
{
	mach_port_t dst_port;
	struct evioSpecialKeyMsg *msg;

	static const struct evioSpecialKeyMsg init_msg =
        { { MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND,	// mach3xxx, is the right?
                        MACH_MSG_TYPE_MAKE_SEND),	// mach_msg_bits_t	msgh_bits;
            sizeof (struct evioSpecialKeyMsg), 		// mach_msg_size_t	msgh_size;
            MACH_PORT_NULL,				// mach_port_t	msgh_remote_port;
            MACH_PORT_NULL,				// mach_port_t	msgh_local_port;
            0,						// mach_msg_size_t msgh_reserved;
            EV_SPECIAL_KEY_MSG_ID			// mach_msg_id_t 	msgh_id;
            },
            0,	/* key */
            0,	/* direction */
            0,	/* flags */
            0	/* level */
        };

	if ( (dst_port = specialKeyPort(key)) == MACH_PORT_NULL )
		return;
	msg = (struct evioSpecialKeyMsg *) IOMalloc(
				sizeof (struct evioSpecialKeyMsg) );
	if ( msg == NULL )
		return;
	
	// Initialize the message.
	bcopy( &init_msg, msg, sizeof (struct evioSpecialKeyMsg) );
	msg->Head.msgh_remote_port = dst_port;
	msg->key = key;
	msg->direction = dir;
	msg->flags = f;
	msg->level = l;

	// Send the message out from the I/O thread.
        sendWorkLoopCommand(this,(IOHIDAction)_performSpecialKeyMsg,(void*)msg);
}

//
// Reset instance variables to their default state for mice/pointers
//
void IOHIDSystem::_resetMouseParameters()
{

	IOTakeLock( driverLock);
	if ( eventsOpen == false )
	{
	    IOUnlock( driverLock);
	    return;
	}
        nanoseconds_to_absolutetime( EV_DCLICKTIME, &clickTimeThresh);
	clickSpaceThresh.x = clickSpaceThresh.y = EV_DCLICKSPACE;
        AbsoluteTime_to_scalar( &clickTime) = 0;
	clickLoc.x = clickLoc.y = -EV_DCLICKSPACE;
	clickState = 1;
        nanoseconds_to_absolutetime( DAUTODIMPERIOD, &autoDimPeriod);
        clock_get_uptime( &autoDimTime);
        ADD_ABSOLUTETIME( &autoDimTime, &autoDimPeriod);
        dimmedBrightness = DDIMBRIGHTNESS;

	IOUnlock( driverLock);
}

void IOHIDSystem::_resetKeyboardParameters()
{
}

/*
 * Methods exported by the EventDriver.
 *
 *	The screenRegister protocol is used by frame buffer drivers to register
 *	themselves with the Event Driver.  These methods are called in response
 *	to a registerSelf or unregisterSelf message received from the Event
 *	Driver.
 */

int IOHIDSystem::registerScreen(IOGraphicsDevice * instance,
		/* bounds */    Bounds * bp)
{
    EvScreen *esp;

    if( (false == eventsOpen) || (0 == bp) )
    {
	return -1;
    }

    if ( lastShmemPtr == (void *)0 )
	lastShmemPtr = evs;
    
    /* shmemSize and bounds already set */
    esp = &((EvScreen*)evScreen)[screens];
    esp->instance = instance;
    esp->bounds = bp;
    // Update our idea of workSpace bounds
    if ( bp->minx < workSpace.minx )
	workSpace.minx = bp->minx;
    if ( bp->miny < workSpace.miny )
	workSpace.miny = bp->miny;
    if ( bp->maxx < workSpace.maxx )
	workSpace.maxx = bp->maxx;
    if ( esp->bounds->maxy < workSpace.maxy )
	workSpace.maxy = bp->maxy;

    return(SCREENTOKEN + screens++);
}


void IOHIDSystem::unregisterScreen(int index)
{
    index -= SCREENTOKEN;

    IOTakeLock( driverLock);
    if ( eventsOpen == false || index < 0 || index >= screens )
    {
	IOUnlock( driverLock);
	return;
    }
    hideCursor();

    // clear the state for the screen
    ((EvScreen*)evScreen)[index].instance = 0;
    // Put the cursor someplace reasonable if it was on the destroyed screen
    cursorScreens &= ~(1 << index);
    // This will jump the cursor back on screen
    setCursorPosition((Point *)&evg->cursorLoc, true);

    showCursor();

    IOUnlock( driverLock);
}

/* Member of EventClient protocol 
 *
 * Absolute position input devices and some specialized output devices
 * may need to know the bounding rectangle for all attached displays.
 * The following method returns a Bounds* for the workspace.  Please note
 * that the bounds are kept as signed values, and that on a multi-display
 * system the minx and miny values may very well be negative.
 */
Bounds * IOHIDSystem::workspaceBounds()
{
	return &workSpace;
}

IOReturn IOHIDSystem::createShmem(void* p1, void*, void*, void*, void*, void*)
{                                                                    // IOMethod
    int                 shmemVersion = (int)p1;
    IOByteCount		size;

    if( shmemVersion != kIOHIDCurrentShmemVersion)
	return( kIOReturnUnsupported);

    IOTakeLock( driverLock);

    if( 0 == globalMemory) {

        size = sizeof(EvOffsets) + sizeof(EvGlobals);
	globalMemory = IOBufferMemoryDescriptor::withOptions(
			kIODirectionNone | kIOMemoryKernelUserShared, size );

        if( !globalMemory) {
            IOUnlock( driverLock);
            return( kIOReturnNoMemory );
	}
	shmem_addr = (vm_offset_t) globalMemory->getBytesNoCopy();
        shmem_size = size;
    }

    initShmem();
    IOUnlock( driverLock);

    return kIOReturnSuccess;
}


// Initialize the shared memory area.
//
// On entry, the driverLock should be set.
void IOHIDSystem::initShmem()
{
	int		i;
	EvOffsets	*eop;

	/* top of sharedMem is EvOffsets structure */
	eop = (EvOffsets *) shmem_addr;

	bzero( (void*)shmem_addr, shmem_size);
	
	/* fill in EvOffsets structure */
	eop->evGlobalsOffset = sizeof(EvOffsets);
	eop->evShmemOffset = eop->evGlobalsOffset + sizeof(EvGlobals);
    
	/* find pointers to start of globals and private shmem region */
	evg = (EvGlobals *)((char *)shmem_addr + eop->evGlobalsOffset);
	evs = (void *)((char *)shmem_addr + eop->evShmemOffset);
    
	evg->version = kIOHIDCurrentShmemVersion;
	evg->structSize = sizeof( EvGlobals);

	/* Set default wait cursor parameters */
	evg->waitCursorEnabled = TRUE;
	evg->globalWaitCursorEnabled = TRUE;
	evg->waitThreshold = (12 * EV_TICKS_PER_SEC) / 10;
        clock_interval_to_absolutetime_interval(DefaultWCFrameRate, kNanosecondScale,
                                                &waitFrameRate);
        clock_interval_to_absolutetime_interval(DefaultWCSustain, kNanosecondScale,
                                                &waitSustain);
        AbsoluteTime_to_scalar(&waitSusTime) = 0;
        AbsoluteTime_to_scalar(&waitFrameTime) = 0;

	EV_TICK_TO_NS(10,&periodicEventDelta);

	/* Set up low-level queues */
	lleqSize = LLEQSIZE;
	for (i=lleqSize; --i != -1; ) {
	    evg->lleq[i].event.type = 0;
            AbsoluteTime_to_scalar(&evg->lleq[i].event.time) = 0;
            evg->lleq[i].event.flags = 0;
	    ev_init_lock(&evg->lleq[i].sema);
	    evg->lleq[i].next = i+1;
	}
	evg->LLELast = 0;
	evg->lleq[lleqSize-1].next = 0;
	evg->LLEHead =
	    evg->lleq[evg->LLELast].next;
	evg->LLETail =
	    evg->lleq[evg->LLELast].next;
	evg->buttons = 0;
	evg->eNum = INITEVENTNUM;
	evg->eventFlags = 0;

        AbsoluteTime	ts;
        unsigned	tick;
        clock_get_uptime( &ts);
        tick = EV_NS_TO_TICK(&ts);
        if ( tick == 0 )
                tick = 1;	// No zero values allowed!
	evg->VertRetraceClock = tick;

        evg->cursorLoc.x = pointerLoc.x;
	evg->cursorLoc.y = pointerLoc.y;
	evg->dontCoalesce = 0;
	evg->dontWantCoalesce = 0;
	evg->wantPressure = 0;
	evg->wantPrecision = 0;
	evg->mouseRectValid = 0;
	evg->movedMask = 0;
	ev_init_lock( &evg->cursorSema );
	ev_init_lock( &evg->waitCursorSema );
	// Set eventsOpen last to avoid race conditions.
	eventsOpen = true;
}

//
// Set the event port.  The event port is both an ownership token
// and a live port we hold send rights on.  The port is owned by our client,
// the WindowServer.  We arrange to be notified on a port death so that
// we can tear down any active resources set up during this session.
// An argument of PORT_NULL will cause us to forget any port death
// notification that's set up.
//
// The driverLock should be held on entry.
//
void IOHIDSystem::setEventPort(mach_port_t port)
{
	static struct _eventMsg init_msg = { {
            // mach_msg_bits_t	msgh_bits;
            MACH_MSGH_BITS(MACH_MSG_TYPE_COPY_SEND,0),
            // mach_msg_size_t	msgh_size;
            sizeof (struct _eventMsg),
            // mach_port_t	msgh_remote_port;
            MACH_PORT_NULL,
            // mach_port_t	msgh_local_port;
            MACH_PORT_NULL,
            // mach_msg_size_t 	msgh_reserved;
            0,
            // mach_msg_id_t	msgh_id;
            0
        } };

	if ( eventMsg == NULL )
		eventMsg = IOMalloc( sizeof (struct _eventMsg) );
	eventPort = port;
	// Initialize the events available message.
	*((struct _eventMsg *)eventMsg) = init_msg;

	((struct _eventMsg *)eventMsg)->h.msgh_remote_port = port;
}

//
// Set the port to be used for a special key notification.  This could be more
// robust about letting ports be set...
//
IOReturn IOHIDSystem::setSpecialKeyPort(
                        /* keyFlavor */ int         special_key,
                        /* keyPort */   mach_port_t key_port)
{
	if ( special_key >= 0 && special_key < NX_NUM_SCANNED_SPECIALKEYS )
		_specialKeyPort[special_key] = key_port;
	return kIOReturnSuccess;
}

mach_port_t IOHIDSystem::specialKeyPort(int special_key)
{
	if ( special_key >= 0 && special_key < NX_NUM_SCANNED_SPECIALKEYS )
		return _specialKeyPort[special_key];
	return MACH_PORT_NULL;
}

//
// Helper functions for postEvent
//
static inline int myAbs(int a) { return(a > 0 ? a : -a); }

short IOHIDSystem::getUniqueEventNum()
{
    while (++evg->eNum == NULLEVENTNUM)
	; /* sic */
    return(evg->eNum);
}

// postEvent 
//
// This routine actually places events in the event queue which is in
// the EvGlobals structure.  It is called from all parts of the ev
// driver.
//
// On entry, the driverLock should be set.
//

void IOHIDSystem::postEvent(int           what,
             /* at */       Point *       location,
             /* atTime */   AbsoluteTime  ts,
             /* withData */ NXEventData * myData)
{
    NXEQElement	* theHead = (NXEQElement *) &evg->lleq[evg->LLEHead];
    NXEQElement	* theLast = (NXEQElement *) &evg->lleq[evg->LLELast];
    NXEQElement	* theTail = (NXEQElement *) &evg->lleq[evg->LLETail];
    int		  wereEvents;
    unsigned      theClock = EV_NS_TO_TICK(&ts);

    /* Some events affect screen dimming */
    if (EventCodeMask(what) & NX_UNDIMMASK) {
        autoDimTime = ts;
        ADD_ABSOLUTETIME( &autoDimTime, &autoDimPeriod);
    	if (autoDimmed)
	    undoAutoDim();
    }
    // Update the PS VertRetraceClock off of the timestamp if it looks sane
    if (   theClock > (unsigned)evg->VertRetraceClock
	&& theClock < (unsigned)(evg->VertRetraceClock + (20 * EV_TICK_TIME)) )
	evg->VertRetraceClock = theClock;

    wereEvents = EventsInQueue();

    xpr_ev_post("postEvent: what %d, X %d Y %d Q %d, needKick %d\n",
		what,location->x,location->y,
		EventsInQueue(), needToKickEventConsumer);

    if ((!evg->dontCoalesce)	/* Coalescing enabled */
    && (theHead != theTail)
    && (theLast->event.type == what)
    && (EventCodeMask(what) & COALESCEEVENTMASK)
    && ev_try_lock(&theLast->sema)) {
    /* coalesce events */
	theLast->event.location.x = location->x;
	theLast->event.location.y = location->y;
        absolutetime_to_nanoseconds(ts, &theLast->event.time);
        if (myData != NULL)
	    theLast->event.data = *myData;
	ev_unlock(&theLast->sema);
    } else if (theTail->next != evg->LLEHead) {
	/* store event in tail */
	theTail->event.type = what;
	theTail->event.location.x = location->x;
	theTail->event.location.y = location->y;
	theTail->event.flags = evg->eventFlags;
        absolutetime_to_nanoseconds(ts, &theLast->event.time);
	theTail->event.window = 0;
	if (myData != NULL)
	    theTail->event.data = *myData;
	switch(what) {
	case NX_LMOUSEDOWN:
	    theTail->event.data.mouse.eventNum =
		leftENum = getUniqueEventNum();
	    break;
	case NX_RMOUSEDOWN:
	    theTail->event.data.mouse.eventNum =
		rightENum = getUniqueEventNum();
	    break;
	case NX_LMOUSEUP:
	    theTail->event.data.mouse.eventNum = leftENum;
	    leftENum = NULLEVENTNUM;
	    break;
	case NX_RMOUSEUP:
	    theTail->event.data.mouse.eventNum = rightENum;
	    rightENum = NULLEVENTNUM;
	    break;
	}
	if (EventCodeMask(what) & PRESSUREEVENTMASK) {
	    theTail->event.data.mouse.pressure = lastPressure;
	}
	if (EventCodeMask(what) & MOUSEEVENTMASK) { /* Click state */
            AbsoluteTime delta = ts;
            SUB_ABSOLUTETIME( &delta, &clickTime);
            if ((CMP_ABSOLUTETIME(&delta, &clickTimeThresh) <= 0)
	    && (myAbs(location->x - clickLoc.x) <= clickSpaceThresh.x)
	    && (myAbs(location->y - clickLoc.y) <= clickSpaceThresh.y)) {
                if ((what == NX_LMOUSEDOWN)||(what == NX_RMOUSEDOWN)) {
                    clickTime = ts;
                    theTail->event.data.mouse.click = ++clickState;
                } else {
                    theTail->event.data.mouse.click = clickState;
                }
	    } else if ((what == NX_LMOUSEDOWN)||(what == NX_RMOUSEDOWN)) {
		clickLoc = *location;
		clickTime = ts;
		clickState = 1;
		theTail->event.data.mouse.click = clickState;
	    } else
		theTail->event.data.mouse.click = 0;
	}
#if PMON
	pmon_log_event(PMON_SOURCE_EV,
		       KP_EV_POST_EVENT,
		       what,
		       evg->eventFlags,
		       theClock);
#endif
	evg->LLETail = theTail->next;
	evg->LLELast = theLast->next;
	if ( ! wereEvents )	// Events available, so wake event consumer
	    kickEventConsumer();
    }
    else
    {
	/*
	 * if queue is full, ignore event, too hard to take care of all cases 
	 */
	IOLog("%s: postEvent LLEventQueue overflow.\n", getName());
	kickEventConsumer();
#if PMON
	pmon_log_event( PMON_SOURCE_EV,
			KP_EV_QUEUE_FULL,
			what,
			evg->eventFlags,
			theClock);
#endif
    }
}

/*
 * - kickEventConsumer
 *
 * 	Try to send a message out to let the event consumer know that
 *	there are now events available for consumption.
 */

void IOHIDSystem::kickEventConsumer()
{ 
	IOReturn	err;

	IOTakeLock( kickConsumerLock);
	xpr_ev_post("kickEventConsumer (need == %d)\n",
		needToKickEventConsumer,2,3,4,5);
	if ( needToKickEventConsumer == true )
	{
		IOUnlock( kickConsumerLock);
		return;		// Request is already pending
	}
	needToKickEventConsumer = true;	// Posting a request now
	IOUnlock( kickConsumerLock);

        err = sendWorkLoopCommand(this, (IOHIDAction)_performKickEventConsumer,
                                  NULL);

	if( err)
	    IOLog("%s: cmdQ fail %d\n", getName(), err);
}

/* 
 * Event sources may need to use an I/O thread from time to time.
 * Rather than have each instance running it's own thread, we provide
 * a callback mechanism to let all the instances share a common Event I/O
 * thread running in the IOTask space, and managed by the Event Driver.
 */

IOReturn IOHIDSystem::sendWorkLoopCommand(OSObject *  target,
                                          IOHIDAction action,
                                          void *      data)
{
	kern_return_t err;

        err = cmdQ->enqueueCommand( /* sleep  */ true,
                                    /* field0 */ target,
                                    /* field1 */ (void *) action,
                                    /* field2 */ data );

	return (err == KERN_SUCCESS) ? kIOReturnSuccess : kIOReturnNoMemory;
}

/*
 * The following methods are executed from the I/O thread only.
 */

/*
 * This routine is run within the I/O thread, on demand from the
 * sendWorkLoopCommand method above.  We attempt to dispatch a message
 * to the specified selector and instance.
 */
void IOHIDSystem::_doPerformInIOThread(void* self,
				       void* target, /* IOCommandQueueAction */
                                       void* action,
                                       void* data,
                                       void* /* unused */)
{                                                    
  (*((IOHIDAction)action))((OSObject *)target, data);
}

/*
 * This is run in the I/O thread, to perform the actual message send operation.
 */

void IOHIDSystem::_performSpecialKeyMsg(IOHIDSystem * self,
					struct evioSpecialKeyMsg *msg)
                                                              /* IOHIDAction */
{
	kern_return_t r;

	xpr_ev_post("_performSpecialKeyMsg 0x%x\n", msg,2,3,4,5);


	/* FIXME: Don't block */
	r = mach_msg_send_from_kernel( &msg->Head, msg->Head.msgh_size);

	xpr_ev_post("_performSpecialKeyMsg: msg_send() == %d\n",r,2,3,4,5);
	if ( r != MACH_MSG_SUCCESS )
	{
		IOLog("%s: _performSpecialKeyMsg msg_send returned %d\n",
			self->getName(), r);
	}
	if ( r == MACH_SEND_INVALID_DEST )	/* Invalidate the port */
	{
		self->setSpecialKeyPort(
		  /* keyFlavor */ msg->key,
		  /* keyPort   */ MACH_PORT_NULL);
	}
	IOFree( (void *)msg, sizeof (struct evioSpecialKeyMsg) );
}

/*
 * This is run in the I/O thread, to perform the actual message send operation.
 * Note that we perform a non-blocking send.  The Event port in the event
 * consumer has a queue depth of 1 message.  Once the consumer picks up that
 * message, it runs until the event queue is exhausted before trying to read
 * another message.  If a message is pending,there is no need to enqueue a
 * second one.  This also keeps us from blocking the I/O thread in a msg_send
 * which could result in a deadlock if the consumer were to make a call into
 * the event driver.
 */
void IOHIDSystem::_performKickEventConsumer(IOHIDSystem * self, void *)  /* IOHIDAction */
{
	kern_return_t r;
	mach_msg_header_t *msgh

	xpr_ev_post("_performKickEventConsumer\n", 1,2,3,4,5);
	IOTakeLock( self->kickConsumerLock);
	self->needToKickEventConsumer = false;   // Request received and processed
	IOUnlock( self->kickConsumerLock);

	msgh = (mach_msg_header_t *)self->eventMsg;
	if( msgh) {

            r = mach_msg_send_from_kernel( msgh, msgh->msgh_size);
            switch ( r )
            {
                case MACH_SEND_TIMED_OUT:/* Already has a message posted */
                case MACH_MSG_SUCCESS:	/* Message is posted */
                    break;
                default:		/* Log the error */
                    IOLog("%s: _performKickEventConsumer msg_send returned %d\n",
				self->getName(), r);
                    break;
            }
	}
}

//
// Schedule the next periodic event to be run, based on the current state of
// the event system.  We have to consider things here such as when the last
// periodic event pass ran, if there is currently any mouse delta accumulated,
// and how long it has been since the last event was consumed by an app (for
// driving the wait cursor).
//
// This code should only be run from the periodicEvents method or
// _setCursorPosition.
//
void IOHIDSystem::scheduleNextPeriodicEvent()
{
    if (CMP_ABSOLUTETIME( &waitFrameTime, &thisPeriodicRun) > 0)
    {
	AbsoluteTime time_for_next_run;

        clock_get_uptime(&time_for_next_run);
        ADD_ABSOLUTETIME( &time_for_next_run, &periodicEventDelta);

        if (CMP_ABSOLUTETIME( &waitFrameTime, &time_for_next_run) < 0) {
            timerES->wakeAtTime(waitFrameTime);
            return;
        }
    }

    timerES->setTimeout(periodicEventDelta);
}

// Periodic events are driven from this method.
// After taking care of all pending work, the method
// calls scheduleNextPeriodicEvent to compute and set the
// next callout.
//

void IOHIDSystem::_periodicEvents(IOHIDSystem * self,
                                  IOTimerEventSource *timer)
{
    self->periodicEvents(timer);
}

void IOHIDSystem::periodicEvents(IOTimerEventSource * /* timer */)
                                /* IOTimerEventSource::Action, IOHIDAction */
{
	unsigned int	tick;

	// If eventsOpen is false, then the driver shmem is
	// no longer valid, and it is in the process of shutting down.
	// We should give up without rescheduling.
	IOTakeLock( driverLock);
	if ( eventsOpen == false )
	{
		IOUnlock( driverLock);
		return;
	}

	// Increment event time stamp last
        clock_get_uptime(&thisPeriodicRun);

	// Temporary hack til we wean CGS off of VertRetraceClock
	tick = EV_NS_TO_TICK(&thisPeriodicRun);
	if ( tick == 0 )
		tick = 1;
	evg->VertRetraceClock = tick;

	// Update cursor position if needed
	if ( needSetCursorPosition == true )
		_setCursorPosition(&pointerLoc, false);

	// WAITCURSOR ACTION
	if ( ev_try_lock(&evg->waitCursorSema) )
	{
	    if ( ev_try_lock(&evg->cursorSema) )
	    {
		// See if the current context has timed out
		if (   (evg->AALastEventSent != evg->AALastEventConsumed)
		    && ((evg->VertRetraceClock - evg->AALastEventSent >
					evg->waitThreshold)))
		    evg->ctxtTimedOut = TRUE;
		// If wait cursor enabled and context timed out, do waitcursor
		if (evg->waitCursorEnabled && evg->globalWaitCursorEnabled &&
		evg->ctxtTimedOut)
		{
		    /* WAIT CURSOR SHOULD BE ON */
		    if (!evg->waitCursorUp)
			showWaitCursor();
		} else
		{
		    /* WAIT CURSOR SHOULD BE OFF */
		    if (evg->waitCursorUp &&
			CMP_ABSOLUTETIME(&waitSusTime, &thisPeriodicRun) <= 0)
			hideWaitCursor();
		}
		/* Animate cursor */
		if (evg->waitCursorUp &&
			CMP_ABSOLUTETIME(&waitFrameTime, &thisPeriodicRun) <= 0)
			animateWaitCursor();
		ev_unlock(&evg->cursorSema);
		if ((CMP_ABSOLUTETIME(&thisPeriodicRun, &autoDimTime) > 0)
                    && (!autoDimmed))
		    doAutoDim();
	    }
	    ev_unlock(&evg->waitCursorSema);
	}

	scheduleNextPeriodicEvent();
	IOUnlock( driverLock);

	return;
}

//
// Start the cursor system running.
//
// At this point, the WindowServer is up, running, and ready to process events.
// We will attach the keyboard and mouse, if none are available yet.
//

bool IOHIDSystem::resetCursor()
{
    volatile Point * p;
    UInt32 newScreens = 0;
    SInt32 pinScreen = -1L;

    p = &evg->cursorLoc;

    /* Get mask of screens on which the cursor is present */
    EvScreen *screen = (EvScreen *)evScreen;
    for (int i = 0; i < screens; i++ ) {
        if ((screen[i].instance) && PtInRect(p, screen[i].bounds)) {
            pinScreen = i;
            newScreens |= (1 << i);
        }
    }

    if (newScreens == 0)
        pinScreen = 0;

    // reset pin rect
    cursorPin = *(((EvScreen*)evScreen)[pinScreen].bounds);
    cursorPin.maxx--;	/* Make half-open rectangle */
    cursorPin.maxy--;
    cursorPinScreen = pinScreen;
    
    if (newScreens == 0) {
        /* Pin new cursor position to cursorPin rect */
        p->x = (p->x < cursorPin.minx) ?
            cursorPin.minx : ((p->x > cursorPin.maxx) ?
            cursorPin.maxx : p->x);
        p->y = (p->y < cursorPin.miny) ?
            cursorPin.miny : ((p->y > cursorPin.maxy) ?
            cursorPin.maxy : p->y);

        /* regenerate mask for new position */
        for (int i = 0; i < screens; i++ ) {
            if ((screen[i].instance) && PtInRect(p, screen[i].bounds))
                newScreens |= (1 << i);
        }
    }

    cursorScreens = newScreens;

    pointerDelta.x += (evg->cursorLoc.x - pointerLoc.x);
    pointerDelta.y += (evg->cursorLoc.y - pointerLoc.y);
    pointerLoc.x = evg->cursorLoc.x;
    pointerLoc.y = evg->cursorLoc.y;

    return( true );
}

bool IOHIDSystem::startCursor()
{
    bool		ok;

    if (0 == screens)		// no screens, no cursor
        return( false );

    resetCursor();
    setBrightness();
    showCursor();

    // Start the cursor control callouts
    ok = (kIOReturnSuccess ==
	sendWorkLoopCommand(this, (IOHIDAction)_periodicEvents, timerES));

    cursorStarted = ok;
    return( ok );
}

//
// Wait Cursor machinery.  The driverLock should be held on entry to
// these methods, and the shared memory area must be set up.
//
void IOHIDSystem::showWaitCursor()
{
	xpr_ev_cursor("showWaitCursor\n",1,2,3,4,5);
	evg->waitCursorUp = true;
        hideCursor();
        evg->frame = EV_WAITCURSOR;
        showCursor();
	// Set animation and sustain absolute times.

	waitSusTime = waitFrameTime = thisPeriodicRun;
	ADD_ABSOLUTETIME( &waitFrameTime, &waitFrameRate);
	ADD_ABSOLUTETIME( &waitSusTime, &waitSustain);
}

void IOHIDSystem::hideWaitCursor()
{
	xpr_ev_cursor("hideWaitCursor\n",1,2,3,4,5);
	evg->waitCursorUp = false;
        hideCursor();
        evg->frame = EV_STD_CURSOR;
        showCursor();
        AbsoluteTime_to_scalar(&waitFrameTime) = 0;
        AbsoluteTime_to_scalar(&waitSusTime ) = 0;
}

void IOHIDSystem::animateWaitCursor()
{
	xpr_ev_cursor("animateWaitCursor\n",1,2,3,4,5);
	changeCursor(evg->frame + 1);
	// Set the next animation time.
	waitFrameTime = thisPeriodicRun;
	ADD_ABSOLUTETIME( &waitFrameTime, &waitFrameRate);
}

void IOHIDSystem::changeCursor(int frame)
{ 
	evg->frame =
		(frame > EV_MAXCURSOR) ? EV_WAITCURSOR : frame;
	xpr_ev_cursor("changeCursor %d\n",evg->frame,2,3,4,5);
	moveCursor();
}

//
// Return the screen number in which point p lies.  Return -1 if the point
// lies outside of all registered screens.
//
int IOHIDSystem::pointToScreen(Point * p)
{
    int i;
    EvScreen *screen = (EvScreen *)evScreen;
    for (i=screens; --i != -1; ) {
	if (screen[i].instance != 0
	&& (p->x >= screen[i].bounds->minx)
	&& (p->x < screen[i].bounds->maxx)
	&& (p->y >= screen[i].bounds->miny)
	&& (p->y < screen[i].bounds->maxy))
	    return i;
    }
    return(-1);	/* Cursor outside of known screen boundary */
}

//
// API used to manipulate screen brightness
//
// On entry to each of these, the driverLock should be set.
//
// Set the current brightness
void IOHIDSystem::setBrightness(int b)
{
	if ( b < EV_SCREEN_MIN_BRIGHTNESS )
		b = EV_SCREEN_MIN_BRIGHTNESS;
	else if ( b > EV_SCREEN_MAX_BRIGHTNESS )
		b = EV_SCREEN_MAX_BRIGHTNESS;
	if ( b != curBright )
	{
	    curBright = b;
	    if ( autoDimmed == false )
		setBrightness();
	}
}

int IOHIDSystem::brightness()
{
	return curBright;
}

// Set the current brightness
void IOHIDSystem::setAutoDimBrightness(int b)
{
	if ( b < EV_SCREEN_MIN_BRIGHTNESS )
		b = EV_SCREEN_MIN_BRIGHTNESS;
	else if ( b > EV_SCREEN_MAX_BRIGHTNESS )
		b = EV_SCREEN_MAX_BRIGHTNESS;
	if ( b != dimmedBrightness )
	{
	    dimmedBrightness = b;
	    if ( autoDimmed == true )
		setBrightness();
	}
}

int IOHIDSystem::autoDimBrightness()
{
	return dimmedBrightness;
}

int IOHIDSystem::currentBrightness()		// Return the current brightness
{
	if ( autoDimmed == true && dimmedBrightness < curBright )
		return dimmedBrightness;
	else
		return curBright;
}

void IOHIDSystem::doAutoDim()
{
	autoDimmed = true;
	setBrightness();
}

// Return display brightness to normal
void IOHIDSystem::undoAutoDim()
{
	autoDimmed = false;
	setBrightness();
}

void IOHIDSystem::forceAutoDimState(bool dim)
{
    	if ( dim == true )
	{
	    if ( autoDimmed == false )
	    {
		if ( eventsOpen == true )
                    clock_get_uptime( &autoDimTime);
		doAutoDim();
	    }
	}
	else
	{
	    if ( autoDimmed == true )
	    {
                if ( eventsOpen == true ) {
                    clock_get_uptime( &autoDimTime);
                    ADD_ABSOLUTETIME( &autoDimTime, &autoDimPeriod);
                }
		undoAutoDim();
	    }
	}
}

//
// API used to manipulate sound volume/attenuation
//
// Set the current brightness.
void IOHIDSystem::setAudioVolume(int v)
{
	if ( v < EV_AUDIO_MIN_VOLUME )
		v = EV_AUDIO_MIN_VOLUME;
	else if ( v > EV_AUDIO_MAX_VOLUME )
		v = EV_AUDIO_MAX_VOLUME;
	curVolume = v;
}

//
// Volume set programatically, rather than from keyboard
//
void IOHIDSystem::setUserAudioVolume(int v)
{
	setAudioVolume(v);
	// Let sound driver know about the change
	evSpecialKeyMsg(        NX_KEYTYPE_SOUND_UP,
		/* direction */ NX_KEYDOWN,
		/* flags */     0,
		/* level */     curVolume);
}

int IOHIDSystem::audioVolume()
{
	return curVolume;
}

//
// API used to drive event state out to attached screens
//
// On entry to each of these, the driverLock should be set.
//
inline void IOHIDSystem::setBrightness()      	// Propagate state out to screens
{
        evDispatch(/* command */ EVLEVEL);
}

inline void IOHIDSystem::showCursor()
{
        evDispatch(/* command */ EVSHOW);
}
inline void IOHIDSystem::hideCursor()
{
	evDispatch(/* command */ EVHIDE);
}

inline void IOHIDSystem::moveCursor()
{
	evDispatch(/* command */ EVMOVE);
}

//
// - attachDefaultEventSources
//	Attach the default event sources.
//
void IOHIDSystem::attachDefaultEventSources()
{
	OSObject  *     source;
	OSIterator * 	sources;


        sources = getProviderIterator();

        if (!sources)  return;

	while( (source = sources->getNextObject())) {
	    if (OSDynamicCast(IOHIDevice, source)) {

	       	registerEventSource((IOHIDevice *)source);
	   }
	}
        sources->release();
}

//
// - detachEventSources
//	Detach all event sources
//
void IOHIDSystem::detachEventSources()
{
	OSIterator * iter;
	IOHIDevice * srcInstance;

	iter = getOpenProviderIterator();
	if( iter) {
            while( (srcInstance = (IOHIDevice *) iter->getNextObject())) {
#ifdef DEBUG
                kprintf("detachEventSource:%s\n", srcInstance->getName());
#endif
                srcInstance->close(this);
	    }
	    iter->release();
	}
}

//
// EventSrcClient implementation
//

//
// A new device instance desires to be added to our list.
// Try to get ownership of the device. If we get it, add it to
// the list.
// 
bool IOHIDSystem::registerEventSource(IOHIDevice * source)
{
	bool success = false;

#ifdef DEBUG
        kprintf("registerEventSource:%s\n", ((IOHIDevice*)source)->getName());
#endif

	if ( OSDynamicCast(IOHIKeyboard, source) ) {
	    success = ((IOHIKeyboard*)source)->open(this, kIOServiceSeize,
                       (KeyboardEventAction)        _keyboardEvent, 
                       (KeyboardSpecialEventAction) _keyboardSpecialEvent,
                       (UpdateEventFlagsAction)     _updateEventFlags);
	} else if ( OSDynamicCast(IOHIPointing, source) ) {
	    success = ((IOHIPointing*)source)->open(this, kIOServiceSeize,
                       (RelativePointerEventAction) _relativePointerEvent,
                       (AbsolutePointerEventAction) _absolutePointerEvent,
                       (ScrollWheelEventAction)     _scrollWheelEvent);
	}

	if ( success == false )
            IOLog("%s: Seize of %s failed.\n", getName(), source->getName());

	return success;
}

IOReturn IOHIDSystem::message(UInt32 type, IOService * provider,
				void * argument)
{
  IOReturn     status = kIOReturnSuccess;

  switch (type)
  {
    case kIOMessageServiceIsTerminated:
#ifdef DEBUG
      kprintf("detachEventSource:%s\n", provider->getName());
#endif
      provider->close( this );
    case kIOMessageServiceWasClosed:
      break;

    default:
      status = super::message(type, provider, argument);
      break;
  }

  return status;
}

//
// This will scale the point at location in the coordinate system represented by bounds
// to the coordinate system of the current screen.
// This is needed for absolute pointer events that come from devices with different bounds.
//
void IOHIDSystem::_scaleLocationToCurrentScreen(Point *location, Bounds *bounds)
{
    // We probably also need to look at current screen offsets as well
    // but that shouldn't matter until we provide tablets with a way to
    // switch screens...
    location->x = ((location->x - bounds->minx) * (cursorPin.maxx - cursorPin.minx + 1)
                / (bounds->maxx - bounds->minx)) + cursorPin.minx;
    location->y = ((location->y - bounds->miny) * (cursorPin.maxy - cursorPin.miny + 1)
                / (bounds->maxy - bounds->miny)) + cursorPin.miny;

    return;
}


//
// Process a mouse status change.  The driver should sign extend
// it's deltas and perform any bit flipping needed there.
//
// We take the state as presented and turn it into events.
// 
void IOHIDSystem::_relativePointerEvent(IOHIDSystem * self,
				    int        buttons,
                       /* deltaX */ int        dx,
                       /* deltaY */ int        dy,
                       /* atTime */ AbsoluteTime ts)
{
	self->relativePointerEvent(buttons, dx, dy, ts);
}

void IOHIDSystem::relativePointerEvent(int        buttons,
                          /* deltaX */ int        dx,
                          /* deltaY */ int        dy,
                          /* atTime */ AbsoluteTime ts)
{
    AbsoluteTime nextVBL, vblDeltaTime, eventDeltaTime, moveDeltaTime;

    if( displayManager != NULL )		// if there is a display manager, tell
        displayManager->activityTickle(0,0);	// it there is user activity

    IOTakeLock( driverLock);
    if( eventsOpen == false )
    {
        IOUnlock( driverLock);
        return;
    }
    // Fake up pressure changes from button state changes
    if( (buttons & EV_LB) != (evg->buttons & EV_LB) )
    {
        if ( buttons & EV_LB )
            lastPressure = MAXPRESSURE;
        else
            lastPressure = MINPRESSURE;
    }
    _setButtonState(buttons, /* atTime */ ts);

    // figure cursor movement
    if( dx || dy )
    {
        eventDeltaTime = ts;
        SUB_ABSOLUTETIME( &eventDeltaTime, &lastEventTime );
        lastEventTime = ts;

        IOGraphicsDevice * instance = ((EvScreen*)evScreen)[cursorPinScreen].instance;
        if( instance)
            instance->getVBLTime( &nextVBL, &vblDeltaTime );
        else
            nextVBL.hi = nextVBL.lo = vblDeltaTime.hi = vblDeltaTime.lo = 0;

        if( dx && ((dx ^ accumDX) < 0))
            accumDX = 0;
        if( dy && ((dy ^ accumDY) < 0))
            accumDY = 0;

        KERNEL_DEBUG(0x0c000060 | DBG_FUNC_NONE,
            nextVBL.hi, nextVBL.lo, postedVBLTime.hi, postedVBLTime.lo, 0);

        if( (nextVBL.lo || nextVBL.hi)
            && (nextVBL.lo == postedVBLTime.lo) && (nextVBL.hi == postedVBLTime.hi))  {
            accumDX += dx;
            accumDY += dy;
            
        } else {
            SInt32 num = 0, div = 0;

            dx += accumDX;
            dy += accumDY;

            moveDeltaTime = ts;
            SUB_ABSOLUTETIME( &moveDeltaTime, &lastMoveTime );
            lastMoveTime = ts;

            if( (eventDeltaTime.lo < vblDeltaTime.lo) && (0 == eventDeltaTime.hi)
             && vblDeltaTime.lo && moveDeltaTime.lo) {
                num = vblDeltaTime.lo;
                div = moveDeltaTime.lo;
                dx = (num * dx) / div;
                dy = (num * dy) / div;
            }

            KERNEL_DEBUG(0x0c000000 | DBG_FUNC_NONE,
                dx, dy, num, div, 0);

            postedVBLTime = nextVBL;  			// we have posted for this vbl
            accumDX = accumDY = 0;

            if( dx || dy ) {
                pointerLoc.x += dx;
                pointerLoc.y += dy;
                pointerDelta.x += dx;
                pointerDelta.y += dy;
                _setCursorPosition(&pointerLoc, false);
            }
        }
    }
    IOUnlock( driverLock);
}

void IOHIDSystem::_absolutePointerEvent(IOHIDSystem * self,
				       int        buttons,
                 /* at */              Point *    newLoc,
                 /* withBounds */      Bounds *   bounds,
                 /* inProximity */     bool       proximity,
                 /* withPressure */    int        pressure,
                 /* withAngle */       int        stylusAngle,
                 /* atTime */          AbsoluteTime ts)
{
	self->absolutePointerEvent(buttons, newLoc, bounds, proximity,
					pressure, stylusAngle, ts);
}

void IOHIDSystem::absolutePointerEvent(int        buttons,
                    /* at */           Point *    newLoc,
                    /* withBounds */   Bounds *   bounds,
                    /* inProximity */  bool       proximity,
                    /* withPressure */ int        pressure,
                    /* withAngle */    int        /* stylusAngle */,
                    /* atTime */       AbsoluteTime ts)
		
{
  /*
   * If you don't know what to pass for the following fields, pass the
   * default values below:
   *    pressure    = MINPRESSURE or MAXPRESSURE
   *    stylusAngle = 90
   */

	NXEventData outData;	/* dummy data */

        if ( displayManager != NULL ) {			// if there is a display manager, tell
            displayManager->activityTickle(0,0);		// it there is user activity
        }

        IOTakeLock( driverLock);
	if ( eventsOpen == false )
	{
		IOUnlock( driverLock);
		return;
	}
	
	lastPressure = pressure;

        _scaleLocationToCurrentScreen(newLoc, bounds);
	if ( newLoc->x != pointerLoc.x || newLoc->y != pointerLoc.y )
	{
            pointerDelta.x += (newLoc->x - pointerLoc.x);
            pointerDelta.y += (newLoc->y - pointerLoc.y);
	    pointerLoc = *newLoc;
	    _setCursorPosition(&pointerLoc, false);
	}
	if ( lastProximity != proximity && proximity == true )
	{
	    evg->eventFlags |= NX_STYLUSPROXIMITYMASK;
	    bzero( (char *)&outData, sizeof outData );
	    postEvent(         NX_FLAGSCHANGED,
		/* at */       (Point *)&pointerLoc,
		/* atTime */   ts,
		/* withData */ &outData);
	}
	if ( proximity == true )
            _setButtonState(buttons, /* atTime */ ts);
	if ( lastProximity != proximity && proximity == false )
	{
	    evg->eventFlags &= ~NX_STYLUSPROXIMITYMASK;
	    bzero( (char *)&outData, sizeof outData );
	    postEvent(         NX_FLAGSCHANGED,
		/* at */       (Point *)&pointerLoc,
		/* atTime */   ts,
		/* withData */ &outData);
	}
	lastProximity = proximity;
	IOUnlock( driverLock);
}

void IOHIDSystem::_scrollWheelEvent(IOHIDSystem * self,
                                    short	deltaAxis1,
                                    short	deltaAxis2,
                                    short	deltaAxis3,
                 /* atTime */       AbsoluteTime ts)
{
        self->scrollWheelEvent(deltaAxis1, deltaAxis2, deltaAxis3, ts);
}

void IOHIDSystem::scrollWheelEvent(short	deltaAxis1,
                                   short	deltaAxis2,
                                   short	deltaAxis3,
                    /* atTime */   AbsoluteTime ts)

{
    NXEventData wheelData;

    if ((deltaAxis1 == 0) && (deltaAxis2 == 0) && (deltaAxis3 == 0)) {
        return;
    } 

    IOTakeLock( driverLock);
    if (!eventsOpen)
    {
            IOUnlock(driverLock);
            return;
    }

    bzero((char *)&wheelData, sizeof wheelData);
    wheelData.scrollWheel.deltaAxis1 = deltaAxis1;
    wheelData.scrollWheel.deltaAxis2 = deltaAxis2;
    wheelData.scrollWheel.deltaAxis3 = deltaAxis3;
    
    postEvent(             NX_SCROLLWHEELMOVED,
            /* at */       (Point *)&evg->cursorLoc,
            /* atTime */   ts,
            /* withData */ &wheelData);

    IOUnlock(driverLock);
    return;
}

void IOHIDSystem::_tabletEvent(IOHIDSystem *self,
                               NXEventData *tabletData,
                               AbsoluteTime ts)
{
    self->tabletEvent(tabletData, ts);
}

void IOHIDSystem::tabletEvent(NXEventData *tabletData,
                              AbsoluteTime ts)
{
    IOTakeLock(driverLock);
    
    if (eventsOpen) {
        postEvent(NX_TABLETPOINTER,
                  (Point *)&evg->cursorLoc,
                  ts,
                  tabletData);
    }

    IOUnlock(driverLock);

    return;
}

void IOHIDSystem::_proximityEvent(IOHIDSystem *self,
                                  NXEventData *proximityData,
                                  AbsoluteTime ts)
{
    self->proximityEvent(proximityData, ts);
}

void IOHIDSystem::proximityEvent(NXEventData *proximityData,
                                 AbsoluteTime ts)
{
    IOTakeLock(driverLock);

    if (eventsOpen) {
        postEvent(NX_TABLETPROXIMITY,
                  (Point *)&evg->cursorLoc,
                  ts,
                  proximityData);
    }

    IOUnlock(driverLock);

    return;
}

//
// Process a keyboard state change.
// 
void IOHIDSystem::_keyboardEvent(IOHIDSystem * self,
				unsigned   eventType,
         /* flags */            unsigned   flags,
         /* keyCode */          unsigned   key,
         /* charCode */         unsigned   charCode,
         /* charSet */          unsigned   charSet,
         /* originalCharCode */ unsigned   origCharCode,
         /* originalCharSet */  unsigned   origCharSet,
         /* keyboardType */ 	unsigned   keyboardType,
         /* repeat */           bool       repeat,
         /* atTime */           AbsoluteTime ts)
{
	self->keyboardEvent(eventType, flags, key, charCode, charSet,
				origCharCode, origCharSet, keyboardType, repeat, ts);
}

void IOHIDSystem::keyboardEvent(unsigned   eventType,
         /* flags */            unsigned   flags,
         /* keyCode */          unsigned   key,
         /* charCode */         unsigned   charCode,
         /* charSet */          unsigned   charSet,
         /* originalCharCode */ unsigned   origCharCode,
         /* originalCharSet */  unsigned   origCharSet,
         /* keyboardType */ 	unsigned   keyboardType,
         /* repeat */           bool       repeat,
         /* atTime */           AbsoluteTime ts)
{
	NXEventData	outData;
                
        if ( ! (displayState & IOPMDeviceUsable) ) {	// display is off, consume the keystroke
            if ( eventType == NX_KEYDOWN ) {
                return;
            }
            if ( displayManager != NULL ) {			// but if there is a display manager, tell
                displayManager->activityTickle(0,0);		// it there is user activity
            }
            return;
        }
        
        if ( displayManager != NULL ) {			// if there is a display manager, tell
            displayManager->activityTickle(0,0);		// it there is user activity
        }
        
        outData.key.repeat = repeat;
	outData.key.keyCode = key;
	outData.key.charSet = charSet;
	outData.key.charCode = charCode;
	outData.key.origCharSet = origCharSet;
	outData.key.origCharCode = origCharCode;
	outData.key.keyboardType = keyboardType;

	IOTakeLock( driverLock);
	if ( eventsOpen == false )
	{
		IOUnlock( driverLock);
		return;
	}
	evg->eventFlags = (evg->eventFlags & ~KEYBOARD_FLAGSMASK)
			| (flags & KEYBOARD_FLAGSMASK);

	postEvent(             eventType,
		/* at */       (Point *)&pointerLoc,
		/* atTime */   ts,
		/* withData */ &outData);

	IOUnlock( driverLock);
}

void IOHIDSystem::_keyboardSpecialEvent(  IOHIDSystem * self,
					  unsigned   eventType,
                       /* flags */     	  unsigned   flags,
                       /* keyCode  */  	  unsigned   key,
                       /* specialty */ 	  unsigned   flavor,
                       /* guid */         UInt64     guid,
                       /* repeat */       bool       repeat,
                       /* atTime */    	  AbsoluteTime ts)
{
	self->keyboardSpecialEvent(eventType, flags, key, flavor, guid, repeat, ts);
}


void IOHIDSystem::keyboardSpecialEvent(   unsigned   eventType,
                       /* flags */        unsigned   flags,
                       /* keyCode  */     unsigned   key,
                       /* specialty */    unsigned   flavor,
                       /* guid */         UInt64     guid,
                       /* repeat */       bool       repeat,
                       /* atTime */       AbsoluteTime ts)
{
	NXEventData	outData;
	int		level = -1;

	bzero( (void *)&outData, sizeof outData );

	IOTakeLock( driverLock);
	if ( eventsOpen == false )
	{
		IOUnlock( driverLock);
		return;
	}
		
	// Update flags.
	evg->eventFlags = (evg->eventFlags & ~KEYBOARD_FLAGSMASK)
			| (flags & KEYBOARD_FLAGSMASK);

	if ( eventType == NX_KEYDOWN )
	{
		switch ( flavor )
		{
			case NX_KEYTYPE_SOUND_UP:
				if ( (flags & SPECIALKEYS_MODIFIER_MASK) == 0 )
				{
					//level = IOAudioManager::sharedInstance()->incrementMasterVolume();
					if (masterAudioFunctions && masterAudioFunctions->incrementMasterVolume)
					{
						masterAudioFunctions->incrementMasterVolume();
					}
				}
				else
				{
					if( !(evg->eventFlags & NX_COMMANDMASK) 	&&
						!(evg->eventFlags & NX_CONTROLMASK) 	&& 
						!(evg->eventFlags & NX_SHIFTMASK)		&& 
						 (evg->eventFlags & NX_ALTERNATEMASK)		)
					{
						// Open the sound preferences control panel.
						KUNCExecute( "Sound.preference", kOpenAppAsConsoleUser, kOpenPreferencePanel );
					}
				}
			    break;
			case NX_KEYTYPE_SOUND_DOWN:
				if ( (flags & SPECIALKEYS_MODIFIER_MASK) == 0 )
				{
					//level = IOAudioManager::sharedInstance()->decrementMasterVolume();
					if (masterAudioFunctions && masterAudioFunctions->decrementMasterVolume)
					{
						masterAudioFunctions->decrementMasterVolume();
					}
				}
				else
				{
					if( !(evg->eventFlags & NX_COMMANDMASK) 	&&
						!(evg->eventFlags & NX_CONTROLMASK) 	&& 
						!(evg->eventFlags & NX_SHIFTMASK)		&& 
						 (evg->eventFlags & NX_ALTERNATEMASK)		)
					{
						// Open the sound preferences control panel.
						KUNCExecute( "Sound.preference", kOpenAppAsConsoleUser, kOpenPreferencePanel );
					}
				}
			    break;
			case NX_KEYTYPE_MUTE:
				if ( (flags & SPECIALKEYS_MODIFIER_MASK) == 0 )
				{
					//level = IOAudioManager::sharedInstance()->toggleMasterMute();
					if (masterAudioFunctions && masterAudioFunctions->toggleMasterMute)
					{
						masterAudioFunctions->toggleMasterMute();
					}
				}
				else
				{
					if( !(evg->eventFlags & NX_COMMANDMASK) 	&&
						!(evg->eventFlags & NX_CONTROLMASK) 	&& 
						!(evg->eventFlags & NX_SHIFTMASK)		&& 
						 (evg->eventFlags & NX_ALTERNATEMASK)		)
					{
						// Open the sound preferences control panel.
						KUNCExecute( "Sound.preference", kOpenAppAsConsoleUser, kOpenPreferencePanel );
					}
				}
				break;
			case NX_KEYTYPE_EJECT:
							
				//	Special key handlers:
				//
				//	Command = invoke macsbug
				//	Command+option = sleep now
				//	Command+option+control = shutdown now
				//	Control = logout dialog
				
				if(  (evg->eventFlags & NX_COMMANDMASK) 	&&
					!(evg->eventFlags & NX_CONTROLMASK) 	&& 
					!(evg->eventFlags & NX_SHIFTMASK)		&& 
					!(evg->eventFlags & NX_ALTERNATEMASK)		)
				{
					// Post a power key event, Classic should pick this up and
					// drop into MacsBug.
					//
					outData.compound.subType = NX_SUBTYPE_POWER_KEY;
					postEvent(	   NX_SYSDEFINED,
					/* at */       (Point *)&pointerLoc,
					/* atTime */   ts,
					/* withData */ &outData);
				}
				else if(   (evg->eventFlags & NX_COMMANDMASK) 	&&
						  !(evg->eventFlags & NX_CONTROLMASK) 	&& 
						  !(evg->eventFlags & NX_SHIFTMASK)		&& 
						   (evg->eventFlags & NX_ALTERNATEMASK)		)
				{					
					//IOLog( "IOHIDSystem -- sleep now!\n" );

					// Post the sleep now event. Someone else will handle the actual call.
					//
					outData.compound.subType = NX_SUBTYPE_SLEEP_EVENT;
					postEvent(	   NX_SYSDEFINED,
					/* at */       (Point *)&pointerLoc,
					/* atTime */   ts,
					/* withData */ &outData);
				}
				else if(   (evg->eventFlags & NX_COMMANDMASK) 	&&
						   (evg->eventFlags & NX_CONTROLMASK) 	&& 
						  !(evg->eventFlags & NX_SHIFTMASK)		&& 
						   (evg->eventFlags & NX_ALTERNATEMASK)		)
				{					
					//IOLog( "IOHIDSystem -- shutdown now!\n" );

					// Post the shutdown now event. Someone else will handle the actual call.
					//
					outData.compound.subType = NX_SUBTYPE_SHUTDOWN_EVENT;
					postEvent(	   NX_SYSDEFINED,
					/* at */       (Point *)&pointerLoc,
					/* atTime */   ts,
					/* withData */ &outData);
				}
				else if(   (evg->eventFlags & NX_COMMANDMASK) 	&&
						   (evg->eventFlags & NX_CONTROLMASK) 	&& 
						  !(evg->eventFlags & NX_SHIFTMASK)		&& 
						  !(evg->eventFlags & NX_ALTERNATEMASK)		)
				{
					// Restart now!
					//IOLog( "IOHIDSystem -- Restart now!\n" );
					
					// Post the Restart now event. Someone else will handle the actual call.
					//
					outData.compound.subType = NX_SUBTYPE_RESTART_EVENT;
					postEvent(	   NX_SYSDEFINED,
					/* at */       (Point *)&pointerLoc,
					/* atTime */   ts,
					/* withData */ &outData);
				}
				else if(  !(evg->eventFlags & NX_COMMANDMASK) 	&&
						   (evg->eventFlags & NX_CONTROLMASK) 	&& 
						  !(evg->eventFlags & NX_SHIFTMASK)		&& 
						  !(evg->eventFlags & NX_ALTERNATEMASK)		)
				{
					// Looks like we should put up the normal 'Power Key' dialog.
					//					
					// Set the event flags to zero, because the system will not do the right
					// thing if we don't zero this out (it will ignore the power key event
					// we post, thinking that some modifiers are down).
					//
					evg->eventFlags = 0;
					
					// Post the power keydown event.
					//
					outData.compound.subType = NX_SUBTYPE_POWER_KEY;
					postEvent(	   NX_SYSDEFINED,
					/* at */       (Point *)&pointerLoc,
					/* atTime */   ts,
					/* withData */ &outData);
				}
				else
				{
					// After all that checking, no modifiers are down, so let's pump up a
					// system defined eject event. This way we can have anyone who's watching
					// for this event (aka LoginWindow) route this event to the right target
					// (aka AutoDiskMounter).
					
					//IOLog( "IOHIDSystem--Normal Eject action!\n" );

					// Post the eject keydown event.
					//
					outData.compound.subType = NX_SUBTYPE_EJECT_KEY;
					postEvent(	   NX_SYSDEFINED,
					/* at */       (Point *)&pointerLoc,
					/* atTime */   ts,
					/* withData */ &outData);
				}
				break;

			case NX_POWER_KEY:
				outData.compound.subType = NX_SUBTYPE_POWER_KEY;
				postEvent(         NX_SYSDEFINED,
					/* at */       (Point *)&pointerLoc,
					/* atTime */   ts,
					/* withData */ &outData);
				break;
		}
	}
#if 0	/* So far, nothing to do on keyup */
	else if ( eventType == NX_KEYUP )
	{
		switch ( flavor )
		{
			case NX_KEYTYPE_SOUND_UP:
				break;
			case NX_KEYTYPE_SOUND_DOWN:
				break;
			case NX_KEYTYPE_MUTE:
				break;
			case NX_POWER_KEY:
				break;
		}
	}
#endif
        if( (0 == (flags & SPECIALKEYS_MODIFIER_MASK))
          && ((1 << flavor) & NX_SPECIALKEY_POST_MASK)) {
            outData.compound.subType   = NX_SUBTYPE_AUX_CONTROL_BUTTONS;
            outData.compound.misc.S[0] = flavor;
            outData.compound.misc.C[2] = eventType;
            outData.compound.misc.C[3] = repeat;
            outData.compound.misc.L[1] = guid & 0xffffffff;
            outData.compound.misc.L[2] = guid >> 32;
    
            postEvent(             NX_SYSDEFINED,
                    /* at */       (Point *)&pointerLoc,
                    /* atTime */   ts,
                    /* withData */ &outData);
        }

	IOUnlock( driverLock);
	if ( level != -1 )	// An interesting special key event occurred
	{
		evSpecialKeyMsg(        flavor,
			/* direction */ eventType,
			/* flags */     flags,
			/* level */     level);
	}
}

/*
 * Update current event flags.  Restricted to keyboard flags only, this
 * method is used to silently update the flags state for keys which both
 * generate characters and flag changes.  The specs say we don't generate
 * a flags-changed event for such keys.  This method is also used to clear
 * the keyboard flags on a keyboard subsystem reset.
 */
void IOHIDSystem::_updateEventFlags(IOHIDSystem * self, unsigned flags)
{
    self->updateEventFlags(flags);
}

void IOHIDSystem::updateEventFlags(unsigned flags)
{
	IOTakeLock( driverLock);
	if ( eventsOpen )
	    evg->eventFlags = (evg->eventFlags & ~KEYBOARD_FLAGSMASK)
			    | (flags & KEYBOARD_FLAGSMASK);
	IOUnlock( driverLock);
}

//
// - _setButtonState:(int)buttons  atTime:(int)t
//	Update the button state.  Generate button events as needed
//
void IOHIDSystem::_setButtonState(int buttons,
                                  /* atTime */ AbsoluteTime ts)
{
	// Magic uber-mouse buttons changed event so we can get all of the buttons...
	if(evg->buttons ^ buttons)
	{
	    NXEventData evData;
	    unsigned long hwButtons, hwDelta, temp;
     	
	    /* I'd like to keep the event button mapping linear, so
	       I have to "undo" the LB/RB mouse bit numbering funkiness
	       before I pass the information down to the app. */
	    /* Ideally this would all go away if we fixed EV_LB and EV_RB
	       to be bits 0 and 1 */
	    hwButtons = buttons & ~7; /* Keep everything but bottom 3 bits. */
	    hwButtons |= (buttons & 3) << 1;  /* Map bits 01 to 12 */
	    hwButtons |= (buttons & 4) >> 2;  /* Map bit 2 back to bit 0 */
            temp = evg->buttons ^ buttons;
	    hwDelta = temp & ~7;
	    hwDelta |= (temp & 3) << 1; /* Map bits 01 to 12 */
	    hwDelta |= (temp & 4) >> 2; /* Map bit 2 back to bit 0 */

	    evData.compound.reserved = 0;
	    evData.compound.subType = NX_SUBTYPE_AUX_MOUSE_BUTTONS;
            evData.compound.misc.L[0] = hwDelta;
	    evData.compound.misc.L[1] = hwButtons;
	
	    postEvent(		NX_SYSDEFINED, 
		/* at */	(Point *)&evg->cursorLoc,
		/* atTime */	ts,
		/* withData */	&evData);
	}
	
	if ((evg->buttons & EV_LB) != (buttons & EV_LB))
	{
	    if (buttons & EV_LB)
	    {
		postEvent(             NX_LMOUSEDOWN,
			/* at */       (Point *)&evg->cursorLoc,
			/* atTime */   ts,
			/* withData */ NULL);
	    }
	    else
	    {
		postEvent(             NX_LMOUSEUP,
			/* at */       (Point *)&evg->cursorLoc,
			/* atTime */   ts,
			/* withData */ NULL);
	    }
	    // After entering initial up/down event, set up
	    // coalescing state so drags will behave correctly
	    evg->dontCoalesce = evg->dontWantCoalesce;
	    if (evg->dontCoalesce)
		evg->eventFlags |= NX_NONCOALSESCEDMASK;
	    else
		evg->eventFlags &= ~NX_NONCOALSESCEDMASK;
	}
    
	if ((evg->buttons & EV_RB) != (buttons & EV_RB)) {
	    if (buttons & EV_RB) {
		postEvent(             NX_RMOUSEDOWN,
			/* at */       (Point *)&evg->cursorLoc,
			/* atTime */   ts,
			/* withData */ NULL);
	    } else {
		postEvent(             NX_RMOUSEUP,
			/* at */       (Point *)&evg->cursorLoc,
			/* atTime */   ts,
			/* withData */ NULL);
	    }
	}

	evg->buttons = buttons;
}
//
//  Sets the cursor position (evg->cursorLoc) to the new
//  location.  The location is clipped against the cursor pin rectangle,
//  mouse moved/dragged events are generated using the given event mask,
//  and a mouse-exited event may be generated. The cursor image is
//  moved.
//  On entry, the driverLock should be set.
//
void IOHIDSystem::setCursorPosition(Point * newLoc, bool external)
{
	if ( eventsOpen == true )
	{
            pointerDelta.x += (newLoc->x - pointerLoc.x);
            pointerDelta.y += (newLoc->y - pointerLoc.y);
	    pointerLoc = *newLoc;
	    _setCursorPosition(newLoc, external);
	}
}

//
// This mechanism is used to update the cursor position, possibly generating
// messages to registered frame buffer devices and posting drag, tracking, and
// mouse motion events.
//
// On entry, the driverLock should be set.
// This can be called from setCursorPosition:(Point *)newLoc to set the
// position by a _IOSetParameterFromIntArray() call, directly from the absolute or
// relative pointer device routines, or on a timed event callback.
//
void IOHIDSystem::_setCursorPosition(Point * newLoc, bool external)
{
        bool cursorMoved = true;
    
	if (!screens)
	    return;

	if( ev_try_lock(&evg->cursorSema) == 0 ) // host using shmem
	{
		needSetCursorPosition = true;	  // try again later
//		scheduleNextPeriodicEvent();
		return;
	}

	// Past here we hold the cursorSema lock.  Make sure the lock is
	// cleared before returning or the system will be wedged.
	
	needSetCursorPosition = false;	  // We WILL succeed

        if (cursorCoupled || external)
        {
            UInt32 newScreens = 0;
            SInt32 pinScreen = -1L;

            /* Get mask of screens on which the cursor is present */
            EvScreen *screen = (EvScreen *)evScreen;
            for (int i = 0; i < screens; i++ ) {
                if ((screen[i].instance) && PtInRect(newLoc, screen[i].bounds)) {
                    pinScreen = i;
                    newScreens |= (1 << i);
                }
            }
        
            if (newScreens == 0) {
                /* At this point cursor has gone off all screens,
                   just clip it to one of the previous screens. */
                newLoc->x = (newLoc->x < cursorPin.minx) ?
                    cursorPin.minx : ((newLoc->x > cursorPin.maxx) ?
                    cursorPin.maxx : newLoc->x);
                newLoc->y = (newLoc->y < cursorPin.miny) ?
                    cursorPin.miny : ((newLoc->y > cursorPin.maxy) ?
                    cursorPin.maxy : newLoc->y);
                /* regenerate mask for new position */
                for (int i = 0; i < screens; i++ ) {
                    if ((screen[i].instance) && PtInRect(newLoc, screen[i].bounds)) {
                        pinScreen = i;
                        newScreens |= (1 << i);
                    }
                }
            }
    
            pointerLoc = *newLoc;	// Sync up pointer with clipped cursor
            /* Catch the no-move case */
            if ((evg->cursorLoc.x == newLoc->x) && (evg->cursorLoc.y == newLoc->y)) {
                if ((pointerDelta.x == 0) && (pointerDelta.y == 0)) {
                    ev_unlock(&evg->cursorSema);
                    return;
                }
                cursorMoved = false;	// mouse moved, but cursor didn't
            } else {
                evg->cursorLoc.x = newLoc->x;
                evg->cursorLoc.y = newLoc->y;
    
                /* If cursor changed screens */
                if (newScreens != cursorScreens) {
                    hideCursor();	/* hide cursor on old screens */
                    cursorScreens = newScreens;
                    cursorPin = *(((EvScreen*)evScreen)[pinScreen].bounds);
                    cursorPin.maxx--;	/* Make half-open rectangle */
                    cursorPin.maxy--;
                    cursorPinScreen = pinScreen;
                    showCursor();
                } else {
                    /* cursor moved on same screens */
                    moveCursor();
                }
            }
        } else {
            /* cursor uncoupled */
            pointerLoc.x = evg->cursorLoc.x;
            pointerLoc.y = evg->cursorLoc.y;
        }

        AbsoluteTime	ts;
        clock_get_uptime(&ts);
        
	/* See if anybody wants the mouse moved or dragged events */
	if (evg->movedMask) {
            if ((evg->movedMask&NX_LMOUSEDRAGGEDMASK)&&(evg->buttons& EV_LB)) {
                _postMouseMoveEvent(NX_LMOUSEDRAGGED, newLoc, ts);
            } else if ((evg->movedMask&NX_RMOUSEDRAGGEDMASK) && (evg->buttons & EV_RB)) {
                _postMouseMoveEvent(NX_RMOUSEDRAGGED, newLoc, ts);
            } else if (evg->movedMask & NX_MOUSEMOVEDMASK) {
                _postMouseMoveEvent(NX_MOUSEMOVED, newLoc, ts);
            }
	}
    
	/* check new cursor position for leaving evg->mouseRect */
	if (cursorMoved && evg->mouseRectValid && (!PtInRect(newLoc, &evg->mouseRect)))
	{
	    if (evg->mouseRectValid)
	    {
		postEvent(             NX_MOUSEEXITED,
			/* at */       newLoc,
			/* atTime */   ts,
			/* withData */ NULL);
		evg->mouseRectValid = 0;
	    }
	}
	ev_unlock(&evg->cursorSema);
}

void IOHIDSystem::_postMouseMoveEvent(int          what,
                                     Point *       location,
                                     AbsoluteTime  ts)
{
    NXEventData data;

    data.mouseMove.dx = pointerDelta.x;
    data.mouseMove.dy = pointerDelta.y;

    pointerDelta.x = 0;
    pointerDelta.y = 0;

    postEvent(what, location, ts, &data);
}

/**
 ** IOUserClient methods
 **/

IOReturn IOHIDSystem::newUserClient(task_t         /* owningTask */,
                    /* withToken */ void *         /* security_id */,
                    /* ofType */    UInt32         type,
                    /* client */    IOUserClient ** handler)
{
    IOUserClient *	newConnect = 0;
    IOReturn		err = kIOReturnNoMemory;

    IOTakeLock( driverLock);

    do {
       if( type == kIOHIDParamConnectType) {
            if( paramConnect) {
                newConnect = paramConnect;
                newConnect->retain();
            } else if( eventsOpen) {
                newConnect = new IOHIDParamUserClient;
            } else {
                err = kIOReturnNotOpen;
		continue;
	    }

        } else if( type == kIOHIDServerConnectType) {
            newConnect = new IOHIDUserClient;
	} else
	    err = kIOReturnUnsupported;

        if( !newConnect)
            continue;

        // initialization is getting out of hand

        if( (newConnect != paramConnect) && (
           (false == newConnect->init())
        || (false == newConnect->attach( this ))
        || (false == newConnect->start( this ))
        || ((type == kIOHIDServerConnectType)
                && (err = evOpen()))
        )) {
            newConnect->detach( this );
            newConnect->release();
            newConnect = 0;
	    continue;
        }
        if( type == kIOHIDParamConnectType)
            paramConnect = newConnect;
	err = kIOReturnSuccess;

    } while( false );

    IOUnlock( driverLock);

    *handler = newConnect;
    return( err );
}


IOReturn IOHIDSystem::setEventsEnable(void*p1,void*,void*,void*,void*,void*)
{                                                                    // IOMethod
    bool enable = (bool)p1;

    if( enable) {
        attachDefaultEventSources();
        _resetMouseParameters();
        _resetKeyboardParameters();
    }
    return( kIOReturnSuccess);
}

IOReturn IOHIDSystem::setCursorEnable(void*p1,void*,void*,void*,void*,void*)
{                                                                    // IOMethod
    bool 		enable = (bool)p1;
    IOReturn		err = kIOReturnSuccess;

    IOTakeLock( driverLock);
    if ( eventsOpen == false ) {
        IOUnlock( driverLock);
        return( kIOReturnNotOpen );
    }

    if( 0 == screens) {		// Should be at least 1!
        IOUnlock( driverLock);
        return( kIOReturnNoDevice );
    }

    if( enable) {
	if( cursorStarted) {
            hideCursor();
            cursorEnabled = resetCursor();
            showCursor();
	} else
            cursorEnabled = startCursor();
    } else
        cursorEnabled = enable;

    cursorCoupled = cursorEnabled;
    
    IOUnlock( driverLock);

    return( err);
}

IOReturn IOHIDSystem::extPostEvent(void*p1,void*,void*,void*,void*,void*)
{                                                                    // IOMethod
    struct evioLLEvent * event = (struct evioLLEvent *)p1;

    IOTakeLock( driverLock);

    if( event->setCursor)
        setCursorPosition(&event->location, true);

    if( event->setFlags)
        evg->eventFlags = (evg->eventFlags & ~KEYBOARD_FLAGSMASK)
                        | (event->flags & KEYBOARD_FLAGSMASK);

    AbsoluteTime	ts;
    clock_get_uptime(&ts);
    postEvent(             event->type,
            /* at */       &event->location,
            /* atTime */   ts,
            /* withData */ &event->data);

    IOUnlock( driverLock);
    return( kIOReturnSuccess);
}

IOReturn IOHIDSystem::extSetMouseLocation(void*p1,void*,void*,void*,void*,void*)
{                                                                    // IOMethod
    Point * loc = (Point *)p1;

    IOTakeLock( driverLock);
    setCursorPosition(loc, true);
    IOUnlock( driverLock);
    return( kIOReturnSuccess);
}

IOReturn IOHIDSystem::extGetButtonEventNum(void*p1,void*p2,void*,void*,void*,void*)
{                                                                    // IOMethod
    NXMouseButton button   = (NXMouseButton)(int)p1;
    int *         eventNum = (int *)p2;
    IOReturn      err      = kIOReturnSuccess;

    IOTakeLock( driverLock);
    switch( button) {
	case NX_LeftButton:
            *eventNum = leftENum;
	    break;
	case NX_RightButton:
            *eventNum = rightENum;
	    break;
	default:
	    err = kIOReturnBadArgument;
    }

    IOUnlock( driverLock);
    return( err);
}

bool IOHIDSystem::updateProperties( void )
{
    UInt64		clickTimeThreshNano;
    UInt64		autoDimThresholdNano;
    UInt64		autoDimTimeNano;
    UInt64		idleTimeNano;
    AbsoluteTime	time1, time2;
    bool 		ok;

    absolutetime_to_nanoseconds( clickTimeThresh, &clickTimeThreshNano);
    absolutetime_to_nanoseconds( autoDimPeriod, &autoDimThresholdNano);
    if( eventsOpen) {
        clock_get_uptime( &time1);
        if( autoDimmed) {
            autoDimTimeNano = 0;
            // now - (autoDimTime - autoDimPeriod)
            SUB_ABSOLUTETIME( &time1, &autoDimTime);
            ADD_ABSOLUTETIME( &time1, &autoDimPeriod);
            absolutetime_to_nanoseconds( time1, &idleTimeNano);
        } else {
            // autoDimTime - now
            time2 = autoDimTime;
            SUB_ABSOLUTETIME( &time2, &time1);
            absolutetime_to_nanoseconds( time2, &autoDimTimeNano);
            // autoDimPeriod - (autoDimTime - evg->VertRetraceClock)
            time1 = autoDimPeriod;
            SUB_ABSOLUTETIME( &time1, &time2);
            absolutetime_to_nanoseconds( time1, &idleTimeNano);
	}
    } else {
        absolutetime_to_nanoseconds( autoDimPeriod, &autoDimTimeNano);
        idleTimeNano = 0;	 // user is active
    }

    ok = setProperty( kIOHIDClickTimeKey, &clickTimeThreshNano,
                sizeof( UInt64))
    &    setProperty( kIOHIDClickSpaceKey, &clickSpaceThresh,
                      sizeof( clickSpaceThresh))
    &    setProperty( kIOHIDAutoDimThresholdKey, &autoDimThresholdNano,
                      sizeof( UInt64))
    &    setProperty( kIOHIDAutoDimTimeKey, &autoDimTimeNano,
                      sizeof( UInt64))
    &    setProperty( kIOHIDIdleTimeKey, &idleTimeNano,
                      sizeof( UInt64))
    &    setProperty( kIOHIDAutoDimStateKey, &autoDimmed,
                      sizeof( autoDimmed))
    &    setProperty( kIOHIDBrightnessKey, &curBright,
                      sizeof( curBright))
    &    setProperty( kIOHIDAutoDimBrightnessKey, &dimmedBrightness,
                      sizeof( dimmedBrightness));

    return( ok );
}

bool IOHIDSystem::serializeProperties( OSSerialize * s ) const
{
    ((IOHIDSystem *) this)->updateProperties();

    return( super::serializeProperties( s ));
}

IOReturn IOHIDSystem::setParamProperties( OSDictionary * dict )
{
    OSData *	data;
    IOReturn	err = kIOReturnSuccess;

    IOTakeLock( driverLock);
    if( (data = OSDynamicCast( OSData, dict->getObject(kIOHIDClickTimeKey))))
    {
        UInt64		nano = *((UInt64 *)(data->getBytesNoCopy()));
        nanoseconds_to_absolutetime(nano, &clickTimeThresh);
    }
    if( (data = OSDynamicCast( OSData,
		dict->getObject(kIOHIDClickSpaceKey)))) {
        clickSpaceThresh.x = ((UInt32 *) (data->getBytesNoCopy()))[EVSIOSCS_X];
        clickSpaceThresh.y = ((UInt32 *) (data->getBytesNoCopy()))[EVSIOSCS_Y];
    }

    if( (data = OSDynamicCast( OSData, dict->getObject(kIOHIDAutoDimThresholdKey)))) {
        AbsoluteTime 	oldPeriod = autoDimPeriod;
        UInt64		nano = *((UInt64 *)(data->getBytesNoCopy()));
        nanoseconds_to_absolutetime(nano, &autoDimPeriod);
        // autoDimTime = autoDimTime - oldPeriod + autoDimPeriod;
        SUB_ABSOLUTETIME( &autoDimTime, &oldPeriod);
        ADD_ABSOLUTETIME( &autoDimTime, &autoDimPeriod);
    }

    if( (data = OSDynamicCast( OSData, dict->getObject(kIOHIDAutoDimStateKey))))
        forceAutoDimState( 0 != *((SInt32 *) (data->getBytesNoCopy())));

    if( (data = OSDynamicCast( OSData, dict->getObject(kIOHIDBrightnessKey))))
        setBrightness( *((SInt32 *) (data->getBytesNoCopy())));

    if( (data = OSDynamicCast( OSData, dict->getObject(kIOHIDAutoDimBrightnessKey))))
        setAutoDimBrightness( *((SInt32 *) (data->getBytesNoCopy())));

    IOUnlock( driverLock);

    return( err );
}

