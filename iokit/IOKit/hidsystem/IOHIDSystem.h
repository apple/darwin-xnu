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
 * EventDriver.h - Exported Interface Event Driver object.
 *
 *		The EventDriver is a pseudo-device driver.
 *
 * HISTORY
 * 19 Mar 1992    Mike Paquette at NeXT
 *      Created. 
 * 4  Aug 1993	  Erik Kay at NeXT
 *	API cleanup
 */

#ifndef	_IOHIDSYSTEM_H
#define _IOHIDSYSTEM_H

#include <IOKit/IOTimerEventSource.h>
#include <IOKit/IOService.h>
#include <IOKit/IOUserClient.h>
#include <IOKit/IOWorkLoop.h>
#include <IOKit/IOCommandQueue.h>
#include <IOKit/IOBufferMemoryDescriptor.h>
#include <IOKit/pwr_mgt/IOPM.h>
#include <IOKit/graphics/IOGraphicsDevice.h>
#include <IOKit/hidsystem/IOHIDevice.h>
#include <IOKit/hidsystem/IOHIDShared.h>
#include <IOKit/hidsystem/IOHIDTypes.h>
#include <IOKit/hidsystem/IOLLEvent.h>
#include "ev_keymap.h"		/* For NX_NUM_SCANNED_SPECIALKEYS */

typedef void (*IOHIDAction)(OSObject *, void *);

class IOHIDSystem : public IOService
{
	OSDeclareDefaultStructors(IOHIDSystem);

	friend class IOHIDUserClient;
	friend class IOHIDParamUserClient;

private:
	IOLock *	driverLock;

	IOWorkLoop *		workLoop;
	IOTimerEventSource *  	timerES;
	IOCommandQueue *	cmdQ;
	IOUserClient *		serverConnect;
	IOUserClient *		paramConnect;
        IONotifier *		publishNotify;

	// Ports on which we hold send rights
	mach_port_t	eventPort;	// Send msg here when event queue
					// goes non-empty
	mach_port_t	_specialKeyPort[NX_NUM_SCANNED_SPECIALKEYS]; // Special key msgs
	void		*eventMsg;	// Msg to be sent to Window Server.

	// Shared memory area information
        IOBufferMemoryDescriptor * globalMemory;
	vm_offset_t	shmem_addr;	// kernel address of shared memory
	vm_size_t	shmem_size;	// size of shared memory

	// Pointers to structures which occupy the shared memory area.
	volatile void	*evs;		// Pointer to private driver shmem
	volatile EvGlobals *evg;	// Pointer to EvGlobals (shmem)
	// Internal variables related to the shared memory area
	int		lleqSize;	// # of entries in low-level queue
                        // FIXME: why is this ivar lleqSize an ivar? {Dan]

	// Screens list
	vm_size_t	evScreenSize;	// Byte size of evScreen array
	void		*evScreen;	// array of screens known to driver
	volatile void	*lastShmemPtr;	// Pointer used to index thru shmem
					// while assigning shared areas to
					// drivers.
	int		screens;	// running total of allocated screens
	UInt32		cursorScreens;	// bit mask of screens with cursor present
        UInt32		cursorPinScreen;// a screen to pin against
	Bounds		cursorPin;	// Range to which cursor is pinned
					// while on this screen.
	Bounds		workSpace;	// Bounds of full workspace.
	// Event Status state - This includes things like event timestamps,
	// time til screen dim, and related things manipulated through the
	// Event Status API.
	//
	Point	pointerLoc;	// Current pointing device location
				// The value leads evg->cursorLoc.
        Point	pointerDelta;	// The cumulative pointer delta values since
                                // previous mouse move event was posted
	Point	clickLoc;	// location of last mouse click
	Point   clickSpaceThresh;	// max mouse delta to be a doubleclick
	int	clickState;	// Current click state
	unsigned char lastPressure;	// last pressure seen
	bool	lastProximity;	// last proximity state seen

	SInt32	curVolume;	// Value of volume setting.
	SInt32	dimmedBrightness;// Value of screen brightness when autoDim
				// has turned on.
	SInt32	curBright;	// The current brightness is cached here while
				// the driver is open.  This number is always
				// the user-specified brightness level; if the
				// screen is autodimmed, the actual brightness
				// level in the monitor will be less.
	SInt32 autoDimmed;	// Is screen currently autodimmed?
	bool evOpenCalled;	// Has the driver been opened?
	bool evInitialized;	// Has the first-open-only initialization run?
	bool eventsOpen;	// Boolean: has evmmap been called yet?
	bool cursorStarted;	// periodic events running?
	bool cursorEnabled;	// cursor positioning ok?
	bool cursorCoupled;	// cursor positioning on pointer moves ok?

	short leftENum;		// Unique ID for last left down event
	short rightENum;	// Unique ID for last right down event
	
	// The periodic event mechanism timestamps and state
	// are recorded here.
	AbsoluteTime thisPeriodicRun;
        AbsoluteTime periodicEventDelta;// Time between periodic events
                                        // todo: make infinite
        AbsoluteTime clickTime;		// Timestamps used to determine doubleclicks
        AbsoluteTime clickTimeThresh;
        AbsoluteTime autoDimPeriod;	// How long since last user action before
                                        // we autodim screen?  User preference item,
                                        // set by InitMouse and evsioctl
        AbsoluteTime autoDimTime;	// Time value when we will autodim screen,
                                        // if autoDimmed is 0.
                                        // Set in LLEventPost.

        AbsoluteTime waitSustain;	// Sustain time before removing cursor
        AbsoluteTime waitSusTime;	// Sustain counter
        AbsoluteTime waitFrameRate;	// Ticks per wait cursor frame
        AbsoluteTime waitFrameTime;	// Wait cursor frame timer

        AbsoluteTime postedVBLTime;	// Used to post mouse events once per frame
        AbsoluteTime lastEventTime;
        AbsoluteTime lastMoveTime;
        SInt32 accumDX;
        SInt32 accumDY;

	// Flags used in scheduling periodic event callbacks
	bool		needSetCursorPosition;
	bool		needToKickEventConsumer;
	IOLock *	kickConsumerLock;
        
public:
        IOService * displayManager;			// points to display manager
        IOPMPowerFlags displayState;

private:
  inline short getUniqueEventNum();

        virtual IOReturn powerStateDidChangeTo ( IOPMPowerFlags, unsigned long, IOService*);
 /* Resets */
  void _resetMouseParameters();
  void _resetKeyboardParameters();

  /* Initialize the shared memory area */
  void     initShmem();
  /* Dispatch low level events through shared memory to the WindowServer */
  void postEvent(int           what,
          /* at */       Point *       location,
          /* atTime */   AbsoluteTime  ts,
          /* withData */ NXEventData * myData);
  /* Dispatch mechanisms for screen state changes */
  void evDispatch(
            /* command */ EvCmd evcmd);
  /* Dispatch mechanism for special key press */
  void evSpecialKeyMsg(unsigned key,
               /* direction */ unsigned dir,
               /* flags */     unsigned f,
               /* level */     unsigned l);
  /* Message the event consumer to process posted events */
  void kickEventConsumer();
  IOReturn sendWorkLoopCommand(OSObject *  target,
                                       IOHIDAction action,
                                       void *      data);
  static void _doPerformInIOThread( void* self,
				    void* target,
                                    void* action,
                                    void* data,
                                    void* unused);
  static void _periodicEvents(IOHIDSystem * self,
                              IOTimerEventSource *timer);

  static void _performSpecialKeyMsg(IOHIDSystem * self,
					struct evioSpecialKeyMsg *msg);
  static void _performKickEventConsumer(IOHIDSystem * self,void *);
 
  static bool publishNotificationHandler( IOHIDSystem * self, 
				void * ref, IOService * newService );

/*
 * HISTORICAL NOTE:
 *   The following methods were part of the IOHIDSystem(Input) category;
 *   the declarations have now been merged directly into this class.
 *
 * Exported Interface Event Driver object input services.
 */

private:
  // Schedule next periodic run based on current event system state.
  void scheduleNextPeriodicEvent();
  // Message invoked to run periodic events.  This method runs in the workloop.
  void periodicEvents(IOTimerEventSource *timer);
  // Start the cursor running.
  bool startCursor();
  // Repin cursor location.
  bool resetCursor();
  // Wait Cursor machinery.
  void showWaitCursor();
  void hideWaitCursor();
  void animateWaitCursor();
  void changeCursor(int frame);
  // Return screen number a point lies on.
  int  pointToScreen(Point * p);
  // Set the undimmed brightness.
  void setBrightness(int b);
  // Return undimmed brightness.
  int  brightness();
  // Set the dimmed brightness.
  void setAutoDimBrightness(int b);
  // Return dimmed brightness.
  int  autoDimBrightness();
  // Return the current brightness.
  int  currentBrightness();
  // Dim all displays.
  void doAutoDim();
  // Return display brightness to normal.
  void undoAutoDim();
  // Force dim/undim.
  void forceAutoDimState(bool dim);
  // Audio volume control.
  void setAudioVolume(int v);
  // Audio volume control, from ext user.
  void setUserAudioVolume(int v);
  // Return audio volume.
  int  audioVolume();
  // Propagate state out to screens.
  inline void setBrightness();

  inline void showCursor();
  inline void hideCursor();
  inline void moveCursor();
  // Claim ownership of event sources.
  void attachDefaultEventSources();
  // Give up ownership of event sources.
  void detachEventSources();
  bool registerEventSource(IOHIDevice * source);

  // Set abs cursor position.
  void setCursorPosition(Point * newLoc, bool external);
  void _setButtonState(int buttons,
                       /* atTime */ AbsoluteTime ts);
  void _setCursorPosition(Point * newLoc, bool external);

  void _postMouseMoveEvent(int		what,
                           Point *	location,
                           AbsoluteTime	theClock);

/* END HISTORICAL NOTE */

public:
  static IOHIDSystem * instance();     /* Return the current instance of the */
				       /* EventDriver, or 0 if none. */

  virtual bool init(OSDictionary * properties = 0);
  virtual IOHIDSystem * probe(IOService *    provider,
                              SInt32 * score);
  virtual bool start(IOService * provider);
  virtual IOReturn message(UInt32 type, IOService * provider,
				void * argument);
  virtual void free();

  virtual IOWorkLoop *getWorkLoop() const;

  virtual IOReturn evOpen(void);
  virtual IOReturn evClose(void);

  virtual bool 	    updateProperties(void);
  virtual IOReturn  setParamProperties(OSDictionary * dict);
  virtual bool      serializeProperties( OSSerialize * s ) const;

  /* Create the shared memory area */
  virtual IOReturn createShmem(void*,void*,void*,void*,void*,void*);
  /* Set the port for event available notify msg */
  virtual void     setEventPort(mach_port_t port);
  /* Set the port for the special key keypress msg */
  virtual IOReturn setSpecialKeyPort(
                     /* keyFlavor */ int         special_key,
                     /* keyPort */   mach_port_t key_port);
  virtual mach_port_t specialKeyPort(int special_key);


  virtual IOReturn newUserClient(task_t         owningTask,
                 /* withToken */ void *         security_id,
                 /* ofType */    UInt32         type,
                 /* client */    IOUserClient ** handler);

/*
 * HISTORICAL NOTE:
 *   The following methods were part of the IOHIPointingEvents protocol;
 *   the declarations have now been merged directly into this class.
 */

public: 
  /* Mouse event reporting */
  virtual void relativePointerEvent(int        buttons,
                       /* deltaX */ int        dx,
                       /* deltaY */ int        dy,
                       /* atTime */ AbsoluteTime ts);

  /* Tablet event reporting */
  virtual void absolutePointerEvent(int        buttons,
                 /* at */           Point *    newLoc,
                 /* withBounds */   Bounds *   bounds,
                 /* inProximity */  bool       proximity,
                 /* withPressure */ int        pressure,
                 /* withAngle */    int        stylusAngle,
                 /* atTime */       AbsoluteTime ts);

  /* Mouse scroll wheel event reporting */
  virtual void scrollWheelEvent(short deltaAxis1,
                                short deltaAxis2,
                                short deltaAxis3,
                                AbsoluteTime ts);
  

  virtual void tabletEvent(NXEventData *tabletData,
                           AbsoluteTime ts);

  virtual void proximityEvent(NXEventData *proximityData,
                              AbsoluteTime ts);

/*
 * HISTORICAL NOTE:
 *   The following methods were part of the IOHIKeyboardEvents protocol;
 *   the declarations have now been merged directly into this class.
 */

public:
  virtual void keyboardEvent(unsigned   eventType,
      /* flags */            unsigned   flags,
      /* keyCode */          unsigned   key,
      /* charCode */         unsigned   charCode,
      /* charSet */          unsigned   charSet,
      /* originalCharCode */ unsigned   origCharCode,
      /* originalCharSet */  unsigned   origCharSet,
      /* keyboardType */     unsigned   keyboardType,
      /* repeat */           bool       repeat,
      /* atTime */           AbsoluteTime ts);

  virtual void keyboardSpecialEvent(   unsigned   eventType,
                    /* flags */        unsigned   flags,
                    /* keyCode  */     unsigned   key,
                    /* specialty */    unsigned   flavor,
                    /* guid */ 	       UInt64     guid,
                    /* repeat */       bool       repeat,
                    /* atTime */       AbsoluteTime ts);

  virtual void updateEventFlags(unsigned flags);  /* Does not generate events */




private:

  /*
   * statics for upstream callouts
   */

  void _scaleLocationToCurrentScreen(Point *location, Bounds *bounds);  // Should this one be public???

  static void _relativePointerEvent( IOHIDSystem * self,
				    int        buttons,
                       /* deltaX */ int        dx,
                       /* deltaY */ int        dy,
                       /* atTime */ AbsoluteTime ts);

  /* Tablet event reporting */
  static void _absolutePointerEvent(IOHIDSystem * self,
				    int        buttons,
                 /* at */           Point *    newLoc,
                 /* withBounds */   Bounds *   bounds,
                 /* inProximity */  bool       proximity,
                 /* withPressure */ int        pressure,
                 /* withAngle */    int        stylusAngle,
                 /* atTime */       AbsoluteTime ts);

  /* Mouse scroll wheel event reporting */
  static void _scrollWheelEvent(IOHIDSystem *self,
                                short deltaAxis1,
                                short deltaAxis2,
                                short deltaAxis3,
                                AbsoluteTime ts);

  static void _tabletEvent(IOHIDSystem *self,
                           NXEventData *tabletData,
                           AbsoluteTime ts);

  static void _proximityEvent(IOHIDSystem *self,
                              NXEventData *proximityData,
                              AbsoluteTime ts);

  static void _keyboardEvent( IOHIDSystem * self,
			     unsigned   eventType,
      /* flags */            unsigned   flags,
      /* keyCode */          unsigned   key,
      /* charCode */         unsigned   charCode,
      /* charSet */          unsigned   charSet,
      /* originalCharCode */ unsigned   origCharCode,
      /* originalCharSet */  unsigned   origCharSet,
      /* keyboardType */     unsigned   keyboardType,
      /* repeat */           bool       repeat,
      /* atTime */           AbsoluteTime ts);
  static void _keyboardSpecialEvent( 	IOHIDSystem * self,
                                        unsigned   eventType,
                    /* flags */     	unsigned   flags,
                    /* keyCode  */  	unsigned   key,
                    /* specialty */ 	unsigned   flavor,
                    /* guid */          UInt64     guid,
                    /* repeat */        bool       repeat,
                    /* atTime */    	AbsoluteTime ts);
  static void _updateEventFlags( IOHIDSystem * self,
				unsigned flags);  /* Does not generate events */


/*
 * HISTORICAL NOTE:
 *   The following methods were part of the IOUserClient protocol;
 *   the declarations have now been merged directly into this class.
 */

public:

  virtual IOReturn setEventsEnable(void*,void*,void*,void*,void*,void*);
  virtual IOReturn setCursorEnable(void*,void*,void*,void*,void*,void*);
  virtual IOReturn extPostEvent(void*,void*,void*,void*,void*,void*);
  virtual IOReturn extSetMouseLocation(void*,void*,void*,void*,void*,void*);
  virtual IOReturn extGetButtonEventNum(void*,void*,void*,void*,void*,void*);

/*
 * HISTORICAL NOTE:
 *   The following methods were part of the IOScreenRegistration protocol;
 *   the declarations have now been merged directly into this class.
 *
 * Methods exported by the EventDriver for display systems.
 *
 *	The screenRegister protocol is used by frame buffer drivers to register
 *	themselves with the Event Driver.  These methods are called in response
 *	to an _IOGetParameterInIntArray() call with "IO_Framebuffer_Register" or
 *	"IO_Framebuffer_Unregister".
 */

public:
  virtual int registerScreen(IOGraphicsDevice * instance,
             /* bounds */    Bounds * bp);
//           /* shmem */     void **  addr,
//           /* size */      int *    size)
  virtual void unregisterScreen(int index);

/*
 * HISTORICAL NOTE:
 *   The following methods were part of the IOWorkspaceBounds protocol;
 *   the declarations have now been merged directly into this class.
 *
 * Absolute position input devices and some specialized output devices
 * may need to know the bounding rectangle for all attached displays.
 * The following method returns a Bounds* for the workspace.  Please note
 * that the bounds are kept as signed values, and that on a multi-display
 * system the minx and miny values may very well be negative.
 */

public:
  virtual Bounds * workspaceBounds();

/* END HISTORICAL NOTES */
};

#endif /* !_IOHIDSYSTEM_H */
