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

#ifndef _APPLEPS2CONTROLLER_H
#define _APPLEPS2CONTROLLER_H

#include <IOKit/IOInterruptEventSource.h>
#include <IOKit/IOService.h>
#include <IOKit/IOWorkLoop.h>
#include <IOKit/IOCommandQueue.h>
#include <IOKit/ps2/ApplePS2Device.h>

class ApplePS2KeyboardDevice;
class ApplePS2MouseDevice;

//
// This section describes the problem with the PS/2 controller design and what
// we are doing about it (OUT_OF_ORDER_DATA_CORRECTION_FEATURE).
//
// While the controller processes requests sent by the client drivers, at some
// point in most requests, a read needs to be made from the data port to check
// an acknowledge or receive some sort of data.  We illustrate this issue with
// an example -- a write LEDs request to the keyboard:
//
// 1. Write        Write LED command.
// 2. Read   0xFA  Verify the acknowledge (0xFA).
// 3. Write        Write LED state.
// 4. Read   0xFA  Verify the acknowledge (0xFA).
//
// The problem is that the keyboard (when it is enabled) can send key events
// to the controller at any time, including when the controller is expecting
// to read an acknowledge next.  What ends up happening is this sequence:
//
// a. Write        Write LED command.
// b. Read   0x21  Keyboard reports [F] key was depressed, not realizing that
//                 we're still expecting a response to the command we  JUST
//                 sent the keyboard.  We receive 0x21 as a response to our
//                 command, and figure the command failed.
// c. Get    0xFA  Keyboard NOW decides to respond to the command with an
//                 acknowledge.    We're not waiting to read anything, so
//                 this byte gets dispatched to the driver's interrupt
//                 handler, which spews out an error message saying it
//                 wasn't expecting an acknowledge.
//
// What can we do about this?  In the above case, we can take note of the fact
// that we are specifically looking for the 0xFA acknowledgement byte (through
// the information passed in the kPS2C_ReadAndCompare primitive).  If we don't
// receive this byte next on the input data stream, we put the byte we did get
// aside for a moment, and give the keyboard (or mouse) a second chance to
// respond correctly.
//
// If we receive the 0xFA acknowledgement byte on the second read, that we
// assume that situation described above just happened.   We transparently
// dispatch the first byte to the driver's interrupt handler, where it was
// meant to go, and return the second correct byte to the read-and-compare
// logic, where it was meant to go.  Everyone wins.
//
// The only situation this feature cannot help is where a kPS2C_ReadDataPort
// primitive is issued in place of a kPS2C_ReadDataPortAndCompare primitive.
// This is necessary in some requests because the driver does not know what
// it is going to receive.   This can be illustrated in the mouse get info
// command.
//
// 1. Write        Prepare to write to mouse.
// 2. Write        Write information command.
// 3. Read   0xFA  Verify the acknowledge (0xFA). __-> mouse can report mouse
// 4. Read         Get first information byte.    __-> packet bytes in between
// 5. Read         Get second information byte.   __-> these reads
// 6. Rrad         Get third information byte.
//
// Controller cannot build any defenses against this.  It is suggested that the
// driver writer disable the mouse first, then send any dangerous commands, and
// re-enable the mouse when the command completes. 
//
// Note that the OUT_OF_ORDER_DATA_CORRECTION_FEATURE can be turned off at
// compile time.    Please see the readDataPort:expecting: method for more
// information about the assumptions necessary for this feature.
//

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
// Definitions
//

// Enable debugger support (eg. mini-monitor).

#define DEBUGGER_SUPPORT 1

// Enable dynamic "second chance" re-ordering of input stream data if a
// command response fails to match the expected byte.

#define OUT_OF_ORDER_DATA_CORRECTION_FEATURE 1

// PS/2 device types.

typedef enum { kDT_Keyboard, kDT_Mouse } PS2DeviceType;

// Interrupt definitions.

#define kIRQ_Keyboard           1
#define kIRQ_Mouse              12
#define kIPL_Keyboard           6
#define kIPL_Mouse              3

// Port timings.

#define kDataDelay              7       // usec to delay before data is valid

// Ports used to control the PS/2 keyboard/mouse and read data from it.

#define kDataPort               0x60    // keyboard data & cmds (read/write)
#define kCommandPort            0x64    // keybd status (read), command (write)

// Bit definitions for kCommandPort read values (status).

#define kOutputReady            0x01    // output (from keybd) buffer full
#define kInputBusy              0x02    // input (to keybd) buffer full
#define kSystemFlag             0x04    // "System Flag"
#define kCommandLastSent        0x08    // 1 = cmd, 0 = data last sent
#define kKeyboardInhibited      0x10    // 0 if keyboard inhibited
#define kMouseData              0x20    // mouse data available

#if DEBUGGER_SUPPORT
// Definitions for our internal keyboard queue (holds keys processed by the
// interrupt-time mini-monitor-key-sequence detection code).

#define kKeyboardQueueSize 32            // number of KeyboardQueueElements

typedef struct KeyboardQueueElement KeyboardQueueElement;
struct KeyboardQueueElement
{
  queue_chain_t chain;
  UInt8         data;
};
#endif DEBUGGER_SUPPORT

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
// ApplePS2Controller Class Declaration
//

class ApplePS2Controller : public IOService
{
  OSDeclareDefaultStructors(ApplePS2Controller);

public:                                // interrupt-time variables and functions
  IOInterruptEventSource * _interruptSourceKeyboard;
  IOInterruptEventSource * _interruptSourceMouse;

#if DEBUGGER_SUPPORT
  void lockController(void);
  void unlockController(void);

  bool doEscape(UInt8 key);
  bool dequeueKeyboardData(UInt8 * key);
  void enqueueKeyboardData(UInt8 key);
#endif DEBUGGER_SUPPORT

private:
  IOCommandQueue *         _commandQueue;
  IOWorkLoop *             _workLoop;

  OSObject *               _interruptTargetKeyboard;
  OSObject *               _interruptTargetMouse;
  PS2InterruptAction       _interruptActionKeyboard;
  PS2InterruptAction       _interruptActionMouse;
  bool                     _interruptInstalledKeyboard;
  bool                     _interruptInstalledMouse;

  ApplePS2MouseDevice *    _mouseDevice;          // mouse nub
  ApplePS2KeyboardDevice * _keyboardDevice;       // keyboard nub

#if DEBUGGER_SUPPORT
  usimple_lock_data_t      _controllerLock;       // mach simple spin lock
  int                      _controllerLockOldSpl; // spl before lock taken

  KeyboardQueueElement *   _keyboardQueueAlloc;   // queues' allocation space
  queue_head_t             _keyboardQueue;        // queue of available keys
  queue_head_t             _keyboardQueueUnused;  // queue of unused entries

  bool                     _extendedState;
  UInt16                   _modifierState;
#endif DEBUGGER_SUPPORT

  virtual void  dispatchDriverInterrupt(PS2DeviceType deviceType, UInt8 data);
  virtual void  interruptOccurred(IOInterruptEventSource *, int);
  virtual void  processRequest(PS2Request * request, void *, void *, void *);
  static  void  submitRequestAndBlockCompletion(void *, void * param);

  virtual UInt8 readDataPort(PS2DeviceType deviceType);
  virtual void  writeCommandPort(UInt8 byte);
  virtual void  writeDataPort(UInt8 byte);

#if OUT_OF_ORDER_DATA_CORRECTION_FEATURE
  virtual UInt8 readDataPort(PS2DeviceType deviceType, UInt8 expectedByte);
#endif

public:
  virtual bool init(OSDictionary * properties);
  virtual bool start(IOService * provider);
  virtual void stop(IOService * provider);

  virtual IOWorkLoop * getWorkLoop() const;

  virtual void installInterruptAction(PS2DeviceType      deviceType,
                                      OSObject *         target,
                                      PS2InterruptAction action);
  virtual void uninstallInterruptAction(PS2DeviceType deviceType);

  virtual PS2Request * allocateRequest();
  virtual void         freeRequest(PS2Request * request);
  virtual bool         submitRequest(PS2Request * request);
  virtual void         submitRequestAndBlock(PS2Request * request);
};

#endif /* _APPLEPS2CONTROLLER_H */
