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

#include <IOKit/assert.h>
#include <IOKit/IOLib.h>
#include "ApplePS2Mouse.h"

// =============================================================================
// ApplePS2Mouse Class Implementation
//

#define super IOHIPointing
OSDefineMetaClassAndStructors(ApplePS2Mouse, IOHIPointing);

UInt32 ApplePS2Mouse::deviceType()  { return NX_EVS_DEVICE_TYPE_MOUSE; };
UInt32 ApplePS2Mouse::interfaceID() { return NX_EVS_DEVICE_INTERFACE_BUS_ACE; };

IOItemCount ApplePS2Mouse::buttonCount() { return 3; };
IOFixed     ApplePS2Mouse::resolution()  { return _resolution; };

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

bool ApplePS2Mouse::init(OSDictionary * properties)
{
  //
  // Initialize this object's minimal state.  This is invoked right after this
  // object is instantiated.
  //

  if (!super::init(properties))  return false;

  _device                    = 0;
  _interruptHandlerInstalled = false;
  _packetByteCount           = 0;
  _packetLength              = kPacketLengthStandard;
  _resolution                = (150) << 16; // (default is 150 dpi; 6 counts/mm)
  _type                      = kMouseTypeStandard;

  return true;
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

ApplePS2Mouse * ApplePS2Mouse::probe(IOService * provider, SInt32 * score)
{
  //
  // The driver has been instructed to verify the presence of the actual
  // hardware we represent. We are guaranteed by the controller that the
  // mouse clock is enabled and the mouse itself is disabled (thus it
  // won't send any asynchronous mouse data that may mess up the
  // responses expected by the commands we send it).
  //

  ApplePS2MouseDevice * device  = (ApplePS2MouseDevice *)provider;
  PS2Request *          request = device->allocateRequest();
  bool                  success;

  if (!super::probe(provider, score))  return 0;

  //
  // Check to see if acknowledges are being received for commands to the mouse.
  //

  // (get information command)
  request->commands[0].command = kPS2C_WriteCommandPort;
  request->commands[0].inOrOut = kCP_TransmitToMouse;
  request->commands[1].command = kPS2C_WriteDataPort;
  request->commands[1].inOrOut = kDP_GetMouseInformation;
  request->commands[2].command = kPS2C_ReadDataPortAndCompare;
  request->commands[2].inOrOut = kSC_Acknowledge;
  request->commands[3].command = kPS2C_ReadDataPort;
  request->commands[3].inOrOut = 0;
  request->commands[4].command = kPS2C_ReadDataPort;
  request->commands[4].inOrOut = 0;
  request->commands[5].command = kPS2C_ReadDataPort;
  request->commands[5].inOrOut = 0;
  request->commandsCount = 6;
  device->submitRequestAndBlock(request);

  // (free the request)
  success = (request->commandsCount == 6);
  device->freeRequest(request);

  return (success) ? this : 0;
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

bool ApplePS2Mouse::start(IOService * provider)
{
  //
  // The driver has been instructed to start.   This is called after a
  // successful probe and match.
  //

  if (!super::start(provider))  return false;

  //
  // Maintain a pointer to and retain the provider object.
  //

  _device = (ApplePS2MouseDevice *)provider;
  _device->retain();

  //
  // Install our driver's interrupt handler, for asynchronous data delivery.
  //

  _device->installInterruptAction(this,
    (PS2InterruptAction)&ApplePS2Mouse::interruptOccurred);
  _interruptHandlerInstalled = true;

  //
  // Obtain our mouse's resolution and sampling rate.
  //

  switch (getMouseInformation() & 0x00FF00)
  {
    case 0x0000: _resolution = (25)  << 16; break; //  25 dpi
    case 0x0100: _resolution = (50)  << 16; break; //  50 dpi
    case 0x0200: _resolution = (100) << 16; break; // 100 dpi
    case 0x0300: _resolution = (200) << 16; break; // 200 dpi
    default:     _resolution = (150) << 16; break; // 150 dpi
  }

  //
  // Enable the Intellimouse mode, should this be an Intellimouse.
  //

  if ( setIntellimouseMode() == true )
  {
    _packetLength = kPacketLengthIntellimouse;
    _type         = kMouseTypeIntellimouse;
  }

  //
  // Enable the mouse clock (should already be so) and the mouse IRQ line.
  //

  setCommandByte(kCB_EnableMouseIRQ, kCB_DisableMouseClock);

  //
  // Finally, we enable the mouse itself, so that it may start reporting
  // mouse events.
  //

  setMouseEnable(true);

  return true;
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

void ApplePS2Mouse::stop(IOService * provider)
{
  //
  // The driver has been instructed to stop.  Note that we must break all
  // connections to other service objects now (ie. no registered actions,
  // no pointers and retains to objects, etc), if any.
  //

  assert(_device == provider);

  //
  // Disable the mouse itself, so that it may stop reporting mouse events.
  //

  setMouseEnable(false);

  //
  // Disable the mouse clock and the mouse IRQ line.
  //

  setCommandByte(kCB_DisableMouseClock, kCB_EnableMouseIRQ);

  //
  // Uninstall the interrupt handler.
  //

  if ( _interruptHandlerInstalled )  _device->uninstallInterruptAction();
  _interruptHandlerInstalled = false;

  //
  // Release the pointer to the provider object.
  //

  _device->release();
  _device = 0;

  super::stop(provider);
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

void ApplePS2Mouse::interruptOccurred(UInt8 data)      // PS2InterruptAction
{
  //
  // This will be invoked automatically from our device when asynchronous mouse
  // needs to be delivered.  Process the mouse data.   Do NOT send any BLOCKING
  // commands to our device in this context.
  //
  // We ignore all bytes until we see the start of a packet, otherwise the mouse
  // packets may get out of sequence and things will get very confusing.
  //

  if (_packetByteCount == 0 && ((data == kSC_Acknowledge) || !(data & 0x08)))
  {
    IOLog("%s: Unexpected data from PS/2 controller.\n", getName());
    return;
  }

  //
  // Add this byte to the packet buffer.  If the packet is complete, that is,
  // we have the three bytes, dispatch this packet for processing.
  //

  _packetBuffer[_packetByteCount++] = data;

  if (_packetByteCount == _packetLength)
  {
    dispatchRelativePointerEventWithPacket(_packetBuffer);
    _packetByteCount = 0;
  }
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

void ApplePS2Mouse::dispatchRelativePointerEventWithPacket(UInt8 * packet)
{
  //
  // Process the three byte mouse packet that was retreived from the mouse.
  // The format of the bytes is as follows:
  //
  // 7  6  5  4  3  2  1  0
  // YO XO YS XS 1  M  R  L
  // X7 X6 X5 X4 X3 X3 X1 X0
  // Y7 Y6 Y5 Y4 Y3 Y2 Y1 Y0
  // Z7 Z6 Z5 Z4 Z3 Z2 Z1 Z0 <- fourth byte returned only for Intellimouse type
  //

  UInt32       buttons = 0;
  SInt32       dx;
  SInt32       dy;
  SInt32       dz;
  AbsoluteTime now;

  if ( !(packet[0] & 0x1) ) buttons |= 0x1;  // left button   (bit 0 in packet)
  if ( !(packet[0] & 0x2) ) buttons |= 0x2;  // right button  (bit 1 in packet)
  if ( !(packet[0] & 0x4) ) buttons |= 0x4;  // middle button (bit 2 in packet)

  dx = ((packet[0] & 0x10) ? 0xffffff00 : 0 ) | packet[1];
  dy = -(((packet[0] & 0x20) ? 0xffffff00 : 0 ) | packet[2]);
  dz = (SInt32)((SInt8)packet[3]);

  clock_get_uptime(&now);

  dispatchRelativePointerEvent(dx, dy, buttons, now);

  return;
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

void ApplePS2Mouse::setMouseEnable(bool enable)
{
  //
  // Instructs the mouse to start or stop the reporting of mouse events.
  // Be aware that while the mouse is enabled, asynchronous mouse events
  // may arrive in the middle of command sequences sent to the controller,
  // and may get confused for expected command responses.
  //
  // It is safe to issue this request from the interrupt/completion context.
  //

  PS2Request * request = _device->allocateRequest();

  // (mouse enable/disable command)
  request->commands[0].command = kPS2C_WriteCommandPort;
  request->commands[0].inOrOut = kCP_TransmitToMouse;
  request->commands[1].command = kPS2C_WriteDataPort;
  request->commands[1].inOrOut = (enable)?kDP_Enable:kDP_SetDefaultsAndDisable;
  request->commands[2].command = kPS2C_ReadDataPortAndCompare;
  request->commands[2].inOrOut = kSC_Acknowledge;
  request->commandsCount = 3;
  _device->submitRequest(request); // asynchronous, auto-free'd
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

void ApplePS2Mouse::setMouseSampleRate(UInt8 sampleRate)
{
  //
  // Instructs the mouse to change its sampling rate to the given value, in
  // reports per second.
  //
  // It is safe to issue this request from the interrupt/completion context.
  //

  PS2Request * request = _device->allocateRequest();

  // (set mouse sample rate command)
  request->commands[0].command = kPS2C_WriteCommandPort;
  request->commands[0].inOrOut = kCP_TransmitToMouse;
  request->commands[1].command = kPS2C_WriteDataPort;
  request->commands[1].inOrOut = kDP_SetMouseSampleRate;
  request->commands[2].command = kPS2C_ReadDataPortAndCompare;
  request->commands[2].inOrOut = kSC_Acknowledge;
  request->commands[3].command = kPS2C_WriteCommandPort;
  request->commands[3].inOrOut = kCP_TransmitToMouse;
  request->commands[4].command = kPS2C_WriteDataPort;
  request->commands[4].inOrOut = sampleRate;
  request->commands[5].command = kPS2C_ReadDataPortAndCompare;
  request->commands[5].inOrOut = kSC_Acknowledge;
  request->commandsCount = 6;
  _device->submitRequest(request); // asynchronous, auto-free'd
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

bool ApplePS2Mouse::setIntellimouseMode()
{
  //
  // Determines whether this mouse is a Microsoft Intellimouse, and if it is,
  // it enables it (the mouse will send 4 byte packets for mouse events from
  // then on). Returns true if the Intellimouse mode was succesfully enabled.
  //
  // Do NOT issue this request from the interrupt/completion context.
  //

  UInt32 mouseInfo;
  bool   isIntellimouse;

  //
  // Obtain the current sample rate, in order that we may restore it after
  // the Intellimouse command sequence completes.
  //

  mouseInfo = getMouseInformation();

  if (mouseInfo == (UInt32)(-1))  return false;

  //
  // Generate the special command sequence to enable the 'Intellimouse' mode.
  // The sequence is to set the sampling rate to 200, 100, then 80, at which
  // point the mouse will start sending 4 byte packets for mouse events and
  // return a mouse ID of 3.
  //

  setMouseSampleRate(200);
  setMouseSampleRate(100);
  setMouseSampleRate(80 );

  //
  // Determine whether we have an Intellimouse by asking for the mouse's ID.
  //

  isIntellimouse = ( getMouseID() == kMouseTypeIntellimouse );

  //
  // Restore the original sampling rate, before we obliterated it.
  //

  setMouseSampleRate(mouseInfo & 0x0000FF);

  return isIntellimouse;
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

UInt32 ApplePS2Mouse::getMouseInformation()
{
  //
  // Asks the mouse to transmit its three information bytes.  Should the
  // mouse not respond, a value of (UInt32)(-1) is returned.
  //
  // Do NOT issue this request from the interrupt/completion context.
  //

  PS2Request * request     = _device->allocateRequest();
  UInt32       returnValue = (UInt32)(-1);

  // (get information command)
  request->commands[0].command = kPS2C_WriteCommandPort;
  request->commands[0].inOrOut = kCP_TransmitToMouse;
  request->commands[1].command = kPS2C_WriteDataPort;
  request->commands[1].inOrOut = kDP_GetMouseInformation;
  request->commands[2].command = kPS2C_ReadDataPortAndCompare;
  request->commands[2].inOrOut = kSC_Acknowledge;
  request->commands[3].command = kPS2C_ReadDataPort;
  request->commands[3].inOrOut = 0;
  request->commands[4].command = kPS2C_ReadDataPort;
  request->commands[4].inOrOut = 0;
  request->commands[5].command = kPS2C_ReadDataPort;
  request->commands[5].inOrOut = 0;
  request->commandsCount = 6;
  _device->submitRequestAndBlock(request);

  if (request->commandsCount == 6) // success?
  {
    returnValue = ((UInt32)request->commands[3].inOrOut << 16) |
                  ((UInt32)request->commands[4].inOrOut << 8 ) |
                  ((UInt32)request->commands[5].inOrOut);
  }
  _device->freeRequest(request);
  
  return returnValue;
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

UInt8 ApplePS2Mouse::getMouseID()
{
  //
  // Asks the mouse to transmit its identification byte.  Should the mouse
  // not respond, a value of (UInt8)(-1) is returned.
  //
  // Note that some documentation on PS/2 mice implies that two identification
  // bytes are returned and not one.  This was proven to be false in my tests.
  //
  // Do NOT issue this request from the interrupt/completion context.
  //

  PS2Request * request     = _device->allocateRequest();
  UInt8        returnValue = (UInt8)(-1);

  // (get information command)
  request->commands[0].command = kPS2C_WriteCommandPort;
  request->commands[0].inOrOut = kCP_TransmitToMouse;
  request->commands[1].command = kPS2C_WriteDataPort;
  request->commands[1].inOrOut = kDP_GetId;
  request->commands[2].command = kPS2C_ReadDataPortAndCompare;
  request->commands[2].inOrOut = kSC_Acknowledge;
  request->commands[3].command = kPS2C_ReadDataPort;
  request->commands[3].inOrOut = 0;
  request->commandsCount = 4;
  _device->submitRequestAndBlock(request);

  if (request->commandsCount == 4) // success?
    returnValue = request->commands[3].inOrOut;

  _device->freeRequest(request);

  return returnValue;
}

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -

void ApplePS2Mouse::setCommandByte(UInt8 setBits, UInt8 clearBits)
{
  //
  // Sets the bits setBits and clears the bits clearBits "atomically" in the
  // controller's Command Byte.   Since the controller does not provide such
  // a read-modify-write primitive, we resort to a test-and-set try loop.
  //
  // Do NOT issue this request from the interrupt/completion context.
  //

  UInt8        commandByte;
  UInt8        commandByteNew;
  PS2Request * request = _device->allocateRequest();

  do
  {
    // (read command byte)
    request->commands[0].command = kPS2C_WriteCommandPort;
    request->commands[0].inOrOut = kCP_GetCommandByte;
    request->commands[1].command = kPS2C_ReadDataPort;
    request->commands[1].inOrOut = 0;
    request->commandsCount = 2;
    _device->submitRequestAndBlock(request);

    //
    // Modify the command byte as requested by caller.
    //

    commandByte    = request->commands[1].inOrOut;
    commandByteNew = (commandByte | setBits) & (~clearBits);

    // ("test-and-set" command byte)
    request->commands[0].command = kPS2C_WriteCommandPort;
    request->commands[0].inOrOut = kCP_GetCommandByte;
    request->commands[1].command = kPS2C_ReadDataPortAndCompare;
    request->commands[1].inOrOut = commandByte;
    request->commands[2].command = kPS2C_WriteCommandPort;
    request->commands[2].inOrOut = kCP_SetCommandByte;
    request->commands[3].command = kPS2C_WriteDataPort;
    request->commands[3].inOrOut = commandByteNew;
    request->commandsCount = 4;
    _device->submitRequestAndBlock(request);

    //
    // Repeat this loop if last command failed, that is, if the old command byte
    // was modified since we first read it.
    //

  } while (request->commandsCount != 4);  

  _device->freeRequest(request);
}
