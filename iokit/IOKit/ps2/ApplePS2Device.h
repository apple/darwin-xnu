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

#ifndef _APPLEPS2DEVICE_H
#define _APPLEPS2DEVICE_H

#include <IOKit/IOService.h>

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
// Definitions
//
// Data Port (0x60) Commands.  These commands are all transmitted directly to
// the physical keyboard and/or mouse, so expect an acknowledge for each byte
// that you send through this port.
//

#define kDP_SetMouseScaling1To1        0xE6 // (mouse)
#define kDP_SetMouseScaling2To1        0xE7 // (mouse)
#define kDP_SetMouseResolution         0xE8 // (mouse)
#define kDP_GetMouseInformation        0xE9 // (mouse)
#define kDP_SetMouseStreamMode         0xEA // (mouse)
#define kDP_SetKeyboardLEDs            0xED // (keyboard)
#define kDP_TestKeyboardEcho           0xEE // (keyboard)
#define kDP_GetSetKeyboardASCs         0xF0 // (keyboard)
#define kDP_GetId                      0xF2 // (keyboard+mouse)
#define kDP_SetKeyboardTypematic       0xF3 // (keyboard)
#define kDP_SetMouseSampleRate         0xF3 // (mouse)
#define kDP_Enable                     0xF4 // (keyboard+mouse)
#define kDP_SetDefaultsAndDisable      0xF5 // (keyboard+mouse)
#define kDP_SetDefaults                0xF6 // (keyboard+mouse)
#define kDP_SetAllTypematic            0xF7 // (keyboard)
#define kDP_SetAllMakeRelease          0xF8 // (keyboard)
#define kDP_SetAllMakeOnly             0xF9 // (keyboard)
#define kDP_SetAllTypematicMakeRelease 0xFA // (keyboard)
#define kDP_SetKeyMakeRelease          0xFB // (keyboard)
#define kDP_SetKeyMakeOnly             0xFC // (keyboard)
#define kDP_Reset                      0xFF // (keyboard+mouse)

//
// Command Port (0x64) Commands.  These commands all access registers local
// to the motherboard, ie. nothing is transmitted,  thus these commands and
// any associated data passed thru the Data Port do not return acknowledges.
//

#define kCP_GetCommandByte             0x20 // (keyboard+mouse)
#define kCP_ReadControllerRAMBase      0x21 //
#define kCP_SetCommandByte             0x60 // (keyboard+mouse)
#define kCP_WriteControllerRAMBase     0x61 //
#define kCP_TestPassword               0xA4 //
#define kCP_GetPassword                0xA5 //
#define kCP_VerifyPassword             0xA6 //
#define kCP_DisableMouseClock          0xA7 // (mouse)
#define kCP_EnableMouseClock           0xA8 // (mouse)
#define kCP_TestMousePort              0xA9 //
#define kCP_TestController             0xAA //
#define kCP_TestKeyboardPort           0xAB //
#define kCP_GetControllerDiagnostic    0xAC //
#define kCP_DisableKeyboardClock       0xAD // (keyboard)
#define kCP_EnableKeyboardClock        0xAE // (keyboard)
#define kCP_ReadInputPort              0xC0 //
#define kCP_PollInputPortLow           0xC1 //
#define kCP_PollInputPortHigh          0xC2 //
#define kCP_ReadOutputPort             0xD0 //
#define kCP_WriteOutputPort            0xD1 //
#define kCP_WriteKeyboardOutputBuffer  0xD2 // (keyboard)
#define kCP_WriteMouseOutputBuffer     0xD3 // (mouse)
#define kCP_TransmitToMouse            0xD4 // (mouse)
#define kCP_ReadTestInputs             0xE0 //
#define kCP_PulseOutputBitBase         0xF0 //

//
// Bit definitions for the 8-bit "Command Byte" register, which is accessed
// through the Command Port (0x64).
//

#define kCB_EnableKeyboardIRQ           0x01    // Enable Keyboard IRQ
#define kCB_EnableMouseIRQ              0x02    // Enable Mouse IRQ
#define kCB_SystemFlag                  0x04    // Set System Flag
#define kCB_InhibitOverride             0x08    // Inhibit Override
#define kCB_DisableKeyboardClock        0x10    // Disable Keyboard Clock
#define kCB_DisableMouseClock           0x20    // Disable Mouse Clock
#define kCB_TranslateMode               0x40    // Keyboard Translate Mode

//
// Bit definitions for the 8-bit "LED" register, which is accessed through
// the Data Port (0x64).  Undefined bit positions must be zero.
//

#define kLED_ScrollLock         0x01    // Scroll Lock
#define kLED_NumLock            0x02    // Num Lock
#define kLED_CapsLock           0x04    // Caps Lock

//
// Scan Codes used for special purposes on the keyboard and/or mouse receive
// port.  These values would be received from your interrupt handler or from
// a ReadDataPort command primitive.    These values do not represent actual
// keys, but indicate some sort of status.
//

#define kSC_Acknowledge         0xFA    // ack for transmitted commands
#define kSC_Extend              0xE0    // marker for "extended" sequence
#define kSC_Pause               0xE1    // marker for pause key sequence
#define kSC_Resend              0xFE    // request to resend keybd cmd
#define kSC_Reset               0xAA    // the keyboard/mouse has reset
#define kSC_UpBit               0x80    // OR'd in if key below is released

//
// Scan Codes for some modifier keys.
//

#define kSC_Alt                 0x38    // (extended = right key)
#define kSC_Ctrl                0x1D    // (extended = right key)
#define kSC_ShiftLeft           0x2A
#define kSC_ShiftRight          0x36
#define kSC_WindowsLeft         0x5B    // extended
#define kSC_WindowsRight        0x5C    // extended

//
// Scan Codes for some keys.
//

#define kSC_Delete              0x53    // (extended = gray key)
#define kSC_NumLock             0x45

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
// PS/2 Command Primitives
//
// o  kPS2C_ReadDataPort:
//    o  Description: Reads the next available byte off the data port (60h).
//    o  Out Field:   Holds byte that was read.
//
// o  kPS2C_ReadDataAndCompare:
//    o  Description: Reads the next available byte off the data port (60h),
//                    and compares it with the byte in the In Field.  If the
//                    comparison fails, the request is aborted (refer to the 
//                    commandsCount field in the request structure).
//    o  In Field:    Holds byte that comparison should be made to.
//
// o  kPS2C_WriteDataPort:
//    o  Description: Writes the byte in the In Field to the data port (60h).
//    o  In Field:    Holds byte that should be written.
//
// o  kPS2C_WriteCommandPort:
//    o  Description: Writes the byte in the In Field to the command port (64h).
//    o  In Field:    Holds byte that should be written.
//

enum PS2CommandEnum
{
  kPS2C_ReadDataPort,
  kPS2C_ReadDataPortAndCompare,
  kPS2C_WriteDataPort,
  kPS2C_WriteCommandPort
};
typedef enum PS2CommandEnum PS2CommandEnum;

struct PS2Command
{
  PS2CommandEnum command;
  UInt8          inOrOut;
};
typedef struct PS2Command PS2Command;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
// PS/2 Request Structure
//
// o  General Notes:
//    o  allocateRequest allocates the request structure -- use it always.
//    o  freeRequest deallocates the request structure -- use it always.
//    o  It is the driver's responsibility to free the request structure:
//       o  after a submitRequestAndBlock call returns, or
//       o  in the completion routine for each submitRequest issued.
//    o  It is not the driver's resposiblity to free the request structure:
//       o  when no completion routine is specified in a request issued via
//          submitRequest, in which case the request is freed automatically
//          by the controller.  This case is called "fire-and-forget".
//    o  On completion, the requester can see how far the processing got by
//       looking at the commandsCount field.  If it is equal to the original
//       number of commands, then the request was successful.  If isn't, the
//       value represents the zero-based index of the command that failed.
//
// o  General Notes For Inquisitive Minds:
//    o  Requests are executed atomically with respect to all other requests,
//       that is, if a keyboard request is currently being processed, then a
//       request submitted by the mouse driver or one submitted by a separate
//       thread of control in the keyboard driver will get queued until the
//       controller is available again.
//    o  Request processing can be preempted to service interrupts on other
//       PS/2 devices,  should other-device data arrive unexpectedly on the
//       input stream while processing a request.
//    o  The request processor knows when to read the mouse input stream
//       over the keyboard input stream for a given command sequence. It
//       does not depend on which driver it came from, rest assurred. If
//       the mouse driver so chose, it could send keyboard commands.
//
// o  commands:
//    o  Description:  Holds list of commands that controller should execute.
//    o  Comments:     Refer to PS2Command structure.
//
// o  commandsCount:
//    o  Description:  Holds the number of commands in the command list.
//    o  Comments:     Number of commands should never exceed kMaxCommands.
//
// o  completionRoutineTarget, Action, and Param:
//    o  Description:  Object and method of the completion routine, which is
//                     called when the request has finished. The Param field
//                     may be filled with anything you want; it is passed to
//                     completion routine when it is called.  These fields
//                     are optional.   If left null, the request structure
//                     will be deallocated automatically by the controller
//                     on completion of the request.
//    o  Prototype:    void completionRoutine(void * target, void * param);
//    o  Comments:     Never issue submitRequestAndBlock or otherwise BLOCK on
//                     any request sent down to your device from the completion
//                     routine.  Obey, or deadlock.
//

#define kMaxCommands 20

typedef void (*PS2CompletionAction)(void * target, void * param);

struct PS2Request
{
  UInt8               commandsCount;
  PS2Command          commands[kMaxCommands];
  void *              completionTarget;
  PS2CompletionAction completionAction;
  void *              completionParam;
};
typedef struct PS2Request PS2Request;

// - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - - -
// ApplePS2KeyboardDevice and ApplePS2MouseDevice Class Descriptions
//
//
// o  General Notes:
//    o  When the probe method is invoked on the client driver, the controller
//       guarantees that the keyboard clock is enabled and the keyboard itself
//       is disabled.  This implies the client driver can send commands to the
//       keyboard without a problem, and the keyboard itself will not send any
//       asynchronous key data that may mess up the responses expected by the
//       commands sent to it.
//
// o  installInterruptAction:
//    o  Description:   Ask the device to deliver asynchronous data to driver.
//    o  In Fields:     Target/action of completion routine.
//
// o  installInterruptAction Interrupt Routine:
//    o  Description:  Delivers a newly read byte from the input data stream.
//    o  Prototype:    void interruptOccurred(void * target, UInt8 byte);
//    o  In Fields:    Byte that was read.
//    o  Comments:     Never issue submitRequestAndBlock or otherwise BLOCK on
//                     any request sent down to your device from the interrupt
//                     routine.  Obey, or deadlock.
//
// o  uninstallInterruptHandler:
//    o  Description:  Ask the device to stop delivering asynchronous data.
//
// o  allocateRequest:
//    o  Description:  Allocate a request structure, blocks until successful.
//    o  Result:       Request structure pointer.
//    o  Comments:     Request structure is guaranteed to be zeroed.
//
// o  freeRequest:
//    o  Description:  Deallocate a request structure.
//    o  In Fields:    Request structure pointer.
//
// o  submitRequest:
//    o  Description:  Submit the request to the controller for processing.
//    o  In Fields:    Request structure pointer.
//    o  Result:       kern_return_t queueing status.
//
// o  submitRequestAndBlock:
//    o  Description:  Submit the request to the controller for processing, then
//                     block the calling thread until the request completes.
//    o  In Fields:    Request structure pointer.
//

typedef void (*PS2InterruptAction)(void * target, UInt8 data);

#endif /* !_APPLEPS2DEVICE_H */
