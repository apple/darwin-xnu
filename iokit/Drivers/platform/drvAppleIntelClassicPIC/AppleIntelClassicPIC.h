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
 *  DRI: Josh de Cesare
 *
 */

#ifndef _IOKIT_APPLEINTELCLASSICPIC_H
#define _IOKIT_APPLEINTELCLASSICPIC_H

#include <IOKit/IOInterrupts.h>
#include <IOKit/IOInterruptController.h>

#define kClockIRQ              0      // FIXME for SMP systems.

#define kPIC1BasePort          0x20
#define kPIC2BasePort          0xa0

#define kPIC1TriggerTypePort   0x4d0
#define kPIC2TriggerTypePort   0x4d1

#define kPICCmdPortOffset      0
#define kPICDataPortOffset     1

#define kEOICommand            0x20

#define kPICSlaveID            2      // Slave ID for second PIC

#define kNumVectors            16

#define IS_SLAVE_VECTOR(x)     ((x) & 8)

// ICW1
//
#define kPIC_ICW1(x)           ((x) + kPICCmdPortOffset)
#define kPIC_ICW1_MBO          0x10    // must be one
#define kPIC_ICW1_LTIM         0x08    // level/edge triggered mode
#define kPIC_ICW1_ADI          0x04    // 4/8 byte call address interval
#define kPIC_ICW1_SNGL         0x02    // single/cascade mode
#define kPIC_ICW1_IC4          0x01    // ICW4 needed/not needed

// ICW2 - Interrupt vector address (bits 7 - 3).
//
#define kPIC_ICW2(x)           ((x) + kPICDataPortOffset)

// ICW3 - Slave device.
//
#define kPIC_ICW3(x)           ((x) + kPICDataPortOffset)

// ICW4
//
#define kPIC_ICW4(x)           ((x) + kPICDataPortOffset)
#define kPIC_ICW4_SFNM         0x10    // special fully nested mode
#define kPIC_ICW4_BUF          0x08    // buffered mode
#define kPIC_ICW4_MS           0x04    // master/slave
#define kPIC_ICW4_AEOI         0x02    // automatic end of interrupt mode
#define kPIC_ICW4_uPM          0x01    // 8088 (vs. 8085) operation

// OCW1 - Interrupt mask.
//
#define kPIC_OCW1(x)           ((x) + kPICDataPortOffset)

// OCW2 - Bit 4 must be zero.
//
#define kPIC_OCW2(x)           ((x) + kPICCmdPortOffset)
#define kPIC_OCW2_R            0x80    // rotation
#define kPIC_OCW2_SL           0x40    // specific
#define kPIC_OCW2_EOI          0x20
#define kPIC_OCW2_LEVEL(x)     ((x) & 0x07)

// OCW3 - Bit 4 must be zero.
//
#define kPIC_OCW3(x)           ((x) + kPICCmdPortOffset)
#define kPIC_OCW3_ESMM         0x40    // special mask mode
#define kPIC_OCW3_SMM          0x20
#define kPIC_OCW3_MBO          0x08    // must be one
#define kPIC_OCW3_P            0x04    // poll
#define kPIC_OCW3_RR           0x02
#define kPIC_OCW3_RIS          0x01


class AppleIntelClassicPIC : public IOInterruptController
{
    OSDeclareDefaultStructors( AppleIntelClassicPIC );
  
protected:
    volatile UInt16  maskInterrupts;   /* Which interrupts are masked out */
    UInt16           triggerTypes;     /* Interrupt trigger type mask */

    inline int   getTriggerType(long irq)
    {
        return ( triggerTypes & (1 << irq) ) ?
                 kIOInterruptTypeLevel : kIOInterruptTypeEdge;
    }

    inline void  updateMask(long irq)
    {
        if ( IS_SLAVE_VECTOR(irq) )
            outb( kPIC_OCW1(kPIC2BasePort), maskInterrupts >> 8 );
        else
            outb( kPIC_OCW1(kPIC1BasePort), maskInterrupts & 0xff );
    }

    inline void  disableInterrupt(long irq)
    {
        maskInterrupts |= (1 << irq);
        updateMask(irq);
    }

    inline void  enableInterrupt(long irq)
    {
        maskInterrupts &= ~(1 << irq);
        updateMask(irq);
    }

    inline void  ackInterrupt(long irq)
    {
        if ( IS_SLAVE_VECTOR(irq) )
            outb( kPIC_OCW2(kPIC2BasePort), kEOICommand );
        outb( kPIC_OCW2(kPIC1BasePort), kEOICommand );
    }

    virtual void initializePIC(UInt16 port,
                               UInt8  icw1, UInt8  icw2,
                               UInt8  icw3, UInt8  icw4);

public:
	virtual bool start(IOService * provider);
    virtual void free(void);

    // Methods that must be implemented by simplifed interrupt controllers.

    virtual int  getVectorType(long vectorNumber, IOInterruptVector * vector);
	virtual IOInterruptAction getInterruptHandlerAddress(void);
    virtual IOReturn handleInterrupt(void * refCon, IOService * nub, int source);
    virtual bool vectorCanBeShared(long vectorNumber, IOInterruptVector * vector);
    virtual void initVector(long vectorNumber, IOInterruptVector * vector);
    virtual void disableVectorHard(long vectorNumber, IOInterruptVector * vector);
    virtual void enableVector(long vectorNumber, IOInterruptVector * vector);
};

#endif /* ! _IOKIT_APPLEINTELCLASSICPIC_H */
