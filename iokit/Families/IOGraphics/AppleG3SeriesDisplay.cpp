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
#include <IOKit/graphics/IODisplay.h>
#include <IOKit/ndrvsupport/IOMacOSVideo.h>

#include <Drivers/hidsystem/drvAppleADBDevices/AppleADBButtons.h>

#define kNumber_of_power_states 4
#define kNumber_of_power_levels 32

#define kScreenBit	0x01
#define kPowerOn	0x80
#define kPowerOff	0x00
#define kDisplayOn	kScreenBit | kPowerOn
#define kDisplayOff	kScreenBit | kPowerOff

class AppleG3SeriesDisplay : public AppleSenseDisplay
{
    OSDeclareDefaultStructors(AppleG3SeriesDisplay)

private:
    
int		current_user_brightness;	// 0-31.  The brightness level last selected via the brightness buttons.
int		current_level;		// 0-31.  The current brightness level
IOService *	PMUdriver;		// points to PMU driver
int *		rawTable;		// points to table of raw brightess levels

// the constants used to talk with the pmu:
enum {
    kPMUpower1Read          = 0x19,        // more power status (DBLite)
    kPMUReadBrightness      = 0x49,        // read the brightness value
    kPMUpower1Cntl          = 0x11,        // more power control (DBLite)
    kPMUSetBrightness       = 0x41         // set screen brightness
};

// We need this to callPlatformFunction when sending to sendMiscCommand
typedef struct SendMiscCommandParameterBlock {
    int command;
    IOByteCount sLength;
    UInt8 *sBuffer;
    IOByteCount *rLength;
    UInt8 *rBuffer;
} SendMiscCommandParameterBlock;
typedef SendMiscCommandParameterBlock *SendMiscCommandParameterBlockPtr;

// A simpler way to interface with the pmu SendMiscCommand
IOReturn localSendMiscCommand(int command, IOByteCount sLength, UInt8 *sBuffer, IOByteCount *rLength, UInt8 *rBuffer);

public:
    IOService * probe ( IOService *, SInt32 * );
    virtual void initForPM ( IOService* );
    virtual IOReturn setPowerState ( unsigned long, IOService* );
    virtual unsigned long maxCapabilityForDomainState ( IOPMPowerFlags );
    virtual unsigned long initialPowerStateForDomainState ( IOPMPowerFlags );
    virtual unsigned long powerStateForDomainState ( IOPMPowerFlags );
    virtual void ourButtonHandler ( unsigned int );
    virtual void setBrightness ( long );
};

void upButtonHandler(AppleG3SeriesDisplay *);
void downButtonHandler(AppleG3SeriesDisplay *);


/*
 The actual display panel has 128 power levels.  Copying the MacOS, we only implement 32 of them.
 We further divide the 32 into four IOKit power states which we export to our superclass.

 In the lowest state, the display is off.  This state consists of only one of the 32 power levels, the lowest.
 In the next state it is in the dimmest usable state.  This state also consists of only one of the 32 levels, the second lowest.
 The next state is also dim and consists of seven of the 32 levels.
 The highest state consists of the highest 23 levels.

 The display has no state or configuration or programming that would be saved/restored over power state changes,
 and the driver does not register with the superclass as an interested driver.

 This driver doesn't have much to do.  It changes between the four power state brightnesses on command
 from the superclass, and it raises and lowers the display brightness by one of the 32 brightness levels
 when it receives a brightness-button interrupt from the ADB stack.

 The only smart thing it does is keep track of which of the 32 brightness levels the user has selected by button, and it
  never exceeds that on command from the display device object.  It only raises above that on an brightness-up-button
 interrupt.

  */


static IOPMPowerState ourPowerStates[kNumber_of_power_states] = {
    {1,0,0,0,0,0,0,0,0,0,0,0},
    {1,IOPMDeviceUsable,0,IOPMPowerOn,0,0,0,0,0,0,0,0},
    {1,IOPMDeviceUsable,0,IOPMPowerOn,0,0,0,0,0,0,0,0},
    {1,IOPMDeviceUsable+IOPMMaxPerformance,0,IOPMPowerOn,0,0,0,0,0,0,0,0}
};

static int  max_brightness_level[kNumber_of_power_states] = {0,1,8,31};

static int HooperTable[ ] = {127,71,69,67,65,63,61,59,
                         58,56,54,52,50,48,46,44,
                        42,40,38,37,35,33,31,29,
                        27,25,23,21,19,18,16,14 };

bool ourNotificationHandler( OSObject *, void *, IOService * );

#define super AppleSenseDisplay

OSDefineMetaClassAndStructors(AppleG3SeriesDisplay, AppleSenseDisplay)


// **********************************************************************************
// probe
//
// **********************************************************************************
IOService * AppleG3SeriesDisplay::probe ( IOService * provider, SInt32 * score )
{
    IOFramebuffer *	framebuffer;
    IOService *		ret = 0;
    UInt32			displayType;
    IOIndex		ourIndex;
    
    do {
        if ( 0 == super::probe( provider, score ) ) {
            continue;
        }

        framebuffer =  (IOFramebuffer *)getConnection()->getFramebuffer();	// point to our framebuffer
        ourIndex = getConnection()->getConnection();				// get our connection index on this framebuffer

        if ( kIOReturnSuccess != framebuffer->getAppleSense(ourIndex,NULL,NULL,NULL,&displayType) ) {
            continue;
        }

        if ( !(displayType == kPanelTFTConnect) ) {				// does it have a panel attached?	
            continue;								// no
        }
        ret = this;								// yes, we will control the panel

    } while ( false );
    
    return ( ret );
}

// **********************************************************************************
// localSendMiscCommand
//
// **********************************************************************************
IOReturn AppleG3SeriesDisplay::localSendMiscCommand(int command, IOByteCount sLength, UInt8 *sBuffer, IOByteCount *rLength, UInt8 *rBuffer)
{
    IOReturn returnValue = kIOReturnError;

    // The poupose of this method is to free us from the pain to create a parameter block each time
    // we wish to talk to the pmu:
    SendMiscCommandParameterBlock prmBlock = {command, sLength, sBuffer, rLength, rBuffer};

    IOLog("AppleG3SeriesDisplay::localSendMiscCommand 0x%02x %d 0x%08lx 0x%08lx 0x%08lx\n",
          command, sLength,  sBuffer, rLength, rBuffer);

    if (PMUdriver != NULL) {
        IOLog("AppleG3SeriesDisplay::localSendMiscCommand calling PMUdriver->callPlatformFunction\n");
        returnValue = PMUdriver->callPlatformFunction("sendMiscCommand", true, (void*)&prmBlock, NULL, NULL, NULL);
    }

    // If we are here we do not have a dreive to talk to:
    IOLog("AppleG3SeriesDisplay::localSendMiscCommand end 0x%08lx\n", returnValue);

    return returnValue;
}

// **********************************************************************************
// initForPM
//
// This method overrides the one in IODisplay.h to do PowerBook-only
// power management of the display.
// **********************************************************************************
void AppleG3SeriesDisplay::initForPM ( IOService * provider )
{
    unsigned long		i;

    UInt8       PMUreceiveBuffer[10];	// (I think 1 is enough, but it scares me)
    IOByteCount unused = sizeof(PMUreceiveBuffer); 

    displayPMVars->powerControllable = true;

    PMinit();							// initialize superclass variables

    PMUdriver = waitForService(serviceMatching("ApplePMU"));

    rawTable = HooperTable;

    localSendMiscCommand(kPMUpower1Read,0, NULL, &unused,PMUreceiveBuffer);

    if ( PMUreceiveBuffer[0] & kScreenBit ) {							// is the screen currently on?
        unused = sizeof(PMUreceiveBuffer);
        localSendMiscCommand(kPMUReadBrightness,0, NULL, &unused,PMUreceiveBuffer);	// yes, figure out the brightness
        current_user_brightness = kNumber_of_power_levels - 1;		// ( in case the for-loop doesn't break)
        current_level = kNumber_of_power_levels - 1;

        for ( i = 0; i < kNumber_of_power_levels; i++ ) {
            if ( PMUreceiveBuffer[0] >= rawTable[i] ) {
                current_user_brightness = i;
                current_level = i;
                break;
            }
        }
    }
    else {							// no
        current_user_brightness = 0;
        current_level = 0;
    }

    addNotification( gIOPublishNotification,serviceMatching("AppleADBButtons"),	// look for the button driver
                     (IOServiceNotificationHandler)ourNotificationHandler, this, 0 );
    
    provider->joinPMtree(this);					// attach into the power management hierarchy
    registerPowerDriver(this,ourPowerStates,kNumber_of_power_states);	// register with policy-maker (us)
}


// **********************************************************************************
// ourNotificationHandler
//
// The ADB button driver has appeared.  Tell it we are interested in the
// brightness-up button and the brightness-down button.
// **********************************************************************************
bool ourNotificationHandler( OSObject * us, void * ref, IOService * yourDevice )
{
    if ( yourDevice != NULL ) {
        ((AppleADBButtons *)yourDevice)->registerForButton(kBrightness_up,(IOService *)us,(button_handler)upButtonHandler,true);
        ((AppleADBButtons *)yourDevice)->registerForButton(kBrightness_down,(IOService *)us,(button_handler)downButtonHandler,true);
    }
    return true;
}


// **********************************************************************************
// setPowerState
//
// All power state changes require a call to the PMU driver, which
// blocks the thread till the command completes.
// **********************************************************************************
IOReturn AppleG3SeriesDisplay::setPowerState ( unsigned long powerStateOrdinal, IOService* whatDevice )
{
    UInt8		displayOn = kDisplayOn;
    UInt8		displayOff = kDisplayOff;
    unsigned long	i;

    if ( powerStateOrdinal < kNumber_of_power_states ) {
        if ( powerStateOrdinal > pm_vars->myCurrentState ) {			// raising power
            if ( pm_vars->myCurrentState == 0 ) {					// is it currently off?
    		IOByteCount unused = 0;
                localSendMiscCommand(kPMUpower1Cntl,1, &displayOn, &unused,NULL);
            }
            current_level = max_brightness_level[powerStateOrdinal];
            if ( current_user_brightness < current_level ) {
                current_level = current_user_brightness; 				// don't exceed what the user used to have it at
            }
            setBrightness(current_level);
            							// If we are still higher than we need to be, request a lower state
            for ( i = 0; i < kNumber_of_power_states; i++ ) {		// figure out what state we should be in
                if ( current_level <= max_brightness_level[i] ) {
                    break;
                }
            }
            if ( pm_vars->myCurrentState > i ) {
                changePowerStateToPriv(i);
            }
        }

        if ( powerStateOrdinal < pm_vars->myCurrentState ) {			// lowering power
            if (powerStateOrdinal == 0 ) {							// going all the way off?
    		IOByteCount unused = 0;
                localSendMiscCommand(kPMUpower1Cntl,1, &displayOff, &unused,NULL);	// yes
                current_level = max_brightness_level[powerStateOrdinal];
            }
            else {
                if ( current_level > max_brightness_level[powerStateOrdinal] ) {			// no
                    current_level = max_brightness_level[powerStateOrdinal];
                    setBrightness(current_level);
                }
            }
        }
    }
    return IOPMAckImplied;
}


// **********************************************************************************
// maxCapabilityForDomainState
//
// This simple device needs only power.  If the power domain is supplying
// power, the display can go to its highest state.  If there is no power
// it can only be in its lowest state, which is off.
// **********************************************************************************
unsigned long  AppleG3SeriesDisplay::maxCapabilityForDomainState ( IOPMPowerFlags domainState )
{
    if ( domainState &  IOPMPowerOn ) {
        return kNumber_of_power_states-1;
    }
    return 0;
}


// **********************************************************************************
// initialPowerStateForDomainState
//
// The power domain may be changing state.  If power is on in the new
// state, that will not affect our state at all.  If domain power is off,
// we can attain only our lowest state, which is off.
// **********************************************************************************
unsigned long  AppleG3SeriesDisplay::initialPowerStateForDomainState ( IOPMPowerFlags domainState )
{
   long unsigned i;

   if ( domainState &  IOPMPowerOn ) {		// domain has power
       for ( i = 0; i < kNumber_of_power_states; i++ ) {	// find power state that has our current
           if ( current_level <= max_brightness_level[i] ) {	// brightness level
               return i;
               break;
           }
       }
   }
   return 0;					// domain is down, so display is off
}


// **********************************************************************************
// powerStateForDomainState
//
// The power domain may be changing state.  If power is on in the new
// state, that will not affect our state at all.  If domain power is off,
// we can attain only our lowest state, which is off.
// **********************************************************************************
unsigned long  AppleG3SeriesDisplay::powerStateForDomainState ( IOPMPowerFlags domainState )
{
   long unsigned i;

   if ( domainState &  IOPMPowerOn ) {		// domain has power
       for ( i = 0; i < kNumber_of_power_states; i++ ) {	// find power state that has our current
           if ( current_level <= max_brightness_level[i] ) {	// brightness level
               return i;
           }
       }
   }
   return 0;					// domain is down, so display is off
}


// **********************************************************************************
// upButtonHandler
//
// The display-brightness-up button just went down.
// We are running on a new thread made by the ADB Button driver
// **********************************************************************************
void upButtonHandler(AppleG3SeriesDisplay * us )
{
    ((AppleG3SeriesDisplay *)us)->ourButtonHandler(kBrightness_up);
}


// **********************************************************************************
// downButtonHandler
//
// The display-brightness-down button just went down.
// We are running on a new thread made by the ADB Button driver
// **********************************************************************************
void downButtonHandler(AppleG3SeriesDisplay * us )
{
    ((AppleG3SeriesDisplay *)us)->ourButtonHandler(kBrightness_down);
}


// **********************************************************************************
// ourButtonHandler
//
// Alter the backlight brightness up or down by one increment.
// This involves a call to the PMU driver, which will block the thread.
// **********************************************************************************
void AppleG3SeriesDisplay::ourButtonHandler ( unsigned int keycode )
{								// If we are idle, ignore the button.
    								// The display will be made usable
    if ( ! displayPMVars->displayIdle ) {				// by the DisplayWrangler
        switch (keycode) {
            case kBrightness_up:						// The brightness-up button has just been pressed
                								// We make sure the brightness is not above the maximum
                								// brightness level of our current power state.  If it
               								 // is too high, we ask the device to raise power.
                if (current_level <  max_brightness_level[pm_vars->myCurrentState] ) {
                    current_level++;
                    current_user_brightness = current_level;
                    setBrightness(current_level);
                }
                else {
                    if ( pm_vars->myCurrentState < (kNumber_of_power_states-1) ) {
                        current_user_brightness++;						// increment user's desire
                        if ( changePowerStateToPriv(pm_vars->myCurrentState + 1) != IOPMNoErr ) {		// request higher power
                            current_user_brightness--;						// can't
                        }
                    }
                }
                break;

            case kBrightness_down:					// The brightness-down button has just been pressed
                								// We lower the brightness, and if that takes us into a
                								// lower power state, we tell our parent about it.
                if ( pm_vars->myCurrentState > 0 ) {				// don't lower if in lowest (off) state
                    if ( current_level > 0 ) {
                        current_level--;
                        current_user_brightness = current_level;
                        setBrightness(current_level);
                        if (current_level <=  max_brightness_level[pm_vars->myCurrentState - 1] ) {	// if this takes us into the next lower state
                            changePowerStateToPriv(pm_vars->myCurrentState - 1);			// request lower power
                        }
                    }
                }
                break;
        }
    }
}


// **********************************************************************************
// setBrightness
//
// Instruct PMU to set the display brightness.
// This will block the thread while the command completes.
// **********************************************************************************
void AppleG3SeriesDisplay::setBrightness ( long brightness )
{
    IOByteCount unused = 0;
    UInt8       setBrightnessBuffer;

    setBrightnessBuffer = (UInt8)rawTable[brightness];
    localSendMiscCommand(kPMUSetBrightness,1, &setBrightnessBuffer, &unused,NULL);
}
