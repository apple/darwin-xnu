/*
 *  DINetBootHook.c
 *  DiskImages
 *
 *  Created by Byron Han on Sat Apr 13 2002.
 *  Copyright (c) 2002 Apple Computer, Inc. All rights reserved.
 *
 *	Revision History
 *
 *	$Log: DINetBootHook.cpp,v $
 *	Revision 1.3  2002/06/16 20:36:02  lindak
 *	Merged PR-2957314 into Jaguar (siegmund: netboot kernel code needs to set
 *	com.apple.AppleDiskImageController.load to boolean Yes)
 *
 *	Revision 1.2.40.2  2002/06/15 03:50:38  dieter
 *	- corrected com.apple.AppleDiskImageController.load string
 *	
 *	Revision 1.2.40.1  2002/06/15 03:01:08  dieter
 *	Bug #: 2957314
 *	- add call to force IOHDIXController to get loaded/matched
 *	
 *	Revision 1.2  2002/05/03 18:08:39  lindak
 *	Merged PR-2909558 into Jaguar (siegmund POST WWDC: add support for NetBoot
 *	over IOHDIXController)
 *	
 *	Revision 1.1.2.1  2002/04/24 22:29:12  dieter
 *	Bug #: 2909558
 *	- added IOHDIXController netboot stubs
 *	
 *	Revision 1.3  2002/04/16 00:41:37  han
 *	migrated code out of here to IOHDIXController's setProperty method
 *	
 *	Revision 1.2  2002/04/14 23:53:53  han
 *	eliminate qDEBUG=1, use emums instead of hard coded string constants
 *	
 *	Revision 1.1  2002/04/14 22:54:42  han
 *	Renamed from DINetBookHook.c.
 *	First stab at implementing this code.
 *	
 *	Revision 1.1  2002/04/13 19:22:28  han
 *	added stub file DINetBookHook.c
 *	
 *
 */
#ifndef qDEBUG
#define qDEBUG 0
#endif

#if qDEBUG
#warning qDEBUG is 1!
#endif

#include <sys/types.h>
#include <IOKit/IOService.h>
#include <IOKit/IOLib.h>

#define	kIOHDIXControllerClassName	"IOHDIXController"
#define	kDIRootImageKey				"di-root-image"
#define	kDIRootImageResultKey		"di-root-image-result"
#define	kDIRootImageDevNameKey		"di-root-image-devname"
#define	kDIRootImageDevTKey			"di-root-image-devt"

extern "C" {
/*
	Name:		di_root_image 
	Function:	mount the disk image returning the dev node
	Parameters:	path	->		path/url to disk image
				devname	<-		dev node used to set the rootdevice global variable
				dev_p	<-		device number generated from major/minor numbers
	Comments:	
*/
int di_root_image(const char *path, char devname[], dev_t *dev_p)
{
	IOReturn			res 				= 0;
	OSIterator		*	controllerIterator 	= 0;
	OSDictionary 	*	matchDictionary 	= 0;
	IOService		*	controller			= 0;
	OSString		*	pathString			= 0;
	OSNumber		*	myResult			= 0;
	OSString		*	myDevName			= 0;
	OSNumber		*	myDevT				= 0;
	
	// sanity check arguments please
	if (devname)		*devname = 0;
	if (dev_p)			*dev_p = 0;
	
	if (!path) 			return kIOReturnBadArgument;
	if (!devname) 		return kIOReturnBadArgument;
	if (!dev_p) 		return kIOReturnBadArgument;

	(void)IOService::getResourceService()->publishResource("com.apple.AppleDiskImageController.load", kOSBooleanTrue);
	IOService::getResourceService()->waitQuiet();

	// first find IOHDIXController
	matchDictionary = IOService::serviceMatching(kIOHDIXControllerClassName);
	if (!matchDictionary) {
		res = kIOReturnNoMemory;
		goto serviceMatching_FAILED;
	}
	
	controllerIterator = IOService::getMatchingServices(matchDictionary);
	if (!controllerIterator) {
		res = kIOReturnNoMemory;
		goto getMatchingServices_FAILED;
	}

	// use the "setProperty" method of IOHDIXController to trigger the desired behaviour
	controller = OSDynamicCast(IOService, controllerIterator->getNextObject());
	if (!controller) {
		res = kIOReturnNotFound;
		goto NoIOHDIXController;
	}
	
	// okay create path object
	pathString = OSString::withCString(path);
	if (!pathString) {
		res = kIOReturnNoMemory;
		goto CannotCreatePathOSString;
	}
	
	// do it
	if (!controller->setProperty(kDIRootImageKey, pathString))
		IOLog("IOHDIXController::setProperty(%s, %s) failed.\n", kDIRootImageKey, pathString->getCStringNoCopy());
	
	myResult = OSDynamicCast(OSNumber, controller->getProperty(kDIRootImageResultKey));
	res = kIOReturnError;
	if (myResult)
		res = myResult->unsigned32BitValue();
		
	if (res) {
		IOLog("%s is 0x%08X/%d\n", kDIRootImageResultKey, res, res);
		goto di_root_image_FAILED;
	}

	// success - grab 
	myDevT = OSDynamicCast(OSNumber, controller->getProperty(kDIRootImageDevTKey));
	if (myDevT)
		*dev_p = myDevT->unsigned32BitValue();
	else {
		IOLog("could not get %s\n", kDIRootImageDevTKey);
		res = kIOReturnError;
		goto di_root_image_FAILED;
	}
		
	myDevName = OSDynamicCast(OSString, controller->getProperty(kDIRootImageDevNameKey));
	if (myDevName)
		strcpy(devname, myDevName->getCStringNoCopy());
	else {
		IOLog("could not get %s\n", kDIRootImageDevNameKey);
		res = kIOReturnError;
		goto di_root_image_FAILED;
	}
		

di_root_image_FAILED:
CannotCreatePathOSString:
serviceMatching_FAILED:
NoIOHDIXController:
getMatchingServices_FAILED:

	// clean up memory allocations
	if (pathString)			pathString->release();
	if (matchDictionary)	matchDictionary->release();
	if (controllerIterator)	controllerIterator->release();

	return res;
}

};
