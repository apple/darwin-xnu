/*
 *  testvmx.h
 *  testkext
 *
 */

#include <IOKit/IOService.h>
#include <IOKit/IOLib.h>

class testvmx : public IOService {
	OSDeclareDefaultStructors(testvmx);

	virtual bool start( IOService * provider );

	virtual void stop( IOService * provider );
};
