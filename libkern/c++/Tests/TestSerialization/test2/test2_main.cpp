/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
 *
 * @APPLE_OSREFERENCE_LICENSE_HEADER_START@
 * 
 * This file contains Original Code and/or Modifications of Original Code
 * as defined in and that are subject to the Apple Public Source License
 * Version 2.0 (the 'License'). You may not use this file except in
 * compliance with the License. The rights granted to you under the License
 * may not be used to create, or enable the creation or redistribution of,
 * unlawful or unlicensed copies of an Apple operating system, or to
 * circumvent, violate, or enable the circumvention or violation of, any
 * terms of an Apple operating system software license agreement.
 * 
 * Please obtain a copy of the License at
 * http://www.opensource.apple.com/apsl/ and read it before using this file.
 * 
 * The Original Code and all software distributed under the License are
 * distributed on an 'AS IS' basis, WITHOUT WARRANTY OF ANY KIND, EITHER
 * EXPRESS OR IMPLIED, AND APPLE HEREBY DISCLAIMS ALL SUCH WARRANTIES,
 * INCLUDING WITHOUT LIMITATION, ANY WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE, QUIET ENJOYMENT OR NON-INFRINGEMENT.
 * Please see the License for the specific language governing rights and
 * limitations under the License.
 * 
 * @APPLE_OSREFERENCE_LICENSE_HEADER_END@
 */
#include <libkern/OSBase.h>

__BEGIN_DECLS
#include <mach/mach_types.h>
#include <mach/vm_types.h>
#include <mach/kmod.h>

kmod_start_func_t test2_start;
kmod_stop_func_t test2_stop;
__END_DECLS

#include <libkern/c++/OSContainers.h>
#include <iokit/IOLib.h>

char *testBuffer = 
" <?xml version=\"1.0\" encoding=\"UTF-8\"?> \n"
" <!DOCTYPE plist SYSTEM \"file://localhost/System/Library/DTDs/PropertyList.dtd\"> \n"
" <plist version=\"1.0\"> \n"
" <!DOCTYPE plist PUBLIC \"-//Apple Computer//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\"> \n"
" <plist version=\"0.9\"> \n"
" <dict> \n"

" <key>key true</key>	<true/> \n"
" <key>key false</key>	<false/> \n"

" <key>key d0</key>	<data> </data> \n"
" <key>key d1</key>	<data>AQ==</data> \n"
" <key>key d2</key>	<data>ASM=</data> \n"
" <key>key d3</key>	<data>ASNF</data> \n"
" <key>key d4</key>	<data ID=\"1\">ASNFZw==</data> \n"

" <key>key i0</key>	<integer></integer> \n"
" <key>key i1</key>	<integer>123456789</integer> \n"
" <key>key i2</key>	<integer>-123456789</integer> \n"
" <key>key i3</key>	<integer size=\"32\" ID=\"2\">0x12345678</integer> \n"

" <key>key s0</key>	<string></string> \n"
" <key>key s1</key>	<string>string 1</string> \n"
" <key>key s2</key>	<string ID=\"3\">string 2</string> \n"
" <key>key mr ©</key>	<string>mac roman copyright ©</string> \n"
" <key>key uft8 \xc2\xa9</key>	<string>utf-8 copyright \xc2\xa9</string> \n"
" <key>key &lt;&amp;&gt;</key>	<string>&lt;&amp;&gt;</string> \n"

" <key>key D0</key>	<dict ID=\"4\"> \n"
"                        </dict> \n"

" <key>key a0</key>	<array> \n"
"                        </array> \n"

" <key>key a1</key>	<array ID=\"5\"> \n"
"                            <string>array string 1</string> \n"
"                            <string>array string 2</string> \n"
"                        </array> \n"

" <key>key r1</key>	<ref IDREF=\"1\"/> \n"
" <key>key r2</key>	<ref IDREF=\"2\"/> \n"
" <key>key r3</key>	<ref IDREF=\"3\"/> \n"
" <key>key r4</key>	<ref IDREF=\"4\"/> \n"
" <key>key r5</key>	<ref IDREF=\"5\"/> \n"

" <key>key e1</key>	<array/> \n"
" <key>key e2</key>	<dict/> \n"
" <key>key e4</key>	<integer/> \n"
" <key>key e5</key>	<string/> \n"
" <key>key e6</key>	<data/> \n"

" <key>key S0</key>	<set> \n"
"                        </set> \n"
" <key>key S1</key>	<set ID=\"6\"> \n"
"                             <string>set string 1</string> \n"
"                             <string>set string 2</string> \n"
"                         </set> \n"
" <key>key r6</key>	<ref IDREF=\"6\"/> \n"
" <key>key e3</key>	<set/> \n"

" </dict> \n"
" </plist> \n"
;

/*
 this causes the parser to return an empty string? it doesn't look like yyerror gets called
 char *testBuffer = "<array ID=1><array IDREF=\"1\"/></array>"
 
*/

kern_return_t
test2_start(struct kmod_info *ki, void *data)
{
        IOLog("test buffer start:\n%s\n:test buffer end.\n", testBuffer);

	// test unserialize
	OSString *errmsg = 0;
	OSObject *d = OSUnserializeXML(testBuffer, &errmsg);
	if (!d) {
                if (errmsg)
                    IOLog("%s\n", errmsg->getCStringNoCopy());
                else
                    IOLog("bogus error message\n");
            
		return KMOD_RETURN_SUCCESS;
	}
        
	// test serialize
	OSSerialize *s = OSSerialize::withCapacity(5);
	if (!d->serialize(s)) {
		IOLog("serialization failed\n");
                return KMOD_RETURN_SUCCESS;
	}

	IOLog("serialized object's length = %d, capacity = %d\n", s->getLength(), s->getCapacity());
	IOLog("object unformatted = %s\n", s->text());

	// try second time
	OSObject *d2 = OSUnserializeXML(s->text(), &errmsg);
	if (!d2) {
		IOLog("%s\n", errmsg->getCStringNoCopy());
                return KMOD_RETURN_SUCCESS;
	}
	OSSerialize *s2 = OSSerialize::withCapacity(5);
	if (!d2->serialize(s2)) {
		IOLog("serialization #2 failed\n");
                return KMOD_RETURN_SUCCESS;
	}

	IOLog("serialized object's length = %d, capacity = %d\n", 
		s2->getLength(), s2->getCapacity());
	IOLog("object unformatted = %s\n", s2->text());

	IOLog("\nserialized objects compared %ssuccessfully textually\n\n",
	       strcmp(s->text(), s2->text()) ? "un":""); 

	IOLog("\nserialized objects compared %ssuccessfully objectwise\n\n",
	       d->isEqualTo(d2) ? "":"un"); 

	s2->release();
	if (d2) d2->release();
	s->release();
	if (d) d->release();

        return KMOD_RETURN_SUCCESS;
}

kern_return_t
test2_stop(struct kmod_info *ki, void *data)
{
        return KMOD_RETURN_SUCCESS;
}
