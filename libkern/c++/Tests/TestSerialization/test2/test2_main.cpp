/*
 * Copyright (c) 2000 Apple Computer, Inc. All rights reserved.
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

char *testBuffer = "
 <?xml version=\"1.0\" encoding=\"UTF-8\"?>
 <!DOCTYPE plist SYSTEM \"file://localhost/System/Library/DTDs/PropertyList.dtd\">
 <plist version=\"0.9\">
 <dict>

 <key>key true</key>	<true/>
 <key>key false</key>	<false/>

 <key>key d0</key>	<data> </data>
 <key>key d1</key>	<data>AQ==</data>
 <key>key d2</key>	<data>ASM=</data>
 <key>key d3</key>	<data>ASNF</data>
 <key>key d4</key>	<data format=\"hex\">0123 4567 89abcdef</data>
 <key>key d5</key>	<data ID=\"1\">ASNFZw==</data>

 <key>key i0</key>	<integer></integer>
 <key>key i1</key>	<integer>123456789</integer>
 <key>key i2</key>	<integer size=\"32\" ID=\"2\">0x12345678</integer>

 <key>key s0</key>	<string></string>
 <key>key s1</key>	<string>string 1</string>
 <key>key s2</key>	<string ID=\"3\">string 2</string>
 <key>key &lt;&amp;&gt;</key>	<string>&lt;&amp;&gt;</string>

 <key>key c0</key>	<dict ID=\"4\">
                        </dict>

 <key>key a0</key>	<array>
                        </array>

 <key>key a1</key>	<array ID=\"5\">
                            <string>array string 1</string>
                            <string>array string 2</string>
                        </array>

 <key>key t0</key>	<set>
                        </set>
 <key>key t1</key>	<set ID=\"6\">
                             <string>set string 1</string>
                             <string>set string 2</string>
                         </set>

 <key>key r1</key>	<ref IDREF=\"1\"/>
 <key>key r2</key>	<ref IDREF=\"2\"/>
 <key>key r3</key>	<ref IDREF=\"3\"/>
 <key>key r4</key>	<ref IDREF=\"4\"/>
 <key>key r5</key>	<ref IDREF=\"5\"/>
 <key>key r6</key>	<ref IDREF=\"6\"/>

 <key>key e1</key>	<array/>
 <key>key e2</key>	<dict/>
 <key>key e3</key>	<set/>
 <key>key e4</key>	<integer/>
 <key>key e5</key>	<string/>
 <key>key e6</key>	<data/>

 </dict>
 </plist>
";

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
