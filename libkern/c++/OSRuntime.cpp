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
/*
 * Copyright (c) 1997 Apple Computer, Inc.
 *
 */
#include <libkern/c++/OSMetaClass.h>
#include <libkern/c++/OSLib.h>
#include <libkern/c++/OSSymbol.h>
#include <libkern/c++/OSBoolean.h>

#include <sys/cdefs.h>

__BEGIN_DECLS

#include <string.h>

struct mach_header;

#include <mach/mach_types.h>
#include <mach-o/mach_header.h>
#include <stdarg.h>

#if OSALLOCDEBUG
extern int debug_iomalloc_size;
#endif

struct _mhead {
	size_t	mlen;
	char	dat[0];
};

void *kern_os_malloc(
	size_t		size)
{
	struct _mhead	*mem;
	size_t		memsize = sizeof (*mem) + size ;

	if (size == 0)
		return (0);

	mem = (struct _mhead *)kalloc(memsize);
	if (!mem)
		return (0);

#if OSALLOCDEBUG
	debug_iomalloc_size += memsize;
#endif

	mem->mlen = memsize;
	(void) memset(mem->dat, 0, size);

	return  (mem->dat);
}

void kern_os_free(
	void		*addr)
{
	struct _mhead	*hdr;

	if (!addr)
		return;

	hdr = (struct _mhead *) addr; hdr--;

#if OSALLOCDEBUG
	debug_iomalloc_size -= hdr->mlen;
#endif

#if 0
	memset((vm_offset_t)hdr, 0xbb, hdr->mlen);
#else
	kfree((vm_offset_t)hdr, hdr->mlen);
#endif
}

void *kern_os_realloc(
	void		*addr,
	size_t		nsize)
{
	struct _mhead	*ohdr;
	struct _mhead	*nmem;
	size_t		nmemsize, osize;

	if (!addr)
		return (kern_os_malloc(nsize));

	ohdr = (struct _mhead *) addr; ohdr--;
	osize = ohdr->mlen - sizeof (*ohdr);
	if (nsize == osize)
		return (addr);

	if (nsize == 0) {
		kern_os_free(addr);
		return (0);
	}

	nmemsize = sizeof (*nmem) + nsize ;
	nmem = (struct _mhead *) kalloc(nmemsize);
	if (!nmem){
		kern_os_free(addr);
		return (0);
	}

#if OSALLOCDEBUG
	debug_iomalloc_size += (nmemsize - ohdr->mlen);
#endif

	nmem->mlen = nmemsize;
	if (nsize > osize)
		(void) memset(&nmem->dat[osize], 0, nsize - osize);
	(void) memcpy(nmem->dat, ohdr->dat,
					(nsize > osize) ? osize : nsize);
	kfree((vm_offset_t)ohdr, ohdr->mlen);

	return (nmem->dat);
}

size_t kern_os_malloc_size(
	void		*addr)
{
	struct _mhead	*hdr;

	if (!addr)
		return( 0);

	hdr = (struct _mhead *) addr; hdr--;
	return( hdr->mlen - sizeof (struct _mhead));
}

#if __GNUC__ >= 3
void __cxa_pure_virtual( void )	{ panic(__FUNCTION__); }
#else
void __pure_virtual( void )	{ panic(__FUNCTION__); }
#endif

typedef void (*structor_t)(void);

void OSRuntimeUnloadCPPForSegment(struct segment_command * segment) {

    struct section * section;

    for (section = firstsect(segment);
         section != 0;
         section = nextsect(segment, section)) {

        if (strcmp(section->sectname, "__destructor") == 0) {
            structor_t * destructors = (structor_t *)section->addr;

            if (destructors) {
                int num_destructors = section->size / sizeof(structor_t);

                for (int i = 0; i < num_destructors; i++) {
                    (*destructors[i])();
                }
            } /* if (destructors) */
        } /* if (strcmp...) */
    } /* for (section...) */

    return;
}

void OSRuntimeUnloadCPP(kmod_info_t *ki, void *)
{
    if (ki && ki->address) {

        struct segment_command * segment;
        struct mach_header *header;

	OSSymbol::checkForPageUnload((void *) ki->address,
				     (void *) (ki->address + ki->size));

        header = (struct mach_header *)ki->address;
        segment = firstsegfromheader(header);

        for (segment = firstsegfromheader(header);
             segment != 0;
             segment = nextseg(segment)) {

            OSRuntimeUnloadCPPForSegment(segment);
        }
    }
}

kern_return_t OSRuntimeFinalizeCPP(kmod_info_t *ki, void *)
{
    void *metaHandle;

    if (OSMetaClass::modHasInstance(ki->name)) {
        // @@@ gvdl should have a verbose flag
        printf("Can't unload %s due to -\n", ki->name);
        OSMetaClass::reportModInstances(ki->name);
        return kOSMetaClassHasInstances;
    }

    // Tell the meta class system that we are starting to unload
    metaHandle = OSMetaClass::preModLoad(ki->name);
    OSRuntimeUnloadCPP(ki, 0);	// Do the actual unload
    (void) OSMetaClass::postModLoad(metaHandle);

    return KMOD_RETURN_SUCCESS;
}

// Functions used by the extenTools/kmod library project
kern_return_t OSRuntimeInitializeCPP(kmod_info_t *ki, void *)
{
    struct mach_header *header;
    void *metaHandle;
    bool load_success;
    struct segment_command * segment;
    struct segment_command * failure_segment;

    if (!ki || !ki->address)
        return KMOD_RETURN_FAILURE;
    else
        header = (struct mach_header *) ki->address;

    // Tell the meta class system that we are starting the load
    metaHandle = OSMetaClass::preModLoad(ki->name);
    assert(metaHandle);
    if (!metaHandle)
        return KMOD_RETURN_FAILURE;

    load_success = true;
    failure_segment = 0;

   /* Scan the header for all sections named "__constructor", in any
    * segment, and invoke the constructors within those sections.
    */
    for (segment = firstsegfromheader(header);
         segment != 0 && load_success;
         segment = nextseg(segment)) {

        struct section * section;

       /* Record the current segment in the event of a failure.
        */
        failure_segment = segment;

        for (section = firstsect(segment);
             section != 0 && load_success;
             section = nextsect(segment, section)) {

            if (strcmp(section->sectname, "__constructor") == 0) {
                structor_t * constructors = (structor_t *)section->addr;

                if (constructors) {
                    // FIXME: can we break here under the assumption that
                    // section names are unique within a segment?

                    int num_constructors = section->size / sizeof(structor_t);
                    int hit_null_constructor = 0;

                    for (int i = 0;
                         i < num_constructors &&
                         OSMetaClass::checkModLoad(metaHandle);
                         i++) {

                        if (constructors[i]) {
                            (*constructors[i])();
                        } else if (!hit_null_constructor) {
                            hit_null_constructor = 1;
                            printf("Error! Null constructor in segment %s.\n",
                                section->segname);
                        }
                    }
                    load_success = OSMetaClass::checkModLoad(metaHandle);

                } /* if (constructors) */
            } /* if (strcmp...) */
        } /* for (section...) */
    } /* for (segment...) */


    // We failed so call all of the destructors
    if (!load_success) {

       /* Scan the header for all sections named "__constructor", in any
        * segment, and invoke the constructors within those sections.
        */
        for (segment = firstsegfromheader(header);
             segment != failure_segment && segment != 0;
             segment = nextseg(segment)) {

            OSRuntimeUnloadCPPForSegment(segment);

        } /* for (segment...) */
    }

    return OSMetaClass::postModLoad(metaHandle);
}

static KMOD_LIB_DECL(__kernel__, 0);
void OSlibkernInit(void)
{
    vm_address_t *headerArray = (vm_address_t *) getmachheaders();

    KMOD_INFO_NAME.address = headerArray[0]; assert(!headerArray[1]);
    if (kOSReturnSuccess != OSRuntimeInitializeCPP(&KMOD_INFO_NAME, 0))
        panic("OSRuntime: C++ runtime failed to initialize");

    OSBoolean::initialize();
}

__END_DECLS

void * operator new( size_t size)
{
    void * result;

    result = (void *) kern_os_malloc( size);
    if( result)
	bzero( result, size);
    return( result);
}

void operator delete( void * addr)
{
    kern_os_free( addr);
}

