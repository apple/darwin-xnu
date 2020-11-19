/*
 * Copyright (c) 2000,2008-2009 Apple Inc. All rights reserved.
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
/*
 * Copyright (c) 1997 Apple Inc.
 *
 */
#include <libkern/c++/OSMetaClass.h>
#include <libkern/c++/OSKext.h>
#include <libkern/c++/OSLib.h>
#include <libkern/c++/OSSymbol.h>
#include <IOKit/IOKitDebug.h>

#include <sys/cdefs.h>
#if defined(HAS_APPLE_PAC)
#include <ptrauth.h>
#define PTRAUTH_STRIP_STRUCTOR(x)       ((uintptr_t) ptrauth_strip(ptrauth_nop_cast(void *, (x)), ptrauth_key_function_pointer))
#else  /* defined(HAS_APPLE_PAC) */
#define PTRAUTH_STRIP_STRUCTOR(x)       ((uintptr_t) (x))
#endif /* !defined(HAS_APPLE_PAC) */

__BEGIN_DECLS

#include <string.h>
#include <mach/mach_types.h>
#include <libkern/kernel_mach_header.h>
#include <libkern/prelink.h>
#include <stdarg.h>

#if KASAN
#include <san/kasan.h>
#endif

#if PRAGMA_MARK
#pragma mark Constants &c.
#endif /* PRAGMA_MARK */
OSKextLogSpec kOSRuntimeLogSpec =
    kOSKextLogErrorLevel |
    kOSKextLogLoadFlag |
    kOSKextLogKextBookkeepingFlag;

#if PRAGMA_MARK
#pragma mark Logging Bootstrap
#endif /* PRAGMA_MARK */
/*********************************************************************
* kern_os Logging Bootstrap
*
* We can't call in to OSKext until the kernel's C++ environment is up
* and running, so let's mask those references with a check variable.
* We print unconditionally if C++ isn't up, but if that's the case
* we've generally hit a serious error in kernel init!
*********************************************************************/
static bool gKernelCPPInitialized = false;

#define OSRuntimeLog(kext, flags, format, args ...)            \
    do {                                                      \
	if (gKernelCPPInitialized) {                          \
	    OSKextLog((kext), (flags), (format), ## args);  \
	} else {                                              \
	    printf((format), ## args);                        \
	}                                                     \
    } while (0)

#if PRAGMA_MARK
#pragma mark Libkern Init
#endif /* PRAGMA_MARK */
/*********************************************************************
* Libkern Init
*********************************************************************/

#if __GNUC__ >= 3
void __dead2
__cxa_pure_virtual( void )
{
	panic("%s", __FUNCTION__);
}
#else
void __dead2
__pure_virtual( void )
{
	panic("%s", __FUNCTION__);
}
#endif

extern lck_grp_t * IOLockGroup;
extern kmod_info_t g_kernel_kmod_info;

enum {
	kOSSectionNamesDefault     = 0,
	kOSSectionNamesBuiltinKext = 1,
	kOSSectionNamesCount       = 2,
};
enum {
	kOSSectionNameInitializer = 0,
	kOSSectionNameFinalizer   = 1,
	kOSSectionNameCount       = 2
};

static const char *
    gOSStructorSectionNames[kOSSectionNamesCount][kOSSectionNameCount] = {
	{ SECT_MODINITFUNC, SECT_MODTERMFUNC },
	{ kBuiltinInitSection, kBuiltinTermSection }
};

void
OSlibkernInit(void)
{
	// This must be called before calling OSRuntimeInitializeCPP.
	OSMetaClassBase::initialize();

	g_kernel_kmod_info.address = (vm_address_t) &_mh_execute_header;
	if (kOSReturnSuccess != OSRuntimeInitializeCPP(NULL)) {
		// &g_kernel_kmod_info, gOSSectionNamesStandard, 0, 0)) {
		panic("OSRuntime: C++ runtime failed to initialize.");
	}

	gKernelCPPInitialized = true;

	return;
}

__END_DECLS

#if PRAGMA_MARK
#pragma mark C++ Runtime Load/Unload
#endif /* PRAGMA_MARK */
/*********************************************************************
* kern_os C++ Runtime Load/Unload
*********************************************************************/

typedef void (*structor_t)(void);

static bool
OSRuntimeCallStructorsInSection(
	OSKext                   * theKext,
	kmod_info_t              * kmodInfo,
	void                     * metaHandle,
	kernel_segment_command_t * segment,
	const char               * sectionName,
	uintptr_t                  textStart,
	uintptr_t                  textEnd)
{
	kernel_section_t * section;
	bool result = TRUE;

	for (section = firstsect(segment);
	    section != NULL;
	    section = nextsect(segment, section)) {
		if (strncmp(section->sectname, sectionName, sizeof(section->sectname) - 1)) {
			continue;
		}
		if (section->size == 0) {
			continue;
		}

		structor_t * structors = (structor_t *)section->addr;
		if (!structors) {
			continue;
		}

		structor_t structor;
		uintptr_t value;
		unsigned long num_structors = section->size / sizeof(structor_t);
		unsigned int hit_null_structor = 0;
		unsigned long firstIndex = 0;

		if (textStart) {
			// bsearch for any in range
			unsigned long baseIdx;
			unsigned long lim;
			firstIndex = num_structors;
			for (lim = num_structors, baseIdx = 0; lim; lim >>= 1) {
				structor = structors[baseIdx + (lim >> 1)];
				if (!structor) {
					panic("%s: null structor", kmodInfo->name);
				}
				value = PTRAUTH_STRIP_STRUCTOR(structor);
				if ((value >= textStart) && (value < textEnd)) {
					firstIndex = (baseIdx + (lim >> 1));
					// scan back for the first in range
					for (; firstIndex; firstIndex--) {
						structor = structors[firstIndex - 1];
						value = PTRAUTH_STRIP_STRUCTOR(structor);
						if ((value < textStart) || (value >= textEnd)) {
							break;
						}
					}
					break;
				}
				if (textStart > value) {
					// move right
					baseIdx += (lim >> 1) + 1;
					lim--;
				}
				// else move left
			}
			baseIdx = (baseIdx + (lim >> 1));
		}
		for (;
		    (firstIndex < num_structors)
		    && (!metaHandle || OSMetaClass::checkModLoad(metaHandle));
		    firstIndex++) {
			if ((structor = structors[firstIndex])) {
				value = PTRAUTH_STRIP_STRUCTOR(structor);
				if ((textStart && (value < textStart))
				    || (textEnd && (value >= textEnd))) {
					break;
				}
				(*structor)();
			} else if (!hit_null_structor) {
				hit_null_structor = 1;
				OSRuntimeLog(theKext, kOSRuntimeLogSpec,
				    "Null structor in kext %s segment %s!",
				    kmodInfo->name, section->segname);
			}
		}
		if (metaHandle) {
			result = OSMetaClass::checkModLoad(metaHandle);
		}
		break;
	} /* for (section...) */
	return result;
}

/*********************************************************************
*********************************************************************/
kern_return_t
OSRuntimeFinalizeCPP(
	OSKext                   * theKext)
{
	kern_return_t              result = KMOD_RETURN_FAILURE;
	void                     * metaHandle = NULL;// do not free
	kernel_mach_header_t     * header;
	kernel_segment_command_t * segment;
	kmod_info_t              * kmodInfo;
	const char              ** sectionNames;
	uintptr_t                  textStart;
	uintptr_t                  textEnd;

	textStart    = 0;
	textEnd      = 0;
	sectionNames = gOSStructorSectionNames[kOSSectionNamesDefault];
	if (theKext) {
		if (!theKext->isCPPInitialized()) {
			result = KMOD_RETURN_SUCCESS;
			goto finish;
		}
		kmodInfo = theKext->kmod_info;
		if (!kmodInfo || !kmodInfo->address) {
			result = kOSKextReturnInvalidArgument;
			goto finish;
		}
		header = (kernel_mach_header_t *)kmodInfo->address;
		if (theKext->flags.builtin) {
			header       = (kernel_mach_header_t *)g_kernel_kmod_info.address;
			textStart    = kmodInfo->address;
			textEnd      = textStart + kmodInfo->size;
			sectionNames = gOSStructorSectionNames[kOSSectionNamesBuiltinKext];
		}
	} else {
		kmodInfo = &g_kernel_kmod_info;
		header   = (kernel_mach_header_t *)kmodInfo->address;
	}

	/* OSKext checks for this condition now, but somebody might call
	 * this function directly (the symbol is exported....).
	 */
	if (OSMetaClass::modHasInstance(kmodInfo->name)) {
		// xxx - Don't log under errors? this is more of an info thing
		OSRuntimeLog(theKext, kOSRuntimeLogSpec,
		    "Can't tear down kext %s C++; classes have instances:",
		    kmodInfo->name);
		OSKext::reportOSMetaClassInstances(kmodInfo->name, kOSRuntimeLogSpec);
		result = kOSMetaClassHasInstances;
		goto finish;
	}

	/* Tell the meta class system that we are starting to unload.
	 * metaHandle isn't actually needed on the finalize path,
	 * so we don't check it here, even though OSMetaClass::postModLoad() will
	 * return a failure (it only does actual work on the init path anyhow).
	 */
	metaHandle = OSMetaClass::preModLoad(kmodInfo->name);

	OSSymbol::checkForPageUnload((void *)kmodInfo->address,
	    (void *)(kmodInfo->address + kmodInfo->size));

	header = (kernel_mach_header_t *)kmodInfo->address;
	segment = firstsegfromheader(header);

	for (segment = firstsegfromheader(header);
	    segment != NULL;
	    segment = nextsegfromheader(header, segment)) {
		OSRuntimeCallStructorsInSection(theKext, kmodInfo, NULL, segment,
		    sectionNames[kOSSectionNameFinalizer], textStart, textEnd);
	}

	(void)OSMetaClass::postModLoad(metaHandle);

	if (theKext) {
		theKext->setCPPInitialized(false);
	}
	result = KMOD_RETURN_SUCCESS;
finish:
	return result;
}

#if defined(HAS_APPLE_PAC)
static inline void
OSRuntimeSignStructorsInSegment(kernel_segment_command_t *segment)
{
	kernel_section_t         * section;
	structor_t               * structors;
	volatile structor_t                 structor;
	size_t                     idx, num_structors;

	for (section = firstsect(segment);
	    section != NULL;
	    section = nextsect(segment, section)) {
		if ((S_MOD_INIT_FUNC_POINTERS != (SECTION_TYPE & section->flags))
		    && (S_MOD_TERM_FUNC_POINTERS != (SECTION_TYPE & section->flags))) {
			continue;
		}
		structors = (structor_t *)section->addr;
		if (!structors) {
			continue;
		}
		num_structors = section->size / sizeof(structor_t);
		for (idx = 0; idx < num_structors; idx++) {
			structor = structors[idx];
			if (NULL == structor) {
				continue;
			}
			structor = ptrauth_strip(structor, ptrauth_key_function_pointer);
			structor = ptrauth_sign_unauthenticated(structor, ptrauth_key_function_pointer, ptrauth_function_pointer_type_discriminator(void (*)(void)));
			structors[idx] = structor;
		}
	} /* for (section...) */
}
#endif

/*********************************************************************
*********************************************************************/
void
OSRuntimeSignStructors(
	kernel_mach_header_t * header __unused)
{
#if defined(HAS_APPLE_PAC)

	kernel_segment_command_t * segment;

	for (segment = firstsegfromheader(header);
	    segment != NULL;
	    segment = nextsegfromheader(header, segment)) {
		OSRuntimeSignStructorsInSegment(segment);
	} /* for (segment...) */
#endif /* !defined(XXX) && defined(HAS_APPLE_PAC) */
}

/*********************************************************************
*********************************************************************/
void
OSRuntimeSignStructorsInFileset(
	kernel_mach_header_t * fileset_header __unused)
{
#if defined(HAS_APPLE_PAC)
	struct load_command *lc;

	lc = (struct load_command *)((uintptr_t)fileset_header + sizeof(*fileset_header));
	for (uint32_t i = 0; i < fileset_header->ncmds; i++,
	    lc = (struct load_command *)((uintptr_t)lc + lc->cmdsize)) {
		if (lc->cmd == LC_FILESET_ENTRY) {
			struct fileset_entry_command *fse;
			kernel_mach_header_t *mh;

			fse = (struct fileset_entry_command *)(uintptr_t)lc;
			mh = (kernel_mach_header_t *)((uintptr_t)fse->vmaddr);
			OSRuntimeSignStructors(mh);
		} else if (lc->cmd == LC_SEGMENT_64) {
			/*
			 * Slide/adjust all LC_SEGMENT_64 commands in the fileset
			 * (and any sections in those segments)
			 */
			kernel_segment_command_t *seg;
			seg = (kernel_segment_command_t *)(uintptr_t)lc;
			OSRuntimeSignStructorsInSegment(seg);
		}
	}

#endif /* defined(HAS_APPLE_PAC) */
}

/*********************************************************************
*********************************************************************/
kern_return_t
OSRuntimeInitializeCPP(
	OSKext                   * theKext)
{
	kern_return_t              result          = KMOD_RETURN_FAILURE;
	kernel_mach_header_t     * header          = NULL;
	void                     * metaHandle      = NULL;// do not free
	bool                       load_success    = true;
	kernel_segment_command_t * segment         = NULL;// do not free
	kernel_segment_command_t * failure_segment = NULL; // do not free
	kmod_info_t             *  kmodInfo;
	const char              ** sectionNames;
	uintptr_t                  textStart;
	uintptr_t                  textEnd;

	textStart    = 0;
	textEnd      = 0;
	sectionNames = gOSStructorSectionNames[kOSSectionNamesDefault];
	if (theKext) {
		if (theKext->isCPPInitialized()) {
			result = KMOD_RETURN_SUCCESS;
			goto finish;
		}

		kmodInfo = theKext->kmod_info;
		if (!kmodInfo || !kmodInfo->address) {
			result = kOSKextReturnInvalidArgument;
			goto finish;
		}
		header = (kernel_mach_header_t *)kmodInfo->address;

		if (theKext->flags.builtin) {
			header       = (kernel_mach_header_t *)g_kernel_kmod_info.address;
			textStart    = kmodInfo->address;
			textEnd      = textStart + kmodInfo->size;
			sectionNames = gOSStructorSectionNames[kOSSectionNamesBuiltinKext];
		}
	} else {
		kmodInfo = &g_kernel_kmod_info;
		header   = (kernel_mach_header_t *)kmodInfo->address;
	}

	/* Tell the meta class system that we are starting the load
	 */
	metaHandle = OSMetaClass::preModLoad(kmodInfo->name);
	assert(metaHandle);
	if (!metaHandle) {
		goto finish;
	}

	/* NO GOTO PAST HERE. */

	/* Scan the header for all constructor sections, in any
	 * segment, and invoke the constructors within those sections.
	 */
	for (segment = firstsegfromheader(header);
	    segment != NULL && load_success;
	    segment = nextsegfromheader(header, segment)) {
		/* Record the current segment in the event of a failure.
		 */
		failure_segment = segment;
		load_success = OSRuntimeCallStructorsInSection(
			theKext, kmodInfo, metaHandle, segment,
			sectionNames[kOSSectionNameInitializer],
			textStart, textEnd);
	} /* for (segment...) */

	/* We failed so call all of the destructors. We must do this before
	 * calling OSMetaClass::postModLoad() as the OSMetaClass destructors
	 * will alter state (in the metaHandle) used by that function.
	 */
	if (!load_success) {
		/* Scan the header for all destructor sections, in any
		 * segment, and invoke the constructors within those sections.
		 */
		for (segment = firstsegfromheader(header);
		    segment != failure_segment && segment != NULL;
		    segment = nextsegfromheader(header, segment)) {
			OSRuntimeCallStructorsInSection(theKext, kmodInfo, NULL, segment,
			    sectionNames[kOSSectionNameFinalizer], textStart, textEnd);
		} /* for (segment...) */
	}

	/* Now, regardless of success so far, do the post-init registration
	 * and cleanup. If we had to call the unloadCPP function, static
	 * destructors have removed classes from the stalled list so no
	 * metaclasses will actually be registered.
	 */
	result = OSMetaClass::postModLoad(metaHandle);

	/* If we've otherwise been fine up to now, but OSMetaClass::postModLoad()
	 * fails (typically due to a duplicate class), tear down all the C++
	 * stuff from the kext. This isn't necessary for libkern/OSMetaClass stuff,
	 * but may be necessary for other C++ code. We ignore the return value
	 * because it's only a fail when there are existing instances of libkern
	 * classes, and there had better not be any created on the C++ init path.
	 */
	if (load_success && result != KMOD_RETURN_SUCCESS) {
		(void)OSRuntimeFinalizeCPP(theKext); //kmodInfo, sectionNames, textStart, textEnd);
	}

	if (theKext && load_success && result == KMOD_RETURN_SUCCESS) {
		theKext->setCPPInitialized(true);
	}
finish:
	return result;
}

/*********************************************************************
*   Unload a kernel segment.
*********************************************************************/

void
OSRuntimeUnloadCPPForSegment(
	kernel_segment_command_t * segment)
{
	OSRuntimeCallStructorsInSection(NULL, &g_kernel_kmod_info, NULL, segment,
	    gOSStructorSectionNames[kOSSectionNamesDefault][kOSSectionNameFinalizer], 0, 0);
}

#if PRAGMA_MARK
#pragma mark C++ Allocators & Deallocators
#endif /* PRAGMA_MARK */
/*********************************************************************
* C++ Allocators & Deallocators
*********************************************************************/
void *
operator new(size_t size)
{
	assert(size);
	return kheap_alloc_tag_bt(KERN_OS_MALLOC, size,
	           (zalloc_flags_t) (Z_WAITOK | Z_ZERO), VM_KERN_MEMORY_LIBKERN);
}

void
operator delete(void * addr)
#if __cplusplus >= 201103L
noexcept
#endif
{
	kheap_free_addr(KERN_OS_MALLOC, addr);
	return;
}

void *
operator new[](unsigned long sz)
{
	return kheap_alloc_tag_bt(KERN_OS_MALLOC, sz,
	           (zalloc_flags_t) (Z_WAITOK | Z_ZERO), VM_KERN_MEMORY_LIBKERN);
}

void
operator delete[](void * ptr)
#if __cplusplus >= 201103L
noexcept
#endif
{
	if (ptr) {
#if KASAN
		/*
		 * Unpoison the C++ array cookie inserted (but not removed) by the
		 * compiler on new[].
		 */
		kasan_unpoison_cxx_array_cookie(ptr);
#endif
		kheap_free_addr(KERN_OS_MALLOC, ptr);
	}
	return;
}

#if __cplusplus >= 201103L

void
operator delete(void * addr, size_t sz) noexcept
{
	kheap_free(KERN_OS_MALLOC, addr, sz);
}

void
operator delete[](void * addr, size_t sz) noexcept
{
	if (addr) {
		kheap_free(KERN_OS_MALLOC, addr, sz);
	}
}

#endif /* __cplusplus >= 201103L */

/* PR-6481964 - The compiler is going to check for size overflows in calls to
 * new[], and if there is an overflow, it will call __throw_length_error.
 * This is an unrecoverable error by the C++ standard, so we must panic here.
 *
 * We have to put the function inside the std namespace because of how the
 * compiler expects the name to be mangled.
 */
namespace std {
void __dead2
__throw_length_error(const char *msg __unused)
{
	panic("Size of array created by new[] has overflowed");
}
};
