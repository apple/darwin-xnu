/*!
 * @header
 * API definitions.
 */
#ifndef __IMG4_API_H
#define __IMG4_API_H

#ifndef __IMG4_INDIRECT
#error "Please #include <img4/img4.h> instead of this file directly"
#endif // __IMG4_INDIRECT

#if IMG4_TAPI
#include <stdint.h>
#endif

#ifndef KERNEL
#include <os/availability.h>
#endif

#if !XNU_KERNEL_PRIVATE
#include <TargetConditionals.h>
#endif

/*!
 * @const IMG4_API_VERSION
 * The API version of the library. This version will be changed in accordance
 * with new API introductions so that callers may submit code to the build that
 * adopts those new APIs before the APIs land by using the following pattern:
 *
 *     #if IMG4_API_VERSION >= 20180424
 *     img4_new_api();
 *     #endif
 *
 * In this example, the library maintainer and API adopter agree on an API
 * version of 20180424 ahead of time for the introduction of
 * img4_new_api(). When a libdarwin with that API version is submitted, the
 * project is rebuilt, and the new API becomes active.
 *
 * Breaking API changes will be both covered under this mechanism as well as
 * individual preprocessor macros in this header that declare new behavior as
 * required.
 */
#define IMG4_API_VERSION (20181106u)

#if !defined(KERNEL) && !IMG4_PROJECT_BUILD
#define IMG4_API_AVAILABLE_20180112 \
		__API_UNAVAILABLE(macos) \
		API_AVAILABLE(ios(12.0), tvos(12.0), watchos(5.0))
#define IMG4_API_AVAILABLE_20181004 \
		__API_UNAVAILABLE(macos) \
		API_AVAILABLE(ios(12.2), tvos(12.2), watchos(5.2))
#define IMG4_API_AVAILABLE_20181106 \
		__API_UNAVAILABLE(macos) \
		API_AVAILABLE(ios(12.2), tvos(12.2), watchos(5.2))
#define IMG4_API_AVAILABLE_20181106
#else
#define IMG4_API_AVAILABLE_20180112
#define IMG4_API_AVAILABLE_20181004
#define IMG4_API_AVAILABLE_20181106
#endif

/*!
 * @typedef img4_struct_version_t
 * A type describing the version of a structure in the library.
 */
IMG4_API_AVAILABLE_20180112
typedef uint16_t img4_struct_version_t;

#endif // __IMG4_API_H
