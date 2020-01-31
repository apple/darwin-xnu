/*!
 * @header
 * Image4 environments.
 */
#ifndef __IMG4_ENVIRONMENT_H
#define __IMG4_ENVIRONMENT_H

#ifndef __IMG4_INDIRECT
#error "Please #include <img4/img4.h> instead of this file directly"
#endif // __IMG4_INDIRECT

/*!
 * @typedef img4_environment_t
 * An opaque type describing an Image4 environment.
 */
typedef struct _img4_environment img4_environment_t;

/*!
 * @const IMG4_ENVIRONMENT_PLATFORM
 * The environment for the host that uses the default platform implementation to
 * resolve the environment. This is the environment against which manifests are
 * personalized.
 */
#if !MACH_KERNEL_PRIVATE
IMG4_API_AVAILABLE_20180112
OS_EXPORT
const struct _img4_environment _img4_environment_platform;
#define IMG4_ENVIRONMENT_PLATFORM (&_img4_environment_platform)
#else
#define IMG4_ENVIRONMENT_PLATFORM (img4if->i4if_environment_platform)
#endif


/*!
 * @const IMG4_ENVIRONMENT_TRUST_CACHE
 * The software environment for globally-signed loadable trust caches. This
 * environment should be used as a fallback when validation against the platform
 * fails, and the caller is handling a loadable trust cache.
 */
#if !MACH_KERNEL_PRIVATE
IMG4_API_AVAILABLE_20181004
OS_EXPORT
const struct _img4_environment _img4_environment_trust_cache;
#define IMG4_ENVIRONMENT_TRUST_CACHE (&_img4_environment_trust_cache)
#else
#define IMG4_ENVIRONMENT_TRUST_CACHE (img4if->i4if_environment_trust_cache)
#endif

#endif // __IMG4_ENVIRONMENT_H
