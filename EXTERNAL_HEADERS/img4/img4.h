/*!
 * @header
 * Image4 interfaces. These interfaces encapsulate the basic concepts required
 * for authenticating and validating Image4 manifests as being authoritative.
 * These concepts are:
 *
 * Environment
 * An environment is a description of a host comprised of hardware identifiers
 * and policy configurations. For example, the environment of an iPhone may
 * include the following hardware identifiers (among others):
 *
 *     ChipID
 *     A number identifying the chip design.
 *
 *     BoardID
 *     A number identifying the board.
 *
 *     UniqueChipID / ECID
 *     A number uniquely identifying a specific instance of a chip.
 *
 * The environment also includes policy information derived by previous stages
 * of secure boot. Examples of such policy are:
 *
 *     Mix-n-Match Prevention
 *     Whether firmware payloads from multiple, valid secure boot manifests
 *     should be prevented from being executed on the host environment. The
 *     default is true.
 *
 * Manifest
 * An Image4 manifest is a set of constraints that describe a host environment.
 * For example, a manifest may have been signed such that it is only valid for a
 * single host environment. In this case, the manifest may include specific
 * values for ChipID, BoardID, UniqueChipID, etc. Such a manifest is said to be
 * personalized for that environment.
 *
 * If an environment meets the constraints in a manifest, that manifest is said
 * to be authoritative over the environment.
 *
 * The manifest also includes one or more objects which may be executed in the
 * environment.
 *
 * Object
 * An object is a description of a payload. An object can describe any payload,
 * not just the payload that is in the Image4. An object describes a payload by
 * means of its digest. Examples of objects present in a secure boot manifest
 * are the kernelcache and the static trust cache.
 *
 * If an authoritative manifest accurately describes an object, then that object
 * may be executed in the host environment. The mechanics of execution typically
 * involve mapping its payload into a privileged memory region. For example,
 * when the kernelcache is executed, its payload bytes are mapped into the range
 * of memory associated with supervisor mode.
 *
 * Payload
 * A payload is the raw sequence of bytes that is described by an object. When
 * described via an Image4 object, payloads are first wrapped in Image4 encoding
 * to associate a tag with them. The resulting series of bytes is what is
 * contained in a .im4p file.
 *
 * An Image4 file may only contain a single payload (even though a manifest may
 * describe multiple payloads through multiple objects).
 *
 * Tag
 * A tag is a FourCC which can identify any of the following:
 *
 *     - an object property (e.g. the 'DGST' property)
 *     - a manifest property (e.g. the 'BORD' property)
 *     - a certificate property
 *     - a type of object (e.g. 'krnl')
 *
 * Tags comprised of all-caps are reserved for the Image4 specification.
 */


#ifndef __IMG4_H
#define __IMG4_H

#include <os/base.h>
#include <stdint.h>
#include <stdbool.h>
#include <sys/cdefs.h>

#define __IMG4_INDIRECT 1

/*
 * This header is used in the pmap layer in xnu, which is in osfmk, which does
 * not have access to most of the BSD headers. (But for some reason it does have
 * access to sys/cdefs.h.) The only thing we need from that header is the
 * errno_t typedef though, so if we can't get to it, then just typeded it
 * ourselves.
 */
#if MACH_KERNEL_PRIVATE
typedef int errno_t;
#else
#include <sys/types.h>
#endif

#if !IMG4_PROJECT_BUILD
#include <img4/api.h>
#endif

__BEGIN_DECLS;

/*!
 * @typedef img4_tag_t
 * A type describing an Image4 tag.
 */
IMG4_API_AVAILABLE_20180112
typedef uint32_t img4_tag_t;

/*!
 * @typedef img4_section_t
 * A type describing the sections of an Image4 object.
 *
 * @const IMG4_SECTION_MANIFEST
 * The manifest section.
 *
 * @const IMG4_SECTION_OBJECT
 * The object section.
 *
 * @const IMG4_SECTION_RESTOREINFO
 * The restore info section.
 */
OS_ENUM(img4_section, uint8_t,
	IMG4_SECTION_MANIFEST,
	IMG4_SECTION_OBJECT,
	IMG4_SECTION_RESTOREINFO,
) IMG4_API_AVAILABLE_20180112;

/*!
 * @typedef img4_custom_tag_handler_t
 * A handler for a tag unrecognized by the implementation.
 *
 * @param tag
 * The FourCC tag.
 *
 * @param ctx
 * The user-provided context pointer given to either
 * {@link img4_get_trusted_payload} or
 * {@link img4_get_trusted_external_payload}.
 */
IMG4_API_AVAILABLE_20180112
typedef errno_t (*img4_custom_tag_handler_t)(
	img4_tag_t tag,
	img4_section_t section,
	void *ctx);

/*!
 * @typedef img4_custom_tag_t
 * A type describing a custom tag and its handler.
 *
 * @property i4ct_tag
 * The FourCC tag.
 *
 * @property i4ct_section
 * The section in which the tag is expected. If {@link IMG4_SECTION_OBJECT} is
 * given, the object corresponding to the tag given to
 * {@link img4_get_trusted_payload} or {@link img4_get_trusted_external_payload}
 * will be consulted for the tag.
 *
 * @property i4ct_handler
 * The handler for the tag.
 */
IMG4_API_AVAILABLE_20180112
typedef struct _img4_custom_tag {
	img4_tag_t i4ct_tag;
	img4_section_t i4ct_section;
	img4_custom_tag_handler_t i4ct_handler;
} img4_custom_tag_t;

/*!
 * @typedef img4_destructor_t
 * A type describing a destructor routine for an Image4 object.
 *
 * @param ptr
 * A pointer to the buffer to dispose of.
 *
 * @param len
 * The length of the buffer.
 */
IMG4_API_AVAILABLE_20180112
typedef void (*img4_destructor_t)(
	void *ptr,
	size_t len);

/*!
 * @typedef img4_flags_t
 * A flagset modifying the behavior of an {@link img4_t}.
 *
 * @const I4F_INIT
 * No flags set. This value is suitable for initialization purposes.
 *
 * @const I4F_TRUST_MANIFEST
 * Causes the implementation to bypass trust evaluation for the manifest, i.e.
 * it will not verify that a manifest has been signed by Apple before trusting
 * it.
 *
 * This option is for testing purposes only and is not respected on the RELEASE
 * variant of the implementation.
 *
 * @const I4F_FORCE_MIXNMATCH
 * Causes the implementation to bypass mix-n-match policy evaluation and always
 * allow mix-n-match, irrespective of the previous boot stage's conclusion or
 * manifest policy.
 *
 * This option is for testing purposes only and is not respected on the RELEASE
 * variant of the implementation.
 */
OS_ENUM(img4_flags, uint64_t,
	I4F_INIT = 0,
	I4F_TRUST_MANIFEST = (1 << 0),
	I4F_FORCE_MIXNMATCH = (1 << 1),
) IMG4_API_AVAILABLE_20180112;

#if TARGET_OS_OSX || defined(PLATFORM_MacOSX)
typedef char _img4_opaque_data_64[656];
typedef char _img4_opaque_data_32[476];
#elif TARGET_OS_IOS || defined(PLATFORM_iPhoneOS)
typedef char _img4_opaque_data_64[656];
typedef char _img4_opaque_data_32[476];
#elif TARGET_OS_WATCH || defined(PLATFORM_WatchOS)
typedef char _img4_opaque_data_64[656];
typedef char _img4_opaque_data_32[488];
#elif TARGET_OS_TV || defined(PLATFORM_tvOS) || defined(PLATFORM_AppleTVOS)
typedef char _img4_opaque_data_64[656];
typedef char _img4_opaque_data_32[476];
#elif TARGET_OS_BRIDGE || defined(PLATFORM_BridgeOS)
typedef char _img4_opaque_data_64[656];
typedef char _img4_opaque_data_32[476];
#else
#error "Unsupported platform"
#endif

/*!
 * @typedef img4_t
 * An opaque structure representing Image4 data. The Image4 data must contain a
 * manifest and may optionally contain a payload. Neither this type nor the APIs
 * APIs which manipulate it are thread-safe.
 */
IMG4_API_AVAILABLE_20180112
typedef struct _img4 {
#if __ILP64__ || __LP64__
	_img4_opaque_data_64 __opaque;
#else
	_img4_opaque_data_32 __opaque;
#endif
} img4_t;

#if TARGET_OS_OSX  || defined(PLATFORM_MacOSX)
typedef char _img4_payload_opaque_data_64[488];
typedef char _img4_payload_opaque_data_32[316];
#elif TARGET_OS_IOS || defined(PLATFORM_iPhoneOS)
typedef char _img4_payload_opaque_data_64[488];
typedef char _img4_payload_opaque_data_32[316];
#elif TARGET_OS_WATCH || defined(PLATFORM_WatchOS)
typedef char _img4_payload_opaque_data_64[488];
typedef char _img4_payload_opaque_data_32[316];
#elif TARGET_OS_TV || defined(PLATFORM_tvOS) || defined(PLATFORM_AppleTVOS)
typedef char _img4_payload_opaque_data_64[488];
typedef char _img4_payload_opaque_data_32[316];
#elif TARGET_OS_BRIDGE || defined(PLATFORM_BridgeOS)
typedef char _img4_payload_opaque_data_64[488];
typedef char _img4_payload_opaque_data_32[316];
#else
#error "Unsupported platform"
#endif

/*!
 * @typedef img4_payload_t
 * An opaque structure describing Image4 payload data. Neither this type nor the
 * APIs which manipulate it are thread-safe.
 */
IMG4_API_AVAILABLE_20180112
typedef struct _img4_payload {
#if __ILP64__ || __LP64__
	_img4_payload_opaque_data_64 __opaque;
#else
	_img4_payload_opaque_data_32 __opaque;
#endif
} img4_payload_t;

#if !IMG4_PROJECT_BUILD
#include <img4/environment.h>
#include <img4/payload.h>
#endif

/*!
 * @function img4_init
 * Initializes an Image4.
 *
 * @param i4
 * A pointer to the storage to initialize.
 *
 * @param flags
 * Flags to modify initialization.
 *
 * @param bytes
 * The Image4 data from which to initialize. If a destructor is provided,
 * control of this buffer transfers to the Image4.
 *
 * @param len
 * The length of the Image4 data.
 *
 * @param destructor
 * A destructor for the Image4 data. May be NULL if the buffer does not require
 * explicit deallocation (e.g. because the buffer is stack data).
 *
 * @result
 * Upon success, zero is returned. The implementation may also return one of the
 * following error codes directly:
 *
 *     [EILSEQ]     The data is not valid Image4 data
 *     [EFTYPE]     The data does not contain an Image4 manifest
 *
 * @discussion
 * The bytes given to this routine must represent an Image4 manifest. They may
 * optionally also represent an Image4 payload.
 */
IMG4_API_AVAILABLE_20180112
OS_EXPORT OS_WARN_RESULT OS_NONNULL1 OS_NONNULL3
errno_t
img4_init(img4_t *i4, img4_flags_t flags, const uint8_t *bytes, size_t len,
		img4_destructor_t destructor);

/*!
 * @function img4_set_custom_tag_handler
 * Sets custom tag handlers for an Image4. These handlers are invoked during
 * trust evaluation of the Image4.
 *
 * @param i4
 * The Image4 to modify.
 *
 * @param tags
 * An array of custom tag structures which specify the custom tags expected.
 * This must be constant storage. Passing heap or stack storage will result in
 * undefined behavior.
 *
 * @param tags_cnt
 * The number of items in the {@link tags} array.
 *
 * @discussion
 * Invocations of custom tag handlers occur during trust evaluation. You should
 * not assume that the Image4 is trusted within the scope of a custom tag
 * handler. Trustworthiness can only be determined by consulting the return
 * value of {@link img4_get_trusted_payload} or
 * {@link img4_get_trusted_external_payload}.
 */
IMG4_API_AVAILABLE_20180112
OS_EXPORT OS_NONNULL1 OS_NONNULL2
void
img4_set_custom_tag_handler(img4_t *i4,
		const img4_custom_tag_t *tags, size_t tags_cnt);

/*!
 * @function img4_get_trusted_payload
 * Obtains the trusted payload bytes from the Image4.
 *
 * @param i4
 * The Image4 to query.
 *
 * @param tag
 * The tag for the payload to obtain.
 *
 * @param env
 * The environment against which to validate the Image4.
 *
 * @param ctx
 * The context pointer to pass to the routines defined in the environment (if
 * a custom environment was passed) and to any custom tag handlers.
 *
 * @param bytes
 * A pointer to the storage where the pointer to the payload buffer will be
 * written on success.
 *
 * @param len
 * A pointer to the storage where the length of the payload buffer will be
 * written on success.
 *
 * @result
 * Upon success, zero is returned. The implementation may also return one of the
 * following error codes directly:
 *
 *     [ENOENT]     The Image4 does not contain a payload for the specified tag
 *     [EAUTH]      The Image4 manifest was not authentic
 *     [EACCES]     The environment given does not satisfy the manifest
 *                  constraints
 *     [EACCES]     The environment and manifest do not agree on a digest
 *                  algorithm
 *     [EILSEQ]     The payload for the given tag does not match its description
 *                  in the manifest
 *     [EIO]        The payload could not be fetched
 *
 * Additionally, errors from the routines specified in the
 * {@link img4_environment_t} may be returned.
 *
 * @discussion
 * This routine will perform the following validation:
 *
 *     1. Validate that the Image4 manifest is authentic (i.e. was signed by
 *        Apple)
 *     2. Validate that the given environment satisfies the constraints in the
 *        manifest
 *     3. Validate that the measurement of the payload for the given tag matches
 *        the measurement in the manifest
 *
 * If any one of these validation checks fails, the payload is considered
 * untrustworthy and is not returned.
 */
IMG4_API_AVAILABLE_20180112
OS_EXPORT OS_WARN_RESULT OS_NONNULL1 OS_NONNULL3 OS_NONNULL5 OS_NONNULL6
errno_t
img4_get_trusted_payload(img4_t *i4, img4_tag_t tag,
		const img4_environment_t *env, void *ctx,
		const uint8_t **bytes, size_t *len);

/*!
 * @function img4_get_trusted_external_payload
 * Obtains the trusted payload bytes from the external Image4 payload after
 * validating them against the object description in the Image4's manifest.
 *
 * @param i4
 * The Image4 to query.
 *
 * @param payload
 * The payload to validate.
 *
 * @param env
 * The environment against which to validate the Image4.
 *
 * @param ctx
 * The context pointer to pass to the routines defined in the environment and to
 * any custom tag handlers.
 *
 * @param bytes
 * A pointer to the storage where the pointer to the payload buffer will be
 * written on success.
 *
 * @param len
 * A pointer to the storage where the length of the payload buffer will be
 * written on success.
 *
 * @result
 * Upon success, zero is returned. The implementation may also return one of the
 * following error codes directly:
 *
 *     [ENOENT]     The Image4 does not contain an object describing the given
 *                  payload
 *     [EAUTH]      The Image4 manifest was not authentic
 *     [EACCES]     The environment given does not satisfy the manifest
 *                  constraints
 *     [EACCES]     The environment and manifest do not agree on a digest
 *                  algorithm
 *     [EILSEQ]     The payload for the given tag does not match its description
 *                  in the manifest
 *     [EIO]        The payload could not be fetched
 *
 * Otherwise, an error from the underlying Image4 implementation will be
 * returned.
 *
 * @discussion
 * This routine performs the same validation steps as
 * {@link img4_get_trusted_payload}.
 */
IMG4_API_AVAILABLE_20180112
OS_EXPORT OS_WARN_RESULT OS_NONNULL1 OS_NONNULL2
errno_t
img4_get_trusted_external_payload(img4_t *i4, img4_payload_t *payload,
		const img4_environment_t *env, void *ctx,
		const uint8_t **bytes, size_t *len);

/*!
 * @function img4_get_entitlement_bool
 * Queries the Image4 manifest for a Boolean entitlement value.
 *
 * @param i4
 * The Image4 to query.
 *
 * @param entitlement
 * The tag for the entitlement to query.
 *
 * @result
 * The Boolean value of the entitlement. If the entitlement was not present,
 * false is returned. If the entitlement was present but did not have a Boolean
 * value, false is returned.
 *
 * @discussion
 * This routine does not trigger validation of the Image4. Therefore the result
 * result of this routine cannot be used to confer trust without also having
 * obtained a valid payload.
 */
IMG4_API_AVAILABLE_20180112
OS_EXPORT OS_WARN_RESULT OS_NONNULL1
bool
img4_get_entitlement_bool(img4_t *i4, img4_tag_t entitlement);

/*!
 * @function img4_get_object_entitlement_bool
 * Queries the specified object in the Image4 manifest for a Boolean entitlement
 * value.
 *
 * @param i4
 * The Image4 to query.
 *
 * @param object
 * The tag for the object to query.
 *
 * @param entitlement
 * The tag for the entitlement to query.
 *
 * @result
 * The Boolean value of the entitlement. If the entitlement was not present,
 * false is returned. If the entitlement was present but did not have a Boolean
 * value, false is returned. If the object specified was not present, false is
 * returned.
 *
 * @discussion
 * See discussion for {@link img4_get_entitlement_bool}.
 */
IMG4_API_AVAILABLE_20180112
OS_EXPORT OS_WARN_RESULT OS_NONNULL1
bool
img4_get_object_entitlement_bool(img4_t *i4, img4_tag_t object,
		img4_tag_t entitlement);

/*!
 * @function img4_destroy
 * Destroys an Image4 and disposes of associated resources.
 *
 * @param i4
 * The Image4 to destroy.
 *
 * @discussion
 * The destructor passed to {@link img4_init} is called as a result of this
 * routine, if any was set.
 */
IMG4_API_AVAILABLE_20180112
OS_EXPORT OS_NONNULL1
void
img4_destroy(img4_t *i4);

__END_DECLS;

#endif // __IMG4_H
