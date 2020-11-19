/*!
 * @header
 * Image4 runtime interfaces.
 */
#ifndef __IMG4_RUNTIME_H
#define __IMG4_RUNTIME_H

#ifndef __IMG4_INDIRECT
#error "Please #include <img4/firmware.h> instead of this file directly"
#endif // __IMG4_INDIRECT

#if IMG4_TAPI
#include "tapi.h"
#endif

OS_ASSUME_NONNULL_BEGIN

/*!
 * @typedef img4_identifier_t
 * An enumeration describing identifiers in the Image4 specification.
 *
 * @const IMG4_IDENTIFIER_CEPO
 * The chip epoch as documented in 2.1.1. Authoritative manifests will specify a
 * certificate epoch which is greater than or equal to that of the chip.
 *
 * Unsigned 32-bit integer.
 *
 * @const IMG4_IDENTIFIER_BORD
 * The board identifier as documented in 2.1.3. Authoritative manifests will
 * specify a board identifier which is equal to that of the chip.
 *
 * Unsigned 32-bit integer.
 *
 * @const IMG4_IDENTIFIER_CHIP
 * The chip identifier as documented in 2.1.2. Authoritative manifests will
 * specify a chip identifier which is equal to that of the chip.
 *
 * Unsigned 32-bit integer.
 *
 * @const IMG4_IDENTIFIER_SDOM
 * The security domain as documented in 2.1.5. Authoritative manifests will
 * specify a security domain which is equal to that that of the chip.
 *
 * Unsigned 32-bit integer.
 *
 * @const IMG4_IDENTIFIER_ECID
 * The unique chip identifier as documented in 2.1.4. Authoritative manifests
 * will specify a unique chip identifier which is equal to that of the chip.
 *
 * Unsigned 64-bit integer.
 *
 * @const IMG4_IDENTIFIER_CPRO
 * The certificate production status as documented in 2.1.6. Authoritative
 * manifests will specify a certificate production status which is equal to that
 * of the chip.
 *
 * Boolean.
 *
 * @const IMG4_IDENTIFIER_CSEC
 * The certificate security mode as documented in 2.1.7. Authoritative manifests
 * will specify a certificate security mode which is equal to that of the chip.
 *
 * Boolean.
 *
 * @const IMG4_IDENTIFIER_EPRO
 * The effective production status as documented in 2.1.23. Unless the chip
 * environment supports demotion, this will always be the same as
 * {@link IMG4_IDENTIFIER_CPRO}. An executable firmware in an authoritative
 * manifest will specify an EPRO object property which is equal to that of the
 * chip post-demotion.
 *
 * Boolean.
 *
 * @const IMG4_IDENTIFIER_ESEC
 * The effective security mode as documented in 2.1.25. Unless the chip
 * environment supports demotion, this will always be the same as
 * {@link IMG4_IDENTIFIER_CSEC}. An executable firmware in an authoritative
 * manifest will specify an ESEC object property which is equal to that of the
 * chip post-demotion.
 *
 * Boolean.
 *
 * @const IMG4_IDENTIFIER_IUOU
 * The "internal use only unit" property. Indicates whether the chip is present
 * on a server-side authlist which permits installing builds which are otherwise
 * restricted to parts whose CPRO is 0. This property is only published by macOS
 * devices whose root of trust is in an arm coprocessor (e.g. T2).
 *
 * Authoritative manifests will specify an internal-use-only-build property
 * which, if true, is equal to the internal-use-only-unit property of the chip.
 * If the internal-use-only-build property is false, then there is no constraint
 * on the chip's internal-use-only-unit property.
 *
 * Boolean.
 *
 * @const IMG4_IDENTIFIER_RSCH
 * The research fusing status. Indicates whether the chip is intended for
 * security research to be performed by external parties. Authoritative
 * manifests will specify a research fusing state which is equal to that of the
 * chip.
 *
 * Boolean.
 *
 * @const IMG4_IDENTIFIER_CHMH
 * The chained manifest hash from the previous stage of secure boot as described
 * in 2.2.11. An authoritative manifest will either
 *
 *     - specify a manifest hash which is equal to that of the previous secure
 *       boot stage's manifest
 *     - itself have a manifest hash which is equal to that of the previous
 *       secure boot stage's manifest
 *
 * If the previous stage of secure boot enabled mix-n-match, there is no
 * constraint on the previous stage's manifest hash.
 *
 * Manifests which specify this property cannot be used to create new trust
 * chains -- they may only extend existing ones.
 *
 * Digest.
 *
 * @const IMG4_IDENTIFIER_AMNM
 * The allow-mix-n-match status of the chip. If mix-n-match is enabled, secure
 * boot will permit different manifests to be used at each stage of boot. If the
 * chip environment allows mix-n-match, evaluation will not require an anti-
 * replay token to be specified, and any chained manifest hash constraints are
 * ignored.
 *
 * Boolean.
 *
 * @const IMG4_IDENTIFIER_EUOU
 * The engineering-use-only-unit status of the chip. This is in effect an alias
 * for the {@link IMG4_IDENTIFIER_IUOU} property. Either property being present
 * in the environment will satisfy a manifest's iuob constraint.
 *
 * Boolean.
 *
 * @const _IMG4_IDENTIFIER_CNT
 * A convenience value representing the number of known identifiers.
 */
IMG4_API_AVAILABLE_20200508
OS_CLOSED_ENUM(img4_identifier, uint64_t,
	IMG4_IDENTIFIER_CEPO,
	IMG4_IDENTIFIER_BORD,
	IMG4_IDENTIFIER_CHIP,
	IMG4_IDENTIFIER_SDOM,
	IMG4_IDENTIFIER_ECID,
	IMG4_IDENTIFIER_CPRO,
	IMG4_IDENTIFIER_CSEC,
	IMG4_IDENTIFIER_EPRO,
	IMG4_IDENTIFIER_ESEC,
	IMG4_IDENTIFIER_IUOU,
	IMG4_IDENTIFIER_RSCH,
	IMG4_IDENTIFIER_CHMH,
	IMG4_IDENTIFIER_AMNM,
	IMG4_IDENTIFIER_EUOU,
	_IMG4_IDENTIFIER_CNT,
);

/*!
 * @const IMG4_DGST_STRUCT_VERSION
 * The version of the {@link img4_dgst_t} structure supported by the
 * implementation.
 */
#define IMG4_DGST_STRUCT_VERSION (0u)

/*!
 * @const IMG4_DGST_MAX_LEN
 * The maximum length of a digest representable by an {@link img4_dgst_t}.
 */
#define IMG4_DGST_MAX_LEN (48u)

/*!
 * @typedef img4_dgst_t
 * A structure representing an Image4 digest.
 *
 * @field i4d_len
 * The version of the structure. Initialize to {@link IMG4_DGST_STRUCT_VERSION}.
 *
 * @field i4d_len
 * The length of the digest.
 *
 * @field i4d_bytes
 * The digest bytes.
 */
IMG4_API_AVAILABLE_20200508
typedef struct _img4_dgst {
	img4_struct_version_t i4d_version;
	size_t i4d_len;
	uint8_t i4d_bytes[IMG4_DGST_MAX_LEN];
} img4_dgst_t;

/*!
 * @const IMG4_DGST_INIT
 * A convenience initializer for an {@link img4_dgst_t} structure.
 */
#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 199901L
#define IMG4_DGST_INIT (img4_dgst_t){ \
	.i4d_version = IMG4_DGST_STRUCT_VERSION, \
	.i4d_len = 0, \
	.i4d_bytes = {0}, \
}
#elif defined(__cplusplus) && __cplusplus >= 201103L
#define IMG4_DGST_INIT (img4_nonce_t{ \
	IMG4_DGST_STRUCT_VERSION, \
	0, \
	{0}, \
})
#elif defined(__cplusplus)
#define IMG4_DGST_INIT (img4_nonce_t((img4_nonce_t){ \
	IMG4_DGST_STRUCT_VERSION, \
	0, \
	{0}, \
}))
#else
#define IMG4_DGST_INIT {IMG4_DGST_STRUCT_VERSION}
#endif

/*!
 * @typedef img4_runtime_init_t
 * A function which initializes the runtime.
 *
 * @param rt
 * The runtime for which the function is being invoked.
 *
 * @discussion
 * This function is called by the implementation prior to any other runtime
 * function being called. The implementation will ensure that it is called only
 * once. Any runtime with an initialization function must be registered with the
 * {@link IMG4_RUNTIME_REGISTER} macro.
 */
IMG4_API_AVAILABLE_20200508
typedef void (*img4_runtime_init_t)(
	const img4_runtime_t *rt
);

/*!
 * @typedef img4_runtime_alloc_t
 * An allocation function.
 *
 * @param rt
 * The runtime for which the function is being invoked.
 *
 * @param n
 * The number of bytes to allocate.
 *
 * @result
 * A pointer to the new allocation, or NULL if there was an allocation failure.
 */
IMG4_API_AVAILABLE_20200508
typedef void *_Nullable (*img4_runtime_alloc_t)(
	const img4_runtime_t *rt,
	size_t n
);

/*!
 * @typedef img4_runtime_dealloc_t
 * A deallocation function.
 *
 * @param rt
 * The runtime for which the function is being invoked.
 *
 * @param p
 * A pointer to the allocation to free. The callee is expected to return
 * immediately if NULL is passed.
 *
 * @param n
 * The size of the allocation. Not all implementation may require this
 * information to be specified.
 */
IMG4_API_AVAILABLE_20200508
typedef void (*img4_runtime_dealloc_t)(
	const img4_runtime_t *rt,
	void *_Nullable p,
	size_t n
);

/*!
 * @typedef img4_log_level_t
 * An enumeration describing the importance/severity of a log message.
 *
 * @const IMG4_LOG_LEVEL_ERROR
 * A fatal condition which will cause the implementation to abort its current
 * operation.
 *
 * @const IMG4_LOG_LEVEL_INFO
 * Information that may be of interest to the system operator.
 *
 * @const IMG4_LOG_LEVEL_DEBUG
 * Information that may be of interest to the maintainer.
 *
 * @const _IMG4_LOG_LEVEL_CNT
 * A convenience constant indicating the number of log levels.
 */
IMG4_API_AVAILABLE_20200508
OS_CLOSED_ENUM(img4_log_level, uint64_t,
	IMG4_LOG_LEVEL_ERROR,
	IMG4_LOG_LEVEL_INFO,
	IMG4_LOG_LEVEL_DEBUG,
	_IMG4_LOG_LEVEL_CNT,
);

/*!
 * @typedef img4_runtime_log_t
 * A function which writes log messages.
 *
 * @param rt
 * The runtime for which the function is being invoked.
 *
 * @param handle
 * An implementation-specific handle for the log message.
 *
 * @param level
 * The message of the log level. The implementation is free to determine whether
 * a given message is worthy of record.
 *
 * @param fmt
 * A printf(3)-style format string.
 *
 * @param ...
 * Arguments to be interpreted by the format string according to the
 * specifications in printf(3).
 */
OS_FORMAT_PRINTF(4, 5)
IMG4_API_AVAILABLE_20200508
typedef void (*img4_runtime_log_t)(
	const img4_runtime_t *rt,
	void *_Nullable handle,
	img4_log_level_t level,
	const char *fmt,
	...
);

/*!
 * @typedef img4_runtime_log_handle_t
 * A function which returns a log handle.
 *
 * @param rt
 * The runtime for which the function is being invoked.
 *
 * @result
 * A runtime-specific log handle that will be passed to the logging function.
 */
IMG4_API_AVAILABLE_20200508
typedef void *_Nullable (*img4_runtime_log_handle_t)(
	const img4_runtime_t *rt
);

/*!
 * @typedef img4_runtime_get_identifier_bool_t
 * A function which retrieves a Boolean Image4 identifier.
 *
 * @param rt
 * The runtime for which the function is being invoked.
 *
 * @param chip
 * The chip for which to retrieve the identifier.
 *
 * @param identifier
 * The identifier to retrieve.
 *
 * @param value
 * Upon successful return, storage which is populated with the retrieved value.
 *
 * @result
 * Upon success, the callee is expected to return zero. Otherwise, the callee
 * may return one of the following error codes:
 *
 *     [ENOTSUP]     The identifier cannot be queried in the runtime
 *     [ENOENT]      The identifier was not found in the runtime's identity
 *                   oracle
 *     [ENODEV]      There was an error querying the runtime's identity oracle
 */
IMG4_API_AVAILABLE_20200508
typedef errno_t (*img4_runtime_get_identifier_bool_t)(
	const img4_runtime_t *rt,
	const img4_chip_t *chip,
	img4_identifier_t identifier,
	bool *value
);

/*!
 * @typedef img4_runtime_get_identifier_uint32_t
 * A function which retrieves an unsigned 32-bit integer Image4 identifier.
 *
 * @param rt
 * The runtime for which the function is being invoked.
 *
 * @param chip
 * The chip for which to retrieve the identifier.
 *
 * @param identifier
 * The identifier to retrieve.
 *
 * @param value
 * Upon successful return, storage which is populated with the retrieved value.
 *
 * @result
 * Upon success, the callee is expected to return zero. Otherwise, the callee
 * may return one of the following error codes:
 *
 *     [ENOTSUP]     The identifier cannot be queried in the runtime
 *     [ENOENT]      The identifier was not found in the runtime's identity
 *                   oracle
 *     [ENODEV]      There was an error querying the runtime's identity oracle
 */
IMG4_API_AVAILABLE_20200508
typedef errno_t (*img4_runtime_get_identifier_uint32_t)(
	const img4_runtime_t *rt,
	const img4_chip_t *chip,
	img4_identifier_t identifier,
	uint32_t *value
);

/*!
 * @typedef img4_runtime_get_identifier_uint64_t
 * A function which retrieves an unsigned 64-bit integer Image4 identifier.
 *
 * @param rt
 * The runtime for which the function is being invoked.
 *
 * @param chip
 * The chip for which to retrieve the identifier.
 *
 * @param identifier
 * The identifier to retrieve.
 *
 * @param value
 * Upon successful return, storage which is populated with the retrieved value.
 *
 * @result
 * Upon success, the callee is expected to return zero. Otherwise, the callee
 * may return one of the following error codes:
 *
 *     [ENOTSUP]     The identifier cannot be queried in the runtime
 *     [ENOENT]      The identifier was not found in the runtime's identity
 *                   oracle
 *     [ENODEV]      There was an error querying the runtime's identity oracle
 */
IMG4_API_AVAILABLE_20200508
typedef errno_t (*img4_runtime_get_identifier_uint64_t)(
	const img4_runtime_t *rt,
	const img4_chip_t *chip,
	img4_identifier_t identifier,
	uint64_t *value
);

/*!
 * @typedef img4_runtime_get_identifier_digest_t
 * A function which retrieves a digest Image4 identifier.
 *
 * @param rt
 * The runtime for which the function is being invoked.
 *
 * @param chip
 * The chip for which to retrieve the identifier.
 *
 * @param identifier
 * The identifier to retrieve.
 *
 * @param value
 * Upon successful return, storage which is populated with the retrieved value.
 *
 * @result
 * Upon success, the callee is expected to return zero. Otherwise, the callee
 * may return one of the following error codes:
 *
 *     [ENOTSUP]     The identifier cannot be queried in the runtime
 *     [ENOENT]      The identifier was not found in the runtime's identity
 *                   oracle
 *     [ENODEV]      There was an error querying the runtime's identity oracle
 */
IMG4_API_AVAILABLE_20200508
typedef errno_t (*img4_runtime_get_identifier_digest_t)(
	const img4_runtime_t *rt,
	const img4_chip_t *chip,
	img4_identifier_t identifier,
	img4_dgst_t *value
);

/*!
 * @define IMG4_BUFF_STRUCT_VERSION
 * The version of the {@link img4_buff_t} structure supported by the
 * implementation.
 */
#define IMG4_BUFF_STRUCT_VERSION (0u)

/*!
 * @struct _img4_buff
 * A structure describing a buffer.
 *
 * @field i4b_version
 * The version of the structure. Initialize to {@link IMG4_BUFF_STRUCT_VERSION}.
 *
 * @field i4b_bytes
 * A pointer to the buffer.
 *
 * @field i4b_len
 * The length of the buffer.
 *
 * @field i4b_dealloc
 * The deallocation function for the buffer. May be NULL if the underlying
 * memory does not require cleanup. When the implementation invokes this
 * function, it will always pass {@link IMG4_RUNTIME_DEFAULT}, and the callee
 * should not consult this parameter for any reason.
 */
struct _img4_buff {
	img4_struct_version_t i4b_version;
	uint8_t *i4b_bytes;
	size_t i4b_len;
	img4_runtime_dealloc_t _Nullable i4b_dealloc;
} IMG4_API_AVAILABLE_20200508;

/*!
 * @const IMG4_BUFF_INIT
 * A convenience initializer for the {@link img4_buff_t} structure.
 */
#if defined(__STDC_VERSION__) && __STDC_VERSION__ >= 199901L
#define IMG4_BUFF_INIT (img4_buff_t){ \
	.i4b_version = IMG4_BUFF_STRUCT_VERSION, \
	.i4b_len = 0, \
	.i4b_bytes = NULL, \
	.i4b_dealloc = NULL, \
}
#elif defined(__cplusplus) && __cplusplus >= 201103L
#define IMG4_BUFF_INIT (img4_buff_t{ \
	IMG4_BUFF_STRUCT_VERSION, \
	NULL, \
	0, \
	NULL, \
})
#elif defined(__cplusplus)
#define IMG4_BUFF_INIT (img4_buff_t((img4_buff_t){ \
	IMG4_BUFF_STRUCT_VERSION, \
	NULL, \
	0, \
	NULL, \
}))
#else
#define IMG4_BUFF_INIT {IMG4_BUFF_STRUCT_VERSION}
#endif

/*!
 * @define IMG4_RUNTIME_STRUCT_VERSION
 * The version of the {@link img4_runtime_t} structure supported by the
 * implementation.
 */
#define IMG4_RUNTIME_STRUCT_VERSION (1u)

/*!
 * @struct _img4_runtime
 * A structure describing required primitives in the operating environment's
 * runtime.
 *
 * @field i4rt_version
 * The version of the structure supported by the implementation. In a custom
 * execution context, initialize to {@link IMG4_RUNTIME_STRUCT_VERSION}.
 *
 * @field i4rt_name
 * A string describing the environment.
 *
 * @field i4rt_init
 * The runtime initialization function. See discussion in
 * {@link img4_runtime_init_t}.
 *
 * @field i4rt_alloc
 * The allocation function for the environment (e.g. in Darwin userspace, this
 * would be a pointer to malloc(3)).
 *
 * @field i4rt_dealloc
 * The deallocation function for the environment (e.g. in Darwin userspace, this
 * would be a pointer to free(3)).
 *
 * @field i4rt_log
 * The function which logs messages from the implementation.
 *
 * @field i4rt_log_handle
 * The function which returns the handle to be passed to the logging function.
 *
 * @field i4rt_get_identifier_bool
 * The function which returns Boolean identifiers.
 *
 * @field i4rt_get_identifier_uint32
 * The function which returns unsigned 32-bit integer identifiers.
 *
 * @field i4rt_get_identifier_uint64
 * The function which returns unsigned 64-bit integer identifiers.
 *
 * @field i4rt_get_identifier_digest
 * The function which returns digest identifiers.
 *
 * @field i4rt_context
 * A user-defined context pointer.
 */
struct _img4_runtime {
	img4_struct_version_t i4rt_version;
	const char *i4rt_name;
	img4_runtime_init_t _Nullable i4rt_init;
	img4_runtime_alloc_t i4rt_alloc;
	img4_runtime_dealloc_t i4rt_dealloc;
	img4_runtime_log_t i4rt_log;
	img4_runtime_log_handle_t i4rt_log_handle;
	img4_runtime_get_identifier_bool_t i4rt_get_identifier_bool;
	img4_runtime_get_identifier_uint32_t i4rt_get_identifier_uint32;
	img4_runtime_get_identifier_uint64_t i4rt_get_identifier_uint64;
	img4_runtime_get_identifier_digest_t i4rt_get_identifier_digest;
	void *_Nullable i4rt_context;
} IMG4_API_AVAILABLE_20200508;

/*!
 * @function IMG4_RUNTIME_REGISTER
 * Registers a runtime with the module implementation such that its
 * initialization function can be called. In environments which support dynamic
 * library linkage, only runtimes registered from the main executable image can
 * be discovered by the implementation.
 *
 * @param _rt
 * The img4_runtime_t structure to register.
 */
#define IMG4_RUNTIME_REGISTER(_rt) LINKER_SET_ENTRY(__img4_rt, _rt);

/*!
 * @const IMG4_RUNTIME_DEFAULT
 * The default runtime for the current operating environment.
 */
#if !XNU_KERNEL_PRIVATE
IMG4_API_AVAILABLE_20200508
OS_EXPORT
const img4_runtime_t _img4_runtime_default;
#define IMG4_RUNTIME_DEFAULT (&_img4_runtime_default)
#else
#define IMG4_RUNTIME_DEFAULT (img4if->i4if_v7.runtime_default)
#endif

/*!
 * @const IMG4_RUNTIME_PMAP_CS
 * The runtime for the xnu pmap monitor. This runtime is not available outside
 * the kernel-proper. On architectures which do not have an xnu monitor, this
 * is merely an alias for the default kernel runtime.
 */
#if XNU_KERNEL_PRIVATE
#define IMG4_RUNTIME_PMAP_CS (img4if->i4if_v7.runtime_pmap_cs)
#endif

/*!
 * @const IMG4_RUNTIME_RESTORE
 * The runtime for the restore ramdisk. This runtime is not available outside
 * of the Darwin userspace library.
 */
#if !KERNEL
IMG4_API_AVAILABLE_20200508
OS_EXPORT
const img4_runtime_t _img4_runtime_restore;
#define IMG4_RUNTIME_RESTORE (&_img4_runtime_restore)
#endif

/*!
 * @function img4_buff_dealloc
 * Deallocates a buffer according to its deallocation function.
 *
 * @param buff
 * A pointer to the a pointer to the buffer. This parameter may be NULL, in
 * which case the implementation will return immediately.
 *
 * @discussion
 * This interface will always invoke the deallocation callback with
 * {@link IMG4_RUNTIME_DEFAULT}. The callee should not consult this parameter
 * for any reason.
 */
#if !XNU_KERNEL_PRIVATE
IMG4_API_AVAILABLE_20200508
OS_EXPORT
void
img4_buff_dealloc(img4_buff_t *_Nullable buff);
#else
#define img4_buff_dealloc(...) (img4if->i4if_v7.buff_dealloc(__VA_ARGS__))
#endif

OS_ASSUME_NONNULL_END

#endif // __IMG4_RUNTIME_H
