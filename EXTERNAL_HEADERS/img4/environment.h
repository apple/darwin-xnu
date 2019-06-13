/*!
 * @header
 * Image4 environment interfaces.
 */
#ifndef __IMG4_ENVIRONMENT_H
#define __IMG4_ENVIRONMENT_H

#ifndef __IMG4_INDIRECT
#error "Please #include <img4/img4.h> instead of this file directly"
#endif // __IMG4_INDIRECT

/*!
 * @const IMG4_ENVIRONMENT_VERSION
 * The version of the {@link img4_environment_t} structure supported by the
 * implementation. See {@link _img4_environment} for complete definition.
 */
#define IMG4_ENVIRONMENT_VERSION ((img4_struct_version_t)0)

/*!
 * @typedef img4_crypto_selector_t
 * A CoreCrypto selector routine.
 */
IMG4_API_AVAILABLE_20180112
typedef const struct ccdigest_info *(*img4_crypto_selector_t)(void);

/*!
 * @typedef img4_crypto_t
 * A structure describing a crypto algorithm used by Image4.
 *
 * @property i4c_name
 * The human-readable string for the crypto algorithm (e.g. "sha1").
 *
 * @property i4c_select
 * The CoreCrypto selector routine for the algorithm
 *
 * @property i4c_hash_len
 * The length of the hash computed by the algorithm.
 *
 * @property i4c_truncated_hash_len
 * The truncated length of the hash computed by the algorithm.
 *
 * @property __opaque
 * Reserved for the implementation.
 */
IMG4_API_AVAILABLE_20180112
typedef struct _img4_crypto {
	const char *i4c_name;
	img4_crypto_selector_t i4c_select;
	uint32_t i4c_hash_len;
	uint32_t i4c_truncated_hash_len;
	const void *__opaque;
} img4_crypto_t;

/*!
 * @const IMG4_CRYPTO_SHA1
 * The Image4 SHA1 implementation.
 */
IMG4_API_AVAILABLE_20180112
OS_EXPORT
const img4_crypto_t _img4_crypto_sha1;
#define IMG4_CRYPTO_SHA1 (&_img4_crypto_sha1)

/*!
 * @const IMG4_CRYPTO_SHA384
 * The Image4 SHA-384 implementation.
 */
IMG4_API_AVAILABLE_20180112
OS_EXPORT
const img4_crypto_t _img4_crypto_sha384;
#define IMG4_CRYPTO_SHA384 (&_img4_crypto_sha384)

/*!
 * @typedef img4_environment_t
 * A type describing an Image4 environment.
 */
IMG4_API_AVAILABLE_20180112
typedef struct _img4_environment img4_environment_t;

/*!
 * @typedef img4_environment_get_crypto_t
 * A function which obtains a crypto descriptor for the host environment.
 *
 * @param i4e
 * The environment descriptor.
 *
 * @param crypto
 * A pointer to the storage in which the pointer to the host's crypto descriptor
 * will be written.
 *
 * @param ctx
 * The context pointer supplied to {@link img4_init}.
 *
 * @result
 * Upon successfully fetching the property value, zero should be returned.
 * Otherwise, the following error codes should be returned:
 *
 *     [ENOENT]     The property does not exist in the environment
 */
IMG4_API_AVAILABLE_20180112
typedef errno_t (*img4_environment_get_crypto_t)(
	const img4_environment_t *i4e,
	const img4_crypto_t **crypto,
	const void *ctx);

/*!
 * @typedef img4_environment_get_bool_t
 * A function which obtains a Boolean property from the host environment.
 *
 * @param val
 * A pointer to storage in which the value will be written.
 *
 * @param ctx
 * The context pointer supplied to {@link img4_init}.
 *
 * @result
 * Upon successfully fetching the property value, zero should be returned.
 * Otherwise, the following error codes should be returned:
 *
 *     [ENOENT]     The property does not exist in the environment
 *     [EFTYPE]     The property is not expressible as a Boolean
 */
IMG4_API_AVAILABLE_20180112
typedef errno_t (*img4_environment_get_bool_t)(
	const img4_environment_t *i4e,
	bool *val,
	const void *ctx);

/*!
 * @typedef img4_environment_get_uint32_t
 * A function which obtains an unsigned 32-bit integer property from the host
 * environment.
 *
 * @param val
 * A pointer to storage in which the value will be written.
 *
 * @param ctx
 * The context pointer supplied to {@link img4_init}.
 *
 * @result
 * Upon successfully fetching the property value, zero should be returned.
 * Otherwise, the following error codes should be returned:
 *
 *     [ENOENT]     The property does not exist in the environment
 *     [EFTYPE]     The property is not expressible as an unsigned 32-bit integer
 */
IMG4_API_AVAILABLE_20180112
typedef errno_t (*img4_environment_get_uint32_t)(
	const img4_environment_t *i4e,
	uint32_t *val,
	const void *ctx);

/*!
 * @typedef img4_environment_get_uint64_t
 * A function which obtains an unsigned 64-bit integer property from the host
 * environment.
 *
 * @param val
 * A pointer to storage in which the value will be written.
 *
 * @param ctx
 * The context pointer supplied to {@link img4_init}.
 *
 * @result
 * Upon successfully fetching the property value, zero should be returned.
 * Otherwise, the following error codes should be returned:
 *
 *     [ENOENT]     The property does not exist in the environment
 *     [EFTYPE]     The property is not expressible as an unsigned 64-bit
 *                  integer
 */
IMG4_API_AVAILABLE_20180112
typedef errno_t (*img4_environment_get_uint64_t)(
	const img4_environment_t *i4e,
	uint64_t *val,
	const void *ctx);

/*!
 * @typedef img4_environment_get_data_t
 * A function which obtains a property which is a raw sequence of bytes from the
 * host environment.
 *
 * @param bytes
 * A pointer to storage in which the value will be written.
 *
 * @param len
 * A pointer to the length of the buffer referred to be {@link val}. Upon
 * successful return, this storage should contain the number of bytes written.
 *
 * @param ctx
 * The context pointer supplied to {@link img4_init}.
 *
 * @result
 * Upon successfully fetching the property value, zero should be returned.
 * Otherwise, the following error codes should be returned:
 *
 *     [ENOENT]     The property does not exist in the environment
 *     [EFTYPE]     The property is not expressible as a raw sequence of bytes
 *     [ERANGE]     The buffer was not large enough to hold the property
 */
IMG4_API_AVAILABLE_20180112
typedef errno_t (*img4_environment_get_data_t)(
	const img4_environment_t *i4e,
	uint8_t *bytes,
	uint32_t *len,
	const void *ctx);

/*!
 * @struct _img4_environment
 * A type describing a host environment.
 *
 * @property i4e_version
 * The version of the environment structure. Pass
 * {@link IMG4_ENVIRONMENT_VERSION}.
 *
 * @property i4e_name
 * A human-readable description of the environment.
 *
 * @property i4e_crypto
 * A pointer to a function which returns the crypto implementation for the
 * environment.
 *
 * @property i4e_cert_epoch
 * A pointer to a function which returns the certificate epoch for the
 * environment.
 *
 * @property i4e_board_id
 * A pointer to a function which returns the board identifier for the
 * environment.
 *
 * @property i4e_chip_id
 * A pointer to a function which returns the chip design identifier for the
 * environment.
 *
 * @property i4e_ecid
 * A pointer to a function which returns the unique chip identifier for the
 * environment.
 *
 * @property i4e_security_domain
 * A pointer to a function which returns the security domain for the
 * environment.
 *
 * @property i4e_cert_prod
 * A pointer to a function which returns the certificate production status for
 * the environment. This indicates whether the environment's leaf certificate
 * must be production or development.
 *
 * - true    the environment's leaf certificate must be production
 * - false   the environment's leaf certificate may be development
 *
 * @property i4e_cert_security
 * A pointer to a function which returns the certificate security mode for the
 * environment. This indicates Whether the leaf certificate must be secure.
 *
 * @property i4e_ap_nonce_hash
 * A pointer to a function which returns the hash of the AP nonce for the
 * environment.
 *
 * @property i4e_prevent_mixnmatch
 * A pointer to a function which returns whether the environment prevents mix-
 * n-match.
 *
 * - true    the environment disallows mix-n-match
 * - false   the environment allows mix-n-match
 *
 * @property i4e_boot_manifest_hash
 * A pointer to a function which returns the hash of the manifest from which
 * mix-n-match policy derives.
 *
 * @property i4e_eff_security
 * A pointer to a function which returns the effective security mode for the
 * environment.
 *
 * @property i4e_eff_prod
 * A pointer to a function which returns the effective production status for the
 * environment.
 *
 * @property i4e_ap_nonce_trust
 * A pointer to a function which returns whether the AP nonce must be
 * exclusively fetched from main memory.
 *
 * - true    the AP nonce hash must be fetched from main memory exclusively;
 *           persistent storage is not trustworthy
 * - false   the AP nonce hash may be fetched from persistent storage
 */
struct _img4_environment {
	img4_struct_version_t i4e_version;
	const char *i4e_name;
	img4_environment_get_crypto_t i4e_crypto;
	img4_environment_get_uint32_t i4e_cert_epoch;
	img4_environment_get_uint32_t i4e_board_id;
	img4_environment_get_uint32_t i4e_chip_id;
	img4_environment_get_uint64_t i4e_ecid;
	img4_environment_get_uint32_t i4e_security_domain;
	img4_environment_get_bool_t i4e_cert_prod;
	img4_environment_get_bool_t i4e_cert_security;
	img4_environment_get_data_t i4e_ap_nonce_hash;
	img4_environment_get_bool_t i4e_prevent_mixnmatch;
	img4_environment_get_data_t i4e_boot_manifest_hash;
	img4_environment_get_bool_t i4e_eff_prod;
	img4_environment_get_bool_t i4e_eff_security;
	img4_environment_get_bool_t i4e_ap_nonce_trust;
} IMG4_API_AVAILABLE_20180112;

/*!
 * @const IMG4_ENVIRONMENT_PLATFORM
 * The environment for the host that uses the default platform implementation to
 * resolve the environment.
 */
IMG4_API_AVAILABLE_20180112
OS_EXPORT
const struct _img4_environment _img4_environment_platform;
#define IMG4_ENVIRONMENT_PLATFORM (&_img4_environment_platform)

#endif // __IMG4_ENVIRONMENT_H
