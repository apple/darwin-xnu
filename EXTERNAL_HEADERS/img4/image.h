/*!
 * @header
 * Interfaces for manipulating Image4 firmware images.
 */
#ifndef __IMG4_IMAGE_H
#define __IMG4_IMAGE_H

#ifndef __IMG4_INDIRECT
#error "Please #include <img4/firmware.h> instead of this file directly"
#endif // __IMG4_INDIRECT

#if IMG4_TAPI
#include "tapi.h"
#endif

OS_ASSUME_NONNULL_BEGIN

/*!
 * @function img4_image_get_bytes
 * Returns the authenticated payload from an Image4 image.
 *
 * @param image
 * The image to query.
 *
 * @result
 * A buffer which describes the authenticated payload.
 */
#if !XNU_KERNEL_PRIVATE
IMG4_API_AVAILABLE_20200508
OS_EXPORT OS_WARN_RESULT OS_NONNULL1
const img4_buff_t *
img4_image_get_bytes(img4_image_t image);
#else
#define img4_image_get_bytes(...) (img4if->i4if_v7.image_get_bytes(__VA_ARGS__))
#endif

/*!
 * @function img4_image_get_property_bool
 * Retrieves the Boolean value for the requested image property.
 *
 * @param image
 * The image to query.
 *
 * @param _4cc
 * The 4cc of the desired image property.
 *
 * @param storage
 * A pointer to storage for a Boolean value.
 *
 * @result
 * If the property is present for the image, a pointer to the storage provided
 * in {@link storage}. If the property is not present in the image or its value
 * is not a Boolean, NULL is returned.
 *
 * @discussion
 * If the property is present for the image, a pointer to the storage provided
 * in {@link storage}. If the property is not present in the image or its value
 * is not a Boolean, NULL is returned.
 */
#if !XNU_KERNEL_PRIVATE
IMG4_API_AVAILABLE_20200508
OS_EXPORT OS_WARN_RESULT OS_NONNULL1 OS_NONNULL3
const bool *
img4_image_get_property_bool(img4_image_t image,
		img4_4cc_t _4cc,
		bool *storage);
#else
#define img4_image_get_property_bool(...) \
		(img4if->i4if_v7.image_get_property_bool(__VA_ARGS__))
#endif

/*!
 * @function img4_image_get_property_uint32
 * Retrieves the unsigned 32-bit integer value for the requested image property.
 *
 * @param image
 * The image to query.
 *
 * @param _4cc
 * The 4cc of the desired image property.
 *
 * @param storage
 * A pointer to storage for a 32-bit unsigned integer value.
 *
 * @result
 * If the property is present for the image, a pointer to the storage provided
 * in {@link storage}. If the property is not present in the image or its value
 * is not an unsigned 32-bit integer, NULL is returned.
 */
#if !XNU_KERNEL_PRIVATE
IMG4_API_AVAILABLE_20200508
OS_EXPORT OS_WARN_RESULT OS_NONNULL1 OS_NONNULL3
const uint32_t *
img4_image_get_property_uint32(img4_image_t image,
		img4_4cc_t _4cc,
		uint32_t *storage);
#else
#define img4_image_get_property_uint32(...) \
		(img4if->i4if_v7.image_get_property_uint32(__VA_ARGS__))
#endif

/*!
 * @function img4_image_get_property_uint64
 * Retrieves the unsigned 64-bit integer value for the requested image property.
 *
 * @param image
 * The image to query.
 *
 * @param _4cc
 * The 4cc of the desired image property.
 *
 * @param storage
 * A pointer to storage for a 64-bit unsigned integer value.
 *
 * @result
 * If the property is present for the image, a pointer to the storage provided
 * in {@link storage}. If the property is not present in the image or its value
 * is not an unsigned 64-bit integer, NULL is returned.
 */
#if !XNU_KERNEL_PRIVATE
IMG4_API_AVAILABLE_20200508
OS_EXPORT OS_WARN_RESULT OS_NONNULL1 OS_NONNULL3
const uint64_t *
img4_image_get_property_uint64(img4_image_t image,
		img4_4cc_t _4cc,
		uint64_t *storage);
#else
#define img4_image_get_property_uint64(...) \
		(img4if->i4if_v7.image_get_property_uint64(__VA_ARGS__))
#endif

/*!
 * @function img4_image_get_property_data
 * Retrieves the buffer value for the requested image property.
 *
 * @param image
 * The image to query.
 *
 * @param _4cc
 * The 4cc of the desired image property.
 *
 * @param storage
 * A pointer to storage for a buffer value.
 *
 * @result
 * If the property is present for the image, a pointer to the storage provided
 * in {@link storage}. If the property is not present in the image or its value
 * is not a data, NULL is returned.
 */
#if !XNU_KERNEL_PRIVATE
IMG4_API_AVAILABLE_20200508
OS_EXPORT OS_WARN_RESULT OS_NONNULL1 OS_NONNULL3
const img4_buff_t *
img4_image_get_property_data(img4_image_t image,
		img4_4cc_t _4cc,
		img4_buff_t *storage);
#else
#define img4_image_get_property_data(...) \
		(img4if->i4if_v7.image_get_property_data(__VA_ARGS__))
#endif

OS_ASSUME_NONNULL_END

#endif // __IMG4_IMAGE_H
