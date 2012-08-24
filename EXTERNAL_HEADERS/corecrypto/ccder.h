/*
 *  ccder.h
 *  corecrypto
 *
 *  Created by Michael Brouwer on 2/28/12.
 *  Copyright 2012 Apple Inc. All rights reserved.
 *
 */

#ifndef _CORECRYPTO_CCDER_H_
#define _CORECRYPTO_CCDER_H_

#include <corecrypto/ccasn1.h>
#include <corecrypto/ccn.h>

#define CCDER_MULTIBYTE_TAGS  1

#ifdef CCDER_MULTIBYTE_TAGS
typedef unsigned long ccder_tag;
#else
typedef uint8_t ccder_tag;
#endif

/* DER types to be used with ccder_decode and ccder_encode functions. */
enum {
    CCDER_EOL               = CCASN1_EOL,
    CCDER_BOOLEAN           = CCASN1_BOOLEAN,
    CCDER_INTEGER           = CCASN1_INTEGER,
    CCDER_BIT_STRING        = CCASN1_BIT_STRING,
    CCDER_OCTET_STRING      = CCASN1_OCTET_STRING,
    CCDER_NULL              = CCASN1_NULL,
    CCDER_OBJECT_IDENTIFIER = CCASN1_OBJECT_IDENTIFIER,
    CCDER_OBJECT_DESCRIPTOR = CCASN1_OBJECT_DESCRIPTOR,
    /* External or instance-of 0x08 */
    CCDER_REAL              = CCASN1_REAL,
    CCDER_ENUMERATED        = CCASN1_ENUMERATED,
    CCDER_EMBEDDED_PDV      = CCASN1_EMBEDDED_PDV,
    CCDER_UTF8_STRING       = CCASN1_UTF8_STRING,
    /*                         0x0d */
    /*                         0x0e */
    /*                         0x0f */
    CCDER_SEQUENCE          = CCASN1_SEQUENCE,
    CCDER_SET               = CCASN1_SET,
    CCDER_NUMERIC_STRING    = CCASN1_NUMERIC_STRING,
    CCDER_PRINTABLE_STRING  = CCASN1_PRINTABLE_STRING,
    CCDER_T61_STRING        = CCASN1_T61_STRING,
    CCDER_VIDEOTEX_STRING   = CCASN1_VIDEOTEX_STRING,
    CCDER_IA5_STRING        = CCASN1_IA5_STRING,
    CCDER_UTC_TIME          = CCASN1_UTC_TIME,
    CCDER_GENERALIZED_TIME  = CCASN1_GENERALIZED_TIME,
    CCDER_GRAPHIC_STRING    = CCASN1_GRAPHIC_STRING,
    CCDER_VISIBLE_STRING    = CCASN1_VISIBLE_STRING,
    CCDER_GENERAL_STRING    = CCASN1_GENERAL_STRING,
    CCDER_UNIVERSAL_STRING  = CCASN1_UNIVERSAL_STRING,
    /*                         0x1d */
    CCDER_BMP_STRING        = CCASN1_BMP_STRING,
    CCDER_HIGH_TAG_NUMBER   = CCASN1_HIGH_TAG_NUMBER,
    CCDER_TELETEX_STRING    = CCDER_T61_STRING,

#ifdef CCDER_MULTIBYTE_TAGS
    CCDER_TAG_MASK          = ((ccder_tag)~0),
    CCDER_TAGNUM_MASK       = ((ccder_tag)~((ccder_tag)7 << (sizeof(ccder_tag) * 8 - 3))),

    CCDER_METHOD_MASK       = ((ccder_tag)1 << (sizeof(ccder_tag) * 8 - 3)),
    CCDER_PRIMITIVE         = ((ccder_tag)0 << (sizeof(ccder_tag) * 8 - 3)),
    CCDER_CONSTRUCTED       = ((ccder_tag)1 << (sizeof(ccder_tag) * 8 - 3)),

    CCDER_CLASS_MASK        = ((ccder_tag)3 << (sizeof(ccder_tag) * 8 - 2)),
    CCDER_UNIVERSAL         = ((ccder_tag)0 << (sizeof(ccder_tag) * 8 - 2)),
    CCDER_APPLICATION       = ((ccder_tag)1 << (sizeof(ccder_tag) * 8 - 2)),
    CCDER_CONTEXT_SPECIFIC  = ((ccder_tag)2 << (sizeof(ccder_tag) * 8 - 2)),
    CCDER_PRIVATE           = ((ccder_tag)3 << (sizeof(ccder_tag) * 8 - 2)),
#else
    CCDER_TAG_MASK			= CCASN1_TAG_MASK,
    CCDER_TAGNUM_MASK		= CCASN1_TAGNUM_MASK,

    CCDER_METHOD_MASK		= CCASN1_METHOD_MASK,
    CCDER_PRIMITIVE         = CCASN1_PRIMITIVE,
    CCDER_CONSTRUCTED		= CCASN1_CONSTRUCTED,

    CCDER_CLASS_MASK		= CCASN1_CLASS_MASK,
    CCDER_UNIVERSAL         = CCASN1_UNIVERSAL,
    CCDER_APPLICATION		= CCASN1_APPLICATION,
    CCDER_CONTEXT_SPECIFIC	= CCASN1_CONTEXT_SPECIFIC,
    CCDER_PRIVATE			= CCASN1_PRIVATE,
#endif
    CCDER_CONSTRUCTED_SET   = CCDER_SET | CCDER_CONSTRUCTED,
    CCDER_CONSTRUCTED_SEQUENCE = CCDER_SEQUENCE | CCDER_CONSTRUCTED,
};


#pragma mark ccder_sizeof_ functions

inline CC_CONST
size_t ccder_sizeof_tag(ccder_tag tag);

inline CC_CONST
size_t ccder_sizeof_len(size_t len);

/* Returns the size of an asn1 encoded item of length l in bytes,
 assuming a 1 byte tag. */
inline CC_CONST
size_t ccder_sizeof(ccder_tag tag, size_t len);

inline CC_CONST
size_t ccder_sizeof_oid(ccoid_t oid);

#pragma mark ccder_encode_ functions.

/* Encode a tag backwards, der_end should point to one byte past the end of
   destination for the tag, returns a pointer to the first byte of the tag.
   Returns NULL if there is an encoding error. */
inline CC_NONNULL2
uint8_t *ccder_encode_tag(ccder_tag tag, const uint8_t *der, uint8_t *der_end);

/* Returns a pointer to the start of the len field.  returns NULL if there
 is an encoding error. */
inline CC_NONNULL2
uint8_t *
ccder_encode_len(size_t len, const uint8_t *der, uint8_t *der_end);

/* der_end should point to the first byte of the content of this der item. */
inline CC_NONNULL3
uint8_t *
ccder_encode_tl(ccder_tag tag, size_t len, const uint8_t *der, uint8_t *der_end);

inline CC_PURE CC_NONNULL2
uint8_t *
ccder_encode_body_nocopy(size_t size, const uint8_t *der, uint8_t *der_end);

/* Encode the tag and length of a constructed object.  der is the lower
   bound, der_end is one byte paste where we want to write the length and
   body_end is one byte past the end of the body of the der object we are
   encoding the tag and length of. */
inline CC_NONNULL((2,3))
uint8_t *
ccder_encode_constructed_tl(ccder_tag tag, const uint8_t *body_end,
                            const uint8_t *der, uint8_t *der_end);

/* Encodes oid into der and returns
 der + ccder_sizeof_oid(oid). */
inline CC_NONNULL1 CC_NONNULL2
uint8_t *ccder_encode_oid(ccoid_t oid, const uint8_t *der, uint8_t *der_end);

inline CC_NONNULL((3,4))
uint8_t *ccder_encode_implicit_integer(ccder_tag implicit_tag,
                                       cc_size n, const cc_unit *s,
                                       const uint8_t *der, uint8_t *der_end);

inline CC_NONNULL((2,3))
uint8_t *ccder_encode_integer(cc_size n, const cc_unit *s,
                              const uint8_t *der, uint8_t *der_end);

inline CC_NONNULL3
uint8_t *ccder_encode_implicit_uint64(ccder_tag implicit_tag,
                                      uint64_t value,
                                      const uint8_t *der, uint8_t *der_end);

inline CC_NONNULL3
uint8_t *ccder_encode_uint64(uint64_t value,
                             const uint8_t *der, uint8_t *der_end);

inline CC_NONNULL((3,4))
uint8_t *ccder_encode_implicit_octet_string(ccder_tag implicit_tag,
                                            cc_size n, const cc_unit *s,
                                            const uint8_t *der,
                                            uint8_t *der_end);

inline CC_NONNULL((2,3))
uint8_t *ccder_encode_octet_string(cc_size n, const cc_unit *s,
                                   const uint8_t *der, uint8_t *der_end);

inline CC_NONNULL((3,4))
uint8_t *ccder_encode_implicit_raw_octet_string(ccder_tag implicit_tag,
                                                size_t s_size, const uint8_t *s,
                                                const uint8_t *der,
                                                uint8_t *der_end);

inline CC_NONNULL((2,3))
uint8_t *ccder_encode_raw_octet_string(size_t s_size, const uint8_t *s,
                                       const uint8_t *der, uint8_t *der_end);

/* ccder_encode_body COPIES the body into the der.
   It's inefficient – especially when you already have to convert to get to
   the form for the body.
   see encode integer for the right way to unify conversion and insertion */
inline CC_NONNULL3
uint8_t *
ccder_encode_body(size_t size, const uint8_t* body,
                  const uint8_t *der, uint8_t *der_end);

#pragma mark ccder_decode_ functions.

/* Returns a pointer to the start of the length field, and returns the decoded tag in tag.
 returns NULL if there is a decoding error. */
inline CC_NONNULL((1,3))
const uint8_t *ccder_decode_tag(ccder_tag *tagp, const uint8_t *der, const uint8_t *der_end);

inline CC_NONNULL((1,3))
const uint8_t *ccder_decode_len(size_t *lenp, const uint8_t *der, const uint8_t *der_end);

/* Returns a pointer to the start of the der object, and returns the length in len.
 returns NULL if there is a decoding error. */
inline CC_NONNULL((2,4))
const uint8_t *ccder_decode_tl(ccder_tag expected_tag, size_t *lenp,
                               const uint8_t *der, const uint8_t *der_end);

inline CC_NONNULL((2,3))
const uint8_t *
ccder_decode_constructed_tl(ccder_tag expected_tag, const uint8_t **body_end,
                            const uint8_t *der, const uint8_t *der_end);

inline CC_NONNULL((1,3))
const uint8_t *
ccder_decode_sequence_tl(const uint8_t **body_end,
                         const uint8_t *der, const uint8_t *der_end);

inline CC_NONNULL((2,4))
const uint8_t *ccder_decode_uint(cc_size n, cc_unit *r,
                                 const uint8_t *der, const uint8_t *der_end);

inline CC_NONNULL((1,3))
const uint8_t *ccder_decode_uint64(uint64_t* r,
                                   const uint8_t *der, const uint8_t *der_end);

/* Decode SEQUENCE { r, s -- (unsigned)integer } in der into r and s.
   Returns NULL on decode errors, returns pointer just past the end of the
   sequence of integers otherwise. */
inline CC_NONNULL((2,3,5))
const uint8_t *ccder_decode_seqii(cc_size n, cc_unit *r, cc_unit *s,
                                  const uint8_t *der, const uint8_t *der_end);
inline CC_NONNULL_ALL
const uint8_t *ccder_decode_oid(ccoid_t *oidp,
                                const uint8_t *der, const uint8_t *der_end);

#ifndef CCDER_MULTIBYTE_TAGS
#include <corecrypto/ccder_decode_constructed_tl.h>
#include <corecrypto/ccder_decode_len.h>
#include <corecrypto/ccder_decode_oid.h>
#include <corecrypto/ccder_decode_seqii.h>
#include <corecrypto/ccder_decode_sequence_tl.h>
#include <corecrypto/ccder_decode_tag.h>
#include <corecrypto/ccder_decode_tl.h>
#include <corecrypto/ccder_decode_uint.h>
#include <corecrypto/ccder_encode_body_nocopy.h>
#include <corecrypto/ccder_encode_constructed_tl.h>
#include <corecrypto/ccder_encode_implicit_integer.h>
#include <corecrypto/ccder_encode_implicit_octet_string.h>
#include <corecrypto/ccder_encode_implicit_uint64.h>
#include <corecrypto/ccder_encode_integer.h>
#include <corecrypto/ccder_encode_len.h>
#include <corecrypto/ccder_encode_octet_string.h>
#include <corecrypto/ccder_encode_oid.h>
#include <corecrypto/ccder_encode_tag.h>
#include <corecrypto/ccder_encode_tl.h>
#include <corecrypto/ccder_encode_uint64.h>
#include <corecrypto/ccder_sizeof.h>
#include <corecrypto/ccder_sizeof_len.h>
#include <corecrypto/ccder_sizeof_oid.h>
#include <corecrypto/ccder_sizeof_tag.h>
#endif

#endif /* _CORECRYPTO_CCDER_H_ */
