/* Copyright (c) (2017,2019) Apple Inc. All rights reserved.
 *
 * corecrypto is licensed under Apple Inc.’s Internal Use License Agreement (which
 * is contained in the License.txt file distributed with corecrypto) and only to 
 * people who accept that license. IMPORTANT:  Any license rights granted to you by 
 * Apple Inc. (if any) are limited to internal use within your organization only on 
 * devices and computers you own or control, for the sole purpose of verifying the 
 * security characteristics and correct functioning of the Apple Software.  You may 
 * not, directly or indirectly, redistribute the Apple Software or any portions thereof.
 */

#ifndef _CORECRYPTO_FIPSPOST_TRACE_H_
#define _CORECRYPTO_FIPSPOST_TRACE_H_

#if CC_FIPSPOST_TRACE

/*
 * Use this string to separate out tests.
 */
#define FIPSPOST_TRACE_TEST_STR    "?"

int fipspost_trace_is_active(void);
void fipspost_trace_call(const char *fname);

/* Only trace when VERBOSE is set to avoid impacting normal boots. */
#define FIPSPOST_TRACE_EVENT do {                                       \
    if (fipspost_trace_is_active()) {                                   \
        fipspost_trace_call(__FUNCTION__);                              \
    }                                                                   \
} while (0);

#define FIPSPOST_TRACE_MESSAGE(MSG) do {                                \
    if (fipspost_trace_is_active()) {                                   \
        fipspost_trace_call(MSG);                                       \
    }                                                                   \
} while (0);

#else

/* Not building a CC_FIPSPOST_TRACE-enabled, no TRACE operations. */
#define FIPSPOST_TRACE_EVENT
#define FIPSPOST_TRACE_MESSAGE(X)

#endif

#endif
