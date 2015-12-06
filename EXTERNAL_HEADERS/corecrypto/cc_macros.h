/*
 *  cc_macros.h
 *  corecrypto
 *
 *  Created on 01/11/2012
 *
 *  Copyright (c) 2012,2015 Apple Inc. All rights reserved.
 *
 */

#ifndef _CORECRYPTO_CC_MACROS_H_
#define _CORECRYPTO_CC_MACROS_H_

#include <corecrypto/cc_config.h>

#ifndef __CC_DEBUG_ASSERT_COMPONENT_NAME_STRING
#define __CC_DEBUG_ASSERT_COMPONENT_NAME_STRING ""
#endif

#ifndef __CC_DEBUG_ASSERT_PRODUCTION_CODE
#define __CC_DEBUG_ASSERT_PRODUCTION_CODE !CORECRYPTO_DEBUG
#endif

#ifndef __CC_DEBUG_ASSERT_MESSAGE
#define __CC_DEBUG_ASSERT_MESSAGE(name, assertion, label, message, file, line, value) \
cc_printf( "CCAssertMacros: %s, %s file: %s, line: %d\n", assertion, (message!=0) ? message : "", file, line);
#endif

#ifndef cc_require
#if __CC_DEBUG_ASSERT_PRODUCTION_CODE
    #define cc_require(assertion, exceptionLabel) \
        do { \
            if ( __builtin_expect(!(assertion), 0) ) { \
                goto exceptionLabel; \
            } \
        } while ( 0 )
#else
    #define cc_require(assertion, exceptionLabel) \
        do { \
            if ( __builtin_expect(!(assertion), 0) ) { \
                __CC_DEBUG_ASSERT_MESSAGE(__CC_DEBUG_ASSERT_COMPONENT_NAME_STRING, \
                    #assertion, #exceptionLabel, 0, __FILE__, __LINE__,  0); \
                goto exceptionLabel; \
            } \
        } while ( 0 )
#endif
#endif

#ifndef cc_require_action
#if __CC_DEBUG_ASSERT_PRODUCTION_CODE
    #define cc_require_action(assertion, exceptionLabel, action)                \
        do                                                                      \
        {                                                                       \
            if ( __builtin_expect(!(assertion), 0) )                            \
            {                                                                   \
                {                                                               \
                    action;                                                     \
                }                                                               \
                goto exceptionLabel;                                            \
            }                                                                   \
        } while ( 0 )
#else
    #define cc_require_action(assertion, exceptionLabel, action)                \
        do                                                                      \
        {                                                                       \
            if ( __builtin_expect(!(assertion), 0) )                            \
            {                                                                   \
                __CC_DEBUG_ASSERT_MESSAGE(                                      \
                    __CC_DEBUG_ASSERT_COMPONENT_NAME_STRING,                    \
                    #assertion, #exceptionLabel, 0,   __FILE__, __LINE__, 0);   \
                {                                                               \
                    action;                                                     \
                }                                                               \
                goto exceptionLabel;                                            \
            }                                                                   \
        } while ( 0 )
#endif
#endif

#endif /* _CORECRYPTO_CC_MACROS_H_ */
