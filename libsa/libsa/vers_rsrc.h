#ifndef _LIBSA_VERS_H_
#define _LIBSA_VERS_H_

#ifdef __cplusplus
extern "C" {
#endif

#ifndef KERNEL
#include <sys/types.h>
#include <libc.h>
#include <CoreFoundation/CoreFoundation.h>
#else
#include <libkern/OSTypes.h>
#endif KERNEL

typedef SInt64 VERS_version;
VERS_version VERS_parse_string(const char * vers_string);
int VERS_string(char * buffer, UInt32 length, VERS_version vers);

#ifdef __cplusplus
}
#endif

#endif _LIBSA_VERS_H_
