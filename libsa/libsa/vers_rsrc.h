#ifndef _LIBSA_VERS_H_
#define _LIBSA_VERS_H_

#include <libkern/OSTypes.h>

typedef union {
    UInt32 vnum;
    UInt8  bytes[4];
} VERS_version;

typedef enum {
    VERS_development = 0x20,
    VERS_alpha       = 0x40,
    VERS_beta        = 0x60,
    VERS_candidate   = 0x70,  // for interim usage only!
    VERS_release     = 0x80,
    VERS_invalid     = 0xff
} VERS_revision;

#define BCD_combine(l, r)  ( (((l) & 0xf) << 4) | ((r) & 0xf) )
#define BCD_get_left(p)    ( ((p) >> 4) & 0xf )
#define BCD_get_right(p)   ( (p) & 0xf )

#define BCD_illegal  (0xff)   // full byte, 11111111

int VERS_parse_string(const char * vers_string, UInt32 * version_num);
int VERS_string(char * buffer, UInt32 length, UInt32 vers);

#endif /* _LIBSA_VERS_H_ */
