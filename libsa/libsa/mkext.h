#ifndef _MKEXT_H_
#define _MKEXT_H_ 1

#include <sys/cdefs.h>
#include <sys/types.h>

#include <mach/machine.h>

#define MKEXT_MAGIC 'MKXT'
#define MKEXT_SIGN 'MOSX'

#define MKEXT_EXTN ".mkext"

// All binary values are big-endian

// If all fields are 0 then this file slot is empty
// If compsize is zero then the file isn't compressed.
typedef struct mkext_file {
    size_t offset;         // 4 bytes
    size_t compsize;       // 4 bytes
    size_t realsize;       // 4 bytes
    time_t modifiedsecs;   // 4 bytes
} mkext_file;

// The plist file entry is mandatory, but module may be empty
typedef struct mkext_kext {
    mkext_file plist;      // 16 bytes
    mkext_file module;     // 16 bytes
} mkext_kext;

typedef struct mkext_header {
    u_int32_t magic;          // 'MKXT'
    u_int32_t signature;      // 'MOSX'
    u_int32_t length;
    u_int32_t adler32;
    u_int32_t version;        // vers resource, currently '1.0.0', 0x01008000
    u_int32_t numkexts;
    cpu_type_t cputype;       // CPU_TYPE_ANY for fat executables
    cpu_subtype_t cpusubtype; // CPU_SUBTYPE_MULITPLE for executables
    mkext_kext kext[1];       // 64 bytes/entry
} mkext_header;

__BEGIN_DECLS
__private_extern__ u_int8_t *
compress_lzss(u_int8_t *dst, u_int32_t dstlen, u_int8_t *src, u_int32_t srclen);

__private_extern__ int
decompress_lzss(u_int8_t *dst, u_int8_t *src, u_int32_t srclen);

__private_extern__ u_int32_t
adler32(u_int8_t *src, int32_t length);

__END_DECLS

#endif /* _MKEXT_H_ */
