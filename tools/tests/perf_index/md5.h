#ifndef __MD5_H_
#define __MD5_H_

#include <stdint.h>

void md5_hash(uint8_t *message, uint64_t len, uint32_t *hash);

#endif
