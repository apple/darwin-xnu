#ifndef _KXLD_DEMANGLE_H_
#define _KXLD_DEMANGLE_H_

#include <sys/types.h>

/* @function kxld_demangle
   
 * @abstract Demangles c++ symbols. 
 * 
 * @param str           The C-string to be demangled.
 * @param buffer        A pointer to a character buffer for storing the result.
 *                      If NULL, a buffer will be malloc'd and stored here.
 *                      If the buffer is not large enough, it will be realloc'd.
 *
 * @param length        The length of the buffer.
 * 
 * @result              If the input string could be demangled, it returns the
 *                      demangled string.  Otherwise, returns the input string.
 * 
 */
const char * kxld_demangle(const char *str, char **buffer, size_t *length)
    __attribute__((pure, nonnull, visibility("hidden")));

#endif /* !_KXLD_DEMANGLE_H_ */
