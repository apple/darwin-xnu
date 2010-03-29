#if !KERNEL

#include <stdlib.h>

/* This demangler is part of the C++ ABI.  We don't include it directly from
 * <cxxabi.h> so that we can avoid using C++ in the kernel linker.
 */
extern char * 
__cxa_demangle(const char* __mangled_name, char* __output_buffer,
               size_t* __length, int* __status);

#endif /* !KERNEL */

#include "kxld_demangle.h"

/*******************************************************************************
*******************************************************************************/
const char *
kxld_demangle(const char *str, char **buffer __unused, size_t *length __unused)
{
#if KERNEL
    return str;
#else
    const char *rval = NULL;
    char *demangled = NULL;
    int status;

    if (!str) goto finish;

    rval = str;

    if (!buffer || !length) goto finish;

    /* Symbol names in the symbol table have an extra '_' prepended to them,
     * so we skip the first character to make the demangler happy.
     */
    demangled = __cxa_demangle(str+1, *buffer, length, &status);
    if (!demangled || status) goto finish;
    
    *buffer = demangled;
    rval = demangled;
finish:
    return rval;
#endif
}

