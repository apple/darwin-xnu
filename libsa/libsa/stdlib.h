#ifndef _LIBSA_STDLIB_H_
#define _LIBSA_STDLIB_H_

#include <sys/cdefs.h>
#include <sys/_types.h>

#ifndef _SIZE_T
#define _SIZE_T
typedef __darwin_size_t	size_t;
#endif

#ifndef NULL
#if defined (__cplusplus)
#define NULL 0
#else
#define NULL ((void *)0)
#endif
#endif


__private_extern__ const char *kld_basefile_name;


__BEGIN_DECLS


__private_extern__ void * malloc(size_t size);
__private_extern__ void   free(void * address);
__private_extern__ void   free_all(void);     // "Free" all memory blocks
__private_extern__ void   malloc_reset(void); // Destroy all memory regions
__private_extern__ void * realloc(void * address, size_t new_size);

__private_extern__ char * strrchr(const char *cp, int ch);
__private_extern__ char * strstr(const char *in, const char *str);

__private_extern__ void qsort(
    void * array,
    size_t nmembers,
    size_t member_size,
    int (*)(const void *, const void *));

__private_extern__ const void * bsearch(
    register const void *key,
    const void *base0,
    size_t nmemb,
    register size_t size,
    register int (*compar)(const void *, const void *));

__END_DECLS

#endif /* _LIBSA_STDLIB_H_ */
