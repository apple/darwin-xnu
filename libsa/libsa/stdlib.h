#ifndef _LIBSA_STDLIB_H_
#define _LIBSA_STDLIB_H_


#ifndef _BSD_SIZE_T_DEFINED_
#define _BSD_SIZE_T_DEFINED_
typedef __SIZE_TYPE__    size_t;
#endif

#ifndef NULL
#define NULL   (0)
#endif


__private_extern__ char *kld_basefile_name;


__private_extern__ void * malloc(size_t size);
__private_extern__ void   free(void * address);
__private_extern__ void   free_all(void);     // "Free" all memory blocks
__private_extern__ void   malloc_reset(void); // Destroy all memory regions
__private_extern__ void * realloc(void * address, size_t new_size);

__private_extern__ char * strrchr(const char *cp, int ch);

__private_extern__ void qsort(
    void * array,
    size_t nmembers,
    size_t member_size,
    int (*)(const void *, const void *));

__private_extern__ void * bsearch(
    register const void *key,
    const void *base0,
    size_t nmemb,
    register size_t size,
    register int (*compar)(const void *, const void *));


/* These are defined in the kernel.
 */
extern long     strtol(const char *, char **, int);
extern unsigned long strtoul(const char *, char **, int);

#endif _LIBSA_STDLIB_H_
