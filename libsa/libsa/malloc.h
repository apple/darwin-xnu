#ifndef _LIBSA_MALLOC_H_
#define _LIBSA_MALLOC_H_

#include <sys/cdefs.h>

__BEGIN_DECLS

/*****
 * These functions are the minimum necessary for use
 * by kld and its client.
 */
void * malloc(size_t size);
void * realloc(void * address, size_t new_size);
void   free(void * address);

void   malloc_init(void);
void   malloc_reset(void); // Destroy all memory regions


/*****
 * These functions aren't compiled into the kernel.
 * Their definitions are in the files malloc_debug
 * and malloc_unused, in case they're ever needed.
 */
#if 0
void   free_all(void);     // "Free" all memory blocks
size_t malloc_size(void * address);
int    malloc_is_valid(void * address);

#ifdef DEBUG
size_t malloc_hiwat(void);
size_t malloc_current_usage(void);
size_t malloc_region_usage(void);
double malloc_peak_usage(void);
double malloc_min_usage(void);
size_t malloc_unused(void);
double malloc_current_efficiency(void);
void malloc_clear_hiwat(void);
void malloc_report(void);
int malloc_sanity_check(void);
#endif /* DEBUG */
#endif /* 0 */

__END_DECLS

#endif /* defined _LIBSA_MALLOC_H_ */
