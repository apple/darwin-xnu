#ifndef _LIBSA_MACH_MACH_H_
#define _LIBSA_MACH_MACH_H_

#include <mach/mach_types.h>
#include <mach/vm_map.h>

__private_extern__ vm_map_t mach_task_self(void);

char *mach_error_string(kern_return_t);


#endif /* _LIBSA_MACH_MACH_H_ */
