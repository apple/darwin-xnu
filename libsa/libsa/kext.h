#ifdef __cplusplus
extern "C" {
#endif /* __cplusplus */

#include <mach/kern_return.h>

__private_extern__ kern_return_t load_kernel_extension(char * kmod_name);
__private_extern__ void load_security_extensions (void);


#ifdef __cplusplus
};
#endif /* __cplusplus */

