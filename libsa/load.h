#ifndef __LOAD_H__
#define __LOAD_H__

#ifdef __cplusplus
extern "C" {
#endif

#include "dgraph.h"

#ifdef KERNEL
#else
#include "KXKext.h"
#endif /* KERNEL */

#ifndef KERNEL
typedef KXKextManagerError kload_error;
enum {
    kload_error_none              = kKXKextManagerErrorNone,
    kload_error_unspecified       = kKXKextManagerErrorUnspecified,
    kload_error_invalid_argument  = kKXKextManagerErrorInvalidArgument,
    kload_error_no_memory         = kKXKextManagerErrorNoMemory,

    kload_error_user_abort        = kKXKextManagerErrorUserAbort,
    kload_error_kernel_error      = kKXKextManagerErrorKernelError,
    kload_error_kernel_permission = kKXKextManagerErrorKernelPermission,

    kload_error_executable_bad         = kKXKextManagerErrorLoadExecutableBad,
    kload_error_already_loaded         = kKXKextManagerErrorAlreadyLoaded,
    kload_error_loaded_version_differs = kKXKextManagerErrorLoadedVersionDiffers,
    kload_error_dependency_loaded_version_differs = kKXKextManagerErrorDependencyLoadedVersionDiffers,
    kload_error_link_load              = kKXKextManagerErrorLinkLoad
};

typedef KXKextManagerLogLevel kload_log_level;
enum {
    kload_log_level_silent       = kKXKextManagerLogLevelSilent,
    kload_log_level_errors_only  = kKXKextManagerLogLevelErrorsOnly,
    kload_log_level_default      = kKXKextManagerLogLevelDefault,
    kload_log_level_basic        = kKXKextManagerLogLevelBasic,
    kload_log_level_load_basic   = kKXKextManagerLogLevelLoadBasic,
    kload_log_level_details      = kKXKextManagerLogLevelDetails,
    kload_log_level_kexts        = kKXKextManagerLogLevelKexts,
    kload_log_level_kext_details = kKXKextManagerLogLevelKextDetails,
    kload_log_level_load_details = kKXKextManagerLogLevelLoadDetails
};
#else

typedef enum {
    kload_error_none,
    kload_error_unspecified,
    kload_error_invalid_argument,
    kload_error_no_memory,

    kload_error_user_abort,
    kload_error_kernel_error,
    kload_error_kernel_permission,

    kload_error_executable_bad,
    kload_error_already_loaded,
    kload_error_loaded_version_differs,
    kload_error_dependency_loaded_version_differs,
    kload_error_link_load
} kload_error;

typedef enum {
    kload_log_level_silent       = -2,   // no notices, no errors
    kload_log_level_errors_only  = -1,
    kload_log_level_default      = 0,
    kload_log_level_basic        = 1,
    kload_log_level_load_basic   = 2,
    kload_log_level_details      = 3,
    kload_log_level_kexts        = 4,
    kload_log_level_kext_details = 5,
    kload_log_level_load_details = 6
} kload_log_level;

#endif /* KERNEL */


kload_error kload_load_dgraph(dgraph_t * dgraph
#ifndef KERNEL
    ,
    const char * kernel_file,
    const char * patch_file, const char * patch_dir,
    const char * symbol_file, const char * symbol_dir,
    int do_load, int do_start_kmod, int do_prelink,
    int interactive_level,
    int ask_overwrite_symbols, int overwrite_symbols
#endif /* not KERNEL */
    );

#ifndef KERNEL
kload_error kload_load_with_arglist(
    int argc, char **argv,
    const char * kernel_file,
    const char * patch_file, const char * patch_dir,
    const char * symbol_file, const char * symbol_dir,
    int do_load, int do_start_kmod,
    int interactive_level,
    int ask_overwrite_symbols, int overwrite_symbols);
#endif /* not KERNEL */

kload_error kload_map_dgraph(dgraph_t * dgraph
#ifndef KERNEL
    ,
    const char * kernel_file
#endif /* not KERNEL */
    );
kload_error kload_map_entry(dgraph_entry_t * entry);

#ifndef KERNEL
int kload_file_exists(const char * path);
kload_error kload_request_load_addresses(
    dgraph_t * dgraph,
    const char * kernel_file);
kload_error kload_set_load_addresses_from_args(
    dgraph_t * dgraph,
    const char * kernel_file,
    char ** addresses);
#endif /* not KERNEL */

kload_error kload_set_load_addresses_from_kernel(
    dgraph_t * dgraph
#ifndef KERNEL
    ,
    const char * kernel_file,
    int do_load
#endif /* not KERNEL */
    );

void kload_set_log_level(kload_log_level level);
#ifndef KERNEL
void kload_set_log_function(
    void (*)(const char * format, ...));
void kload_set_error_log_function(
    void (*)(const char * format, ...));
void kload_set_user_approve_function(
    int (*)(int default_answer, const char * format, ...));
void kload_set_user_veto_function(
    int (*)(int default_answer, const char * format, ...));
void kload_set_user_input_function(
    const char * (*)(const char * format, ...));

void kload_log_message(const char * format, ...);
void kload_log_error(const char * format, ...);
#define KNL               ""

#else
#define kload_log_message IOLog
#define kload_log_error   IOLog
#define KNL               "\n"

#endif /* not KERNEL */



#endif /* __LOAD_H__ */

#ifdef __cplusplus
}
#endif

