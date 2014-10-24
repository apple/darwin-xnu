#ifndef __FAIL_H_
#define __FAIL_H_

#define TOSTRING_HELPER(x) #x
#define TOSTRING(x) TOSTRING_HELPER(x)

#define PERFINDEX_FAILURE -1
#define PERFINDEX_SUCCESS 0

extern char* error_str;

#define FAIL(message) do {\
    error_str = message " at " __FILE__ ": " TOSTRING(__LINE__);\
    return PERFINDEX_FAILURE;\
} while(0)

#define VERIFY(condition, fail_message) do {\
    if(!(condition)) FAIL(fail_message);\
} while(0)

#endif
