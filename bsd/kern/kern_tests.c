/***************************************************************
 *                 Test Declarations Go Here 		       *
 ***************************************************************/
#include <pexpert/pexpert.h>
#include <sys/sysctl.h>
#include <kern/debug.h>
#include <sys/kern_tests.h>

/***************************************************************
 *                 End Test Declarations 		       *
 ***************************************************************/
typedef int (*xnu_test_func_t)(void);

typedef struct xnu_test {
	xnu_test_func_t t_func;
	const char *t_name;
} xnu_test_t;

#define DEFINE_XNU_TEST(func) { func, #func }

xnu_test_t xnu_tests[] = {
};

#define NUM_XNU_TESTS (sizeof(xnu_tests) / sizeof(xnu_test_t))

static int
run_xnu_tests
(struct sysctl_oid *oidp, __unused void *arg1, __unused int arg2, struct sysctl_req *req)
{
	unsigned i;
	int result;

	for (i = 0; i < NUM_XNU_TESTS; i++) {
		result = xnu_tests[i].t_func();
		if (result == 0) {
			kprintf("xnu_tests: %s passed.\n", xnu_tests[i].t_name);
		} else{
			panic("xnu_tests: %s failed.\n", xnu_tests[i].t_name);
		} 
	}

	return sysctl_handle_int(oidp, NULL, 0, req);
}

SYSCTL_PROC(_kern, OID_AUTO, kern_tests,
		CTLTYPE_INT | CTLFLAG_RD | CTLFLAG_LOCKED,
		0, 0, run_xnu_tests, "I", "");

