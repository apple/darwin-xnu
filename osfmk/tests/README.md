# Kernel Power On Self Tests (POST)

The tests directories osfmk/tests and bsd/tests include set of tests that run in kernel at boot-time. The primary objective for these tests is to verify functionality of various subsystems like memory allocators, scheduling, VM, IPC ports etc. Following are some tips and guidelines to creating and running tests.

## Features:
  * Compiled out of RELEASE kernels.
  * enabled with boot-arg kernPOST [ 0x1 : for on desk testing, 0x3 for BATs testing]
  * Automatically skips tests that are designed to panic kernel for on-desk testing, but run in BATs environment.
  * Does not require complete install on device to run. Just kernelcache is enough.
  * Ability to check for assertions and panic path as well.

## How to run kernel POST

  * Start usbterm and setup your target machine/device in iBoot. 
  * set boot-args to include "```kernPOST=0x1```"" to enable kernel testing on boot.
  * load kernelcache using "```usb get /patch/to/kc```"
  * boot the image "```bootx```"
  * watch for nanokdp serial output with tags like "```[KTEST] <test> logs```"

## How do I configure to run just test #8?

Kernel POST supports configuring test through boot-args. For example if you want to run your test #8 (say you are tweaking it to do more testing). Just set "```kernPOST_config=8```" and only your test will be run. The configuration also takes ranges as follows
```
-> kernPOST_config=1_3,5_9999  # skip test#4. Will run tests 1,2,3 and 5,6 and onwards.
  
-> kernPOST_config=1_3,4_9999  # will not skip anything. lower_upper are both inclusive.
  
```

## How do I add a new test?
Adding a new kernel POST test is very simple. Here are a few steps and guidelines for adding tests.

  * There are two locations ```osfmk/tests/``` and ```bsd/tests``` where you can add tests based on your area of testing.
  * If you wish to add a new *.c* file for your tests then, use ```#include <xnupost.h>``` to include required functions and macros for testing. Remember to add file_name.c in ```osfmk/conf/files``` or ```bsd/conf/files``` as 
  
  ```osfmk/tests/my_tests.c   optional config_xnupost```
  * To add a test function just declare a function with prototype as 
  
  ```kern_return_t my_sample_tests(void); ```
  * And add to struct xnupost_test array in osfmk/tests/kernel_tests.c or bsd/tests/bsd_tests.c as 

```
struct xnupost_test kernel_post_tests[] = {
	XNUPOST_TEST_CONFIG_BASIC(my_sample_tests),  // simple test 
    XNUPOST_TEST_CONFIG_TEST_PANIC(panic_test) // test that is expected to panic 
};
```
  * And you are set. Use KERN_SUCCESS to report successful run and any other error for failure. Here is an example with some available macros.
  
```
kern_return_t my_sample_tests() {
    uint64_t test_begin_timestamp = 0;
    uint64_t cur_timestamp = 0, tmp;
    
    T_SETUPBEGIN; 
	test_begin_timestamp = mach_absolute_time();
	T_ASSERT_NOTNULL(test_begin_timestamp, "mach_absolute_time returned 0.");
    T_SETUPEND;
    
    T_LOG("Testing mach_absolute_time for 100 iterations");
    for (int i = 0; i < 100; i++) {
        tmp = mach_absolute_time();
        T_EXPECT_TRUE((cur_timestamp <= tmp ), "Time went backwards");
        cur_timestamp = tmp;
	}
    
	T_LOG("Completed mach_absolute_time tests.");
    return KERN_SUCCESS;
}
```

  * There are many ** T_* ** macros available for your convenience.
  * **Note**: Please make sure your test does a proper cleanup of state. The kernel is expected to continue to boot after testing. If you are unable to cleanup and require a reboot then use XNUPOST_TEST_CONFIG_TEST_PANIC type and panic at the end of the function. This will make sure the test controller reboots and runs the next test in automation.

## What is the difference between T_EXPECT and T_ASSERT macros?

  * T_ASSERT macros will check for condition and upon failure return with KERN_FAILURE. This way it ensures that no further execution of test code is done. 
  * T_EXPECT will just report failure of that test case, but will continue to run further test code.

## How do I run my tests in BATs?

Bats has a new test type **kernel_POST** that runs Lean test environment tests. You can run the following command to get POST testing.

```
~osdev/tat/dev/bin/bats  build  -b <build>  -t darwinLTE  -p  xnu:<branch> -r <radarnum>
```

## How do I test for panic/assertions?

The xnupost subsystem provides mechanism for setting up a `panic widget`. This widget can check for some conditions and report test case SUCCESS/FAILURE. See xnupost.h for `XT_RET* ` style return values. There are convenience macros for registering for generic panic and for assertion handling. For example if you wish to check for api foo(int arg) { assert(arg > 0); ... } then a test case could be like

```
kern_return_t test_foo_arg_assertion(void) {
	void * assert_retval = NULL;
	kern_return_t kr = T_REGISTER_ASSERT_CHECK("arg > 0", &assert_retval);
	T_ASSERT(kr == KERN_SUCCESS, "register assertion handler");

	foo(-1); /* this will cause assert to fire */

	T_ASSERT(assert_retval == (void *)XT_RET_W_SUCCESS, "verify assertion was hit");
}

```

## How do XNUPOST panic widgets work?

On debug/development kernels, the `panic()` code is modified to call out to XNUPOST system `xnupost_process_panic()`. This callout can then determine if testing was enabled and has a widget registered for checking panics. If yes, then the corresponding widget function is called and the return value determines what action is taken. For example a widget could return either of the following values

  XT_PANIC_UNRELATED    /* not related. continue panic */
  XT_RET_W_FAIL         /* report FAILURE and return from panic */
  XT_RET_W_SUCCESS      /* report SUCCESS and return from panic */
  XT_PANIC_W_FAIL       /* report FAILURE and continue to panic */
  XT_PANIC_W_SUCCESS    /* report SUCCESS and continue to panic */

The panic widget data is saved in internal data array where each is of type:
struct xnupost_panic_widget {
	void * xtp_context_p;  /* a context pointer for callbacks to track */
	void ** xtp_outval_p;  /* an out param for function to return some value to running test */
	const char * xtp_func_name;  /* widget name for tracking in serial output */
	xt_panic_widget_func xtp_func; 
};

There is an example use case in `osfmk/tests/kernel_tests.c :check_panic_test() and panic_test()` for writing a widget.
For basic assertion check see example in `osfmkt/tests/kernel_tests.c :kcdata_api_assert_tests()`

