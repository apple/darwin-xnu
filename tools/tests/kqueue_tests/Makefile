all: readwrite timer

readwrite:
	gcc -o readwrite_tests kqueue_readwrite_tests.c -arch ppc -arch i386

timer:
	gcc -o timer_tests kqueue_timer_tests.c -arch ppc -arch i386 -arch x86_64
