ifdef RC_BUILDIT
DOING_BUILDIT=yes
endif

ifdef RC_OS
DOING_BUILDIT=yes
endif

ifdef DOING_BUILDIT
include $(MAKEFILEPATH)/CoreOS/ReleaseControl/Common.make
MY_ARCH = $(patsubst %, -arch %, $(RC_ARCHS)) 
install:: xnu_quick_test
else
	ifndef SRCROOT
		SRCROOT=$(shell /bin/pwd)
	endif
	ifndef OBJROOT
		OBJROOT=$(SRCROOT)/BUILD/obj
	endif
	ifndef DSTROOT
		DSTROOT=$(SRCROOT)/BUILD/dst
	endif
	
	ifndef ARCH
		ARCH=i386 x86_64 ppc ppc64
	endif
	
	ifdef ARCH
		MY_ARCH = $(patsubst %, -arch %, $(ARCH)) # allows building multiple archs.
	endif

	CFLAGS += $(MY_ARCH)
endif

CFLAGS += -g -I /System/Library/Frameworks/System.framework/Versions/B/PrivateHeaders/ -F/AppleInternal/Library/Frameworks/ $(MORECFLAGS)
LIBFLAGS = -I /System/Library/Frameworks/System.framework/Versions/B/PrivateHeaders/ -F/AppleInternal/Library/Frameworks/ -framework XILog
#CFLAGS+= $(MY_ARCH) -g -D_POSIX_C_SOURCE=200112L

MY_OBJECTS = $(OBJROOT)/main.o $(OBJROOT)/memory_tests.o $(OBJROOT)/misc.o \
			 $(OBJROOT)/sema_tests.o $(OBJROOT)/shared_memory_tests.o \
			 $(OBJROOT)/socket_tests.o $(OBJROOT)/tests.o $(OBJROOT)/xattr_tests.o


xnu_quick_test : $(OBJROOT) $(DSTROOT) $(MY_OBJECTS) helpers
	sudo rm -rf $(DSTROOT)/xnu_quick_test
	cc $(MY_ARCH) $(LIBFLAGS) -o $(DSTROOT)/xnu_quick_test $(MY_OBJECTS)
	sudo chown root $(DSTROOT)/xnu_quick_test
	sudo chmod 4755 $(DSTROOT)/xnu_quick_test

# The helper binaries are used to test exec()'ing between 64bit and 32bit. 
# Creates test binaries with page zero sizes = 4KB and 4GB. Also creates 32-bit
# helper processes for the 64-bit version of xnu_quick_test to test the conversion
# from a 32-bit process to a 64-bit process.
helpers : helpers/sleep.c helpers/launch.c helpers/arch.c helperdir $(OBJROOT)/misc.o
	gcc -arch ppc                               helpers/sleep.c -o $(DSTROOT)/helpers/sleep-ppc32
	gcc -arch i386                              helpers/sleep.c -o $(DSTROOT)/helpers/sleep-i386
	gcc -arch x86_64 -pagezero_size 0x100000000 helpers/sleep.c -o $(DSTROOT)/helpers/sleep-x86_64-4G
	gcc -arch x86_64 -pagezero_size 0x1000      helpers/sleep.c -o $(DSTROOT)/helpers/sleep-x86_64-4K
	gcc -arch ppc64  -pagezero_size 0x100000000 helpers/sleep.c -o $(DSTROOT)/helpers/sleep-ppc64-4G
	gcc -arch ppc64  -pagezero_size 0x1000      helpers/sleep.c -o $(DSTROOT)/helpers/sleep-ppc64-4K
	gcc $(LIBFLAGS) -arch i386	$(OBJROOT)/misc.o helpers/launch.c -o $(DSTROOT)/helpers/launch-i386
	gcc $(LIBFLAGS) -arch x86_64	$(OBJROOT)/misc.o helpers/launch.c -o $(DSTROOT)/helpers/launch-x86_64
	gcc $(LIBFLAGS) -arch ppc	$(OBJROOT)/misc.o helpers/launch.c -o $(DSTROOT)/helpers/launch-ppc
	gcc $(LIBFLAGS) -arch ppc64	$(OBJROOT)/misc.o helpers/launch.c -o $(DSTROOT)/helpers/launch-ppc64
	gcc -arch ppc -arch ppc64 -arch i386 -arch x86_64 helpers/arch.c -o $(DSTROOT)/helpers/arch
	
helperdir :
	mkdir -p $(DSTROOT)/helpers

$(OBJROOT) :
	mkdir -p $(OBJROOT);
	
$(DSTROOT) :
	mkdir -p $(DSTROOT);

INCLUDES = /Developer/SDKs/Purple/System/Library/Frameworks/System.framework/Versions/B/PrivateHeaders/
	

$(OBJROOT)/main.o : main.c tests.h
	cc $(CFLAGS) -c main.c  -o $@
	
$(OBJROOT)/memory_tests.o : memory_tests.c tests.h
	cc $(CFLAGS) -c memory_tests.c  -o $@

# misc.o has to be built 4-way for the helpers to link
$(OBJROOT)/misc.o : misc.c tests.h
	cc -arch i386 -arch x86_64 -arch ppc -arch ppc64 $(CFLAGS) -c misc.c   -o $@
	
$(OBJROOT)/sema_tests.o : sema_tests.c tests.h
	cc $(CFLAGS) -c sema_tests.c   -o $@
	
$(OBJROOT)/shared_memory_tests.o : shared_memory_tests.c tests.h
	cc $(CFLAGS) -c shared_memory_tests.c   -o $@

$(OBJROOT)/socket_tests.o : socket_tests.c tests.h
	cc $(CFLAGS) -c socket_tests.c   -o $@

$(OBJROOT)/tests.o : tests.c tests.h
	cc $(CFLAGS) -c tests.c    -o $@

$(OBJROOT)/xattr_tests.o : xattr_tests.c tests.h
	cc $(CFLAGS) -c xattr_tests.c    -o $@


ifndef DOING_BUILDIT
.PHONY : clean
clean :
	sudo rm -f $(DSTROOT)/xnu_quick_test
	sudo rm -f $(DSTROOT)/helpers/*
	rm -f $(OBJROOT)/*.o
endif

