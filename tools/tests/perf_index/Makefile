SDKROOT ?= /
Embedded?=$(shell echo $(SDKROOT) | grep -iq iphoneos && echo YES || echo NO)
CC:=xcrun -sdk "$(SDKROOT)" cc
CFLAGS:=-c -Wall -pedantic
OPTIMIZATION:=-Os
LDFLAGS=

SRCROOT?=$(shell /bin/pwd)
DSTROOT?=$(shell /bin/pwd)
OBJROOT?=$(shell /bin/pwd)

SOURCES:=main.c stress_cpu.c stress_memory.c stress_syscall.c stress_fault.c md5.c stress_file_create.c stress_file_write.c stress_file_read.c stress_file_local.c stress_file_ram.c iperf.c compile.c stress_general.c
SOURCE_PATHS:=$(addprefix $(SRCROOT)/,$(SOURCES))
OBJECTS:=$(addprefix $(OBJROOT)/,$(SOURCES:.c=.o))
EXECUTABLE=perf_index

ifdef RC_ARCHS
ARCHS:=$(RC_ARCHS)
else
ifeq ($(ARCHS),)
ifeq "$(Embedded)" "YES"
ARCHS:=armv7 armv7s
else
ARCHS:=x86_64 i386
endif
endif
endif

CFLAGS += $(patsubst %, -arch %, $(ARCHS))
LDFLAGS += $(patsubst %, -arch %, $(ARCHS))

all: $(SOURCE_PATHS) $(EXECUTABLE)

$(EXECUTABLE): $(OBJECTS) 
	$(CC) $(LDFLAGS) $(OBJECTS) -o $(DSTROOT)/$@

$(OBJROOT)/%.o: $(SRCROOT)/%.c
	$(CC) $(CFLAGS) $(OPTIMIZATION) $< -o $@

clean:
	rm -f *.o
	rm -f $(EXECUTABLE)
