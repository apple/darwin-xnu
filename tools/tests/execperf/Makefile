SDKROOT ?= /
ARCHS = x86_64
CC = xcrun -sdk $(SDKROOT) cc
CODESIGN = xcrun -sdk $(SDKROOT) codesign
CFLAGS = -O0 -g -isysroot $(SDKROOT) $(patsubst %, -arch %,$(ARCHS))
LDFLAGS = -Wl,-new_linker -dead_strip \
	-isysroot $(SDKROOT) $(patsubst %, -arch %,$(ARCHS))
NOPIE_OPTION = -Wl,-no_pie

EXECUTABLES = exit.nodyld \
	exit.nopie.dyld-but-no-Libsystem exit.pie.dyld-but-no-Libsystem \
	exit.nopie.dyld-and-Libsystem exit.pie.dyld-and-Libsystem \
	exit.nopie exit.pie \
	printexecinfo
OBJECTS = exit-asm.o exit.o printexecinfo.o

default: $(EXECUTABLES) run

clean:
	rm -f run $(EXECUTABLES)
	rm -f run.o $(OBJECTS)

run.o: run.c
	$(CC) -c -o $@ $< $(CFLAGS)

run: run.o
	$(CC) -o $@ $< $(LDFLAGS)
	$(CODESIGN) -s - $@

# OBJECTS

exit-asm.o: exit-asm.S
	$(CC) -c -o $@ $< $(CFLAGS)

exit.o: exit.c
	$(CC) -c -o $@ $< $(CFLAGS)

printexecinfo.o: printexecinfo.c
	$(CC) -c -o $@ $< $(CFLAGS)

# EXECUTABLES

exit.nodyld: exit-asm.o
	$(CC) -o $@ $< $(LDFLAGS) -e mystart -nostartfiles -nodefaultlibs -static
	$(CODESIGN) -s - $@


exit.nopie.dyld-but-no-Libsystem: exit-asm.o
	$(CC) -o $@ $< $(LDFLAGS) -e mystart $(NOPIE_OPTION) -nostartfiles -nodefaultlibs
	$(CODESIGN) -s - $@

exit.pie.dyld-but-no-Libsystem: exit-asm.o
	$(CC) -o $@ $< $(LDFLAGS) -e mystart -Wl,-pie -nostartfiles -nodefaultlibs
	$(CODESIGN) -s - $@

exit.nopie.dyld-and-Libsystem: exit-asm.o
	$(CC) -o $@ $< $(LDFLAGS) -e mystart $(NOPIE_OPTION) -nostartfiles -nodefaultlibs -lSystem
	$(CODESIGN) -s - $@

exit.pie.dyld-and-Libsystem: exit-asm.o
	$(CC) -o $@ $< $(LDFLAGS) -e mystart -Wl,-pie -nostartfiles -nodefaultlibs -lSystem
	$(CODESIGN) -s - $@

exit.nopie: exit.o
	$(CC) -o $@ $< $(LDFLAGS) -e mystart $(NOPIE_OPTION)
	$(CODESIGN) -s - $@

exit.pie: exit.o
	$(CC) -o $@ $< $(LDFLAGS) -e mystart -Wl,-pie
	$(CODESIGN) -s - $@

printexecinfo: printexecinfo.o
	$(CC) -o $@ $< $(LDFLAGS)
	$(CODESIGN) -s - $@

# ACTIONS

quick-test: $(EXECUTABLES) run
	./test.sh
