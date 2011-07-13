CFLAGS=-g -Os -arch x86_64 -arch i386

TARGETS	= lockstat

all:	$(TARGETS)

lockstat: lockstat.c
	${CC} ${CFLAGS} -o $@ $?
clean:
	rm -rf $(TARGETS)
