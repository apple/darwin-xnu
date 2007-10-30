CFLAGS=-g -Os -arch ppc -arch i386

TARGETS	= lockstat

all:	$(TARGETS)

lockstat: lockstat.c
	${CC} ${CFLAGS} -o $@ $?
clean:
	rm -rf $(TARGETS)
