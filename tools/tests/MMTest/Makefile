CFLAGS=-g -O2 -arch ppc -arch i386
CFLAGS64=-g -O2 -arch ppc64 -arch x86_64

TARGETS	= MMtest MMtest_64 MPMMtest MPMMtest_64

all:	$(TARGETS)

MMtest: MMtest.c
	${CC} ${CFLAGS} -o $@ $?

MMtest_64: MMtest.c
	${CC} ${CFLAGS64} -o $@ $?

MPMMtest: MPMMtest.c
	${CC} ${CFLAGS} -o $@ $?

MPMMtest_64: MPMMtest.c
	${CC} ${CFLAGS64} -o $@ $?

clean:
	rm -rf $(TARGETS)
