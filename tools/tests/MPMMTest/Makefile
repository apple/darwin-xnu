CFLAGS=-g -O2 -arch ppc -arch i386
CFLAGS64=-g -O2 -arch x86_64

TARGETS	= MPMMtest MPMMtest_64 KQMPMMtest KQMPMMtest_64 KQMPMMtestD KQMPMMtest_64D

all:	$(TARGETS)

MPMMtest: MPMMtest.c
	${CC} ${CFLAGS} -o $@ $?

MPMMtest_64: MPMMtest.c
	${CC} ${CFLAGS64} -o $@ $?

KQMPMMtest: KQMPMMtest.c
	${CC} ${CFLAGS} -o $@ $?

KQMPMMtest_64: KQMPMMtest.c
	${CC} ${CFLAGS64} -o $@ $?

KQMPMMtestD: KQMPMMtest.c
	${CC} ${CFLAGS} -DDIRECT_MSG_RCV=1 -o $@ $?

KQMPMMtest_64D: KQMPMMtest.c
	${CC} ${CFLAGS64} -DDIRECT_MSG_RCV=1 -o $@ $?

clean:
	rm -rf $(TARGETS) *.dSYM
