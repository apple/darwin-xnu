CFLAGS	=-g -arch i386
CFLAGS64=-g -arch x86_64

TESTS =		\
	sets	\
	pool	\
	tags	\

TARGETS = $(TESTS) $(TESTS:=64)

all:	$(TESTS)

.c:	
	gcc $(CFLAGS) $< -o $@		# 32-bit fat 
	gcc $(CFLAGS64) $< -o $@64 		# 64-bit fat

clean:
	rm -rf $(TARGETS) 
