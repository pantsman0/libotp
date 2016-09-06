TESTCFLAGS=-g -O0 -fpic -Wall -Werror -fno-builtin
CFLAGS=-fpic -fno-builtin
TEST_LINKER=-lcunit
TESTSOURCES=test_driver.c libotp.c hmac_sha1.c sha1/sha1.c
TESTBINARY=libotptest
SO_BINARY_LEVEL=0


default: shared

all: shared static

shared: libotp.so

static: libotp.o

libotp.o: hmac_sha1.o sha1/sha1.o 

libotp.so: hmac_sha1.o sha1/sha1.o
	$(CC) $(CFLAGS) -shared -o libotp.so.$(SO_BINARY_LEVEL) libotp.c

clean:
	rm -rf *.so.* *.o sha1/*.o $(TESTBINARY)

test:
	$(CC) $(TESTCFLAGS) -o $(TESTBINARY) $(TESTSOURCES) $(TEST_LINKER)
	./$(TESTBINARY)
	make clean
