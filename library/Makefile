INCD := include/
CMND := ../common
BIND := bin/
SRCD := src/
TSTD := tests/

LIB_SRC := $(shell find $(SRCD) -name *.c)
TEST_SRC := $(shell find $(TSTD) -name *.c)

clean:
	rm -f $(BIND)*
	rm -f test.txt

# See http://samanbarghi.com/blog/2014/09/05/how-to-wrap-a-system-call-libc-function-in-linux/ for explanation
# of GCC options
lib: $(LIB_SRC)
	gcc -fPIC -shared -I $(CMND)/include -I $(INCD) -o $(BIND)libsipwrap.so $(LIB_SRC) $(CMND)/logger.c -ldl

test: $(TEST_SRC)
	gcc -o $(BIND)test $(TEST_SRC)

all: lib test