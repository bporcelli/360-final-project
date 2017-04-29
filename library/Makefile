INCD := include/
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
	gcc -fPIC -shared -I $(INCD) -o $(BIND)libwrap.so $(LIB_SRC) -ldl

test: $(TEST_SRC)
	gcc -o $(BIND)test $(TEST_SRC)

all: lib test