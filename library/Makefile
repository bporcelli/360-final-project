clean: 
	rm -rf bin/*
	rm -f test.txt

# See http://samanbarghi.com/blog/2014/09/05/how-to-wrap-a-system-call-libc-function-in-linux/ for explanation
# of GCC options
lib: testlib.c
	gcc -fPIC -shared -o bin/libtest.so testlib.c -ldl

test: test.c
	gcc -o bin/test test.c

all: lib test