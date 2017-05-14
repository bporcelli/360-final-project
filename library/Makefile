INCD := include
CMND := ../common
BIND := bin
SRCD := src
TSTD := tests

LIB_SRC := $(shell find $(SRCD) -name *.c)
COM_SRC := $(CMND)/redirect.c $(CMND)/logger.c $(CMND)/level.c $(CMND)/util.c

# See http://samanbarghi.com/blog/2014/09/05/how-to-wrap-a-system-call-libc-function-in-linux/ for explanation
# of GCC options
lib: $(LIB_SRC)
	gcc -fPIC -shared -I $(CMND)/include -I $(INCD) -o $(BIND)/libsipwrap.so $(LIB_SRC) $(COM_SRC) -ldl

test: $(TSTD)/test.c
	gcc -o $(BIND)/test $(TSTD)/test.c

packet_test: $(TSTD)/packet-test.c
	gcc -I $(CMND)/include -o $(BIND)/ptest $(TSTD)/packet-test.c $(CMND)/packet.c $(CMND)/logger.c

bridge_test: $(TSTD)/bridge-test.c
	gcc -I $(CMND)/include -I $(INCD) -o $(BIND)/btest $(TSTD)/bridge-test.c $(SRCD)/bridge.c $(CMND)/packet.c $(CMND)/logger.c

tests: test packet_test bridge_test

all: lib tests

clean:
	rm -f $(BIND)/*
	rm -f test.txt