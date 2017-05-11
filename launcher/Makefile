EXE := runt
COM := ../common
TSTD := tests

SRC := launcher.c
COM_SRC := $(COM)/logger.c $(COM)/level.c $(COM)/util.c

$(EXE): $(SRC) $(COM_SRC)
	gcc -I $(COM)/include $(SRC) $(COM_SRC) -o $(EXE)

test_driver: $(TSTD)/driver.c
	gcc -I $(COM)/include $(TSTD)/driver.c -o $(TSTD)/driver
	sudo chown root:root $(TSTD)/driver
	sudo chmod +s $(TSTD)/driver

test: $(TSTD)/test.c
	gcc -I $(COM)/include $(TSTD)/test.c $(COM)/logger.c $(COM)/util.c -o $(TSTD)/test

tests: test_driver test

all: $(EXE) tests

clean:
	rm -f runt
	rm -f tests/test
	rm -f tests/driver
	rm -f *.txt