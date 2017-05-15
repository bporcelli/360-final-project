COM := ../common
INC := inc
BIN := bin

COM_SRC = $(COM)/util.c $(COM)/logger.c $(COM)/level.c

runt_driver: runt-driver.c
	gcc -I $(COM)/include -I $(INC) runt-driver.c $(INC)/test-util.c $(COM_SRC) -o $(BIN)/runt_driver
	
	# Must be setuid-root to set initial file permissions
	sudo chown root:root $(BIN)/runt_driver
	sudo chmod +s $(BIN)/runt_driver

runt_test: runt-test.c
	gcc -I $(COM)/include -I $(INC) runt-test.c $(INC)/test-util.c $(COM_SRC) -o $(BIN)/runt_test

open_test: open-files.c
	gcc -I $(COM)/include -I $(INC) open-files.c $(INC)/test-util.c $(COM_SRC) -o $(BIN)/open_test

uid_test: show_getuid_and_getgid.c
	gcc -I $(COM)/include -I $(INC) show_getuid_and_getgid.c $(INC)/test-util.c $(COM_SRC) -o $(BIN)/uid_test

unlink_test: unlink-test.c
	gcc -I $(COM)/include -I $(INC) unlink-test.c $(INC)/test-util.c $(COM_SRC) -o $(BIN)/unlink_test

tests: runt_driver runt_test open_test uid_test unlink_test

all: tests

clean:
	rm -f $(BIN)/*
	rm -f *.txt