COM := ../common

runt_driver: runt-driver.c
	gcc -I $(COM)/include runt-driver.c $(COM)/util.c $(COM)/logger.c -o runt_driver
	
	# Must be setuid-root to set initial file permissions
	sudo chown root:root runt_driver
	sudo chmod +s runt_driver

runt_test: runt-test.c
	gcc -I $(COM)/include runt-test.c $(COM)/logger.c $(COM)/util.c -o runt_test

tests: runt_driver runt_test

all: tests

clean:
	rm -f runt_driver
	rm -f runt_test
	rm -f *.txt