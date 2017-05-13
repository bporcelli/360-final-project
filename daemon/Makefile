INCD := include
CMND := ../common
EXEC := daemon

LIB_SRC := $(shell find . -name *.c)
COM_SRC := $(CMND)/logger.c $(CMND)/level.c

$(EXEC): $(LIB_SRC)
	gcc -I $(CMND)/include -I $(INCD) -o daemon $(LIB_SRC) $(INCD)/thpool.c $(COM_SRC)

	# Must be setuid-root to change real, effective, saved UID/GIDs
	sudo chown root:root $(EXEC)
	sudo chmod +s $(EXEC)

all: $(EXEC)

clean:
	rm -f $(EXEC)