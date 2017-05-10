EXE := runt
COM := ../common

SRC := launcher.c
COM_SRC := $(COM)/logger.c $(COM)/level.c

$(EXE): $(SRC) $(COM_SRC)
	gcc -I $(COM)/include $(SRC) $(COM_SRC) -o $(EXE)

all: $(EXE)

clean:
	rm -f runt