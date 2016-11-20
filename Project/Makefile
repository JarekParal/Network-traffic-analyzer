CFLAGS=-std=c++11 
BIN=analyzer
CC=gcc
RM=rm -f

ALL: main.o convert.o structures.o
	$(CC) $(CFLAGS) -o $(BIN) main.o convert.o structures.o
clean:
	$(RM) *.o *.output $(BIN)