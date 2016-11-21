CFLAGS=-std=c++11 
BIN=analyzer
CC=g++
RM=rm -f

ALL:
	$(CC) $(CFLAGS) -o $(BIN) main.cpp convert.cpp packet.cpp filter.cpp paramParser.cpp
clean:
	$(RM) *.o *.output $(BIN)