CC=g++
CFLAGS=-O3 -s -D_FORTIFY_SOURCE=2 -fstack-protector-all  -z relro -z now -z noexecstack  

all: engine

engine: engine.cpp
	$(CC) $(CFLAGS) -o $@ $<

clean:
	rm engine
