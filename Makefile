CC=g++ -m32
CFLAGS=-I. -lcryptopp -lpthread

all:
	$(CC) atm.cpp Otherfuncs.cpp -m32 -o atm $(CFLAGS)
	$(CC) bank.cpp account.cpp Otherfuncs.cpp -m32 -o bank $(CFLAGS)
	$(CC) proxy.cpp -m32 -o proxy $(CFLAGS)
