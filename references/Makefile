CC=g++ -m32
CFLAGS=-I. -lcryptopp -lpthread

all:
	$(CC) atm.cpp Sharedfuncs.cpp -m32 -o atm $(CFLAGS)
	$(CC) bank.cpp account.cpp Sharedfuncs.cpp -m32 -o bank $(CFLAGS)
	$(CC) proxy.cpp -m32 -o proxy $(CFLAGS)
