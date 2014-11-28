#ifndef __bank_h__
#define __bank_h__

#include <string.h>

struct AtmSession
{
	AtmSession() : state(0) {}
	
	unsigned int state;
	std::string bank_nonce;
	std::string atm_nonce;
	byte* key;

	bool handshake(long int &csock);
	bool sendThePacket(long int &csock, void* packet, std::string command);
	bool listenForPacket(long int &csock, char* packet);
};

#endif
