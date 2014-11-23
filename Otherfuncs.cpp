#include <time.h>
#include <vector>
#include <string>
#include <sstream>
#include "includes/cryptopp/sha.h"
#include "includes/cryptopp/hex.h"
#include "includes/cryptopp/aes.h"
#include "includes/cryptopp/ccm.h"
#include "includes/cryptopp/gcm.h"
#include "includes/cryptopp/osrng.h"
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <fstream>
std::vector<std::string> &split(const std::string &s, char delim, std::vector<std::string> &elems) {
    std::stringstream ss(s);
    std::string item;
    while (std::getline(ss, item, delim)) {
		if (!item.empty())
		{
			elems.push_back(item);
		}
    }
    return elems;
}

std::vector<std::string> split(const std::string &s, char delim) {
    std::vector<std::string> elems;
    split(s, delim, elems);
    return elems;
}

//Listens for a packet and modifies the packet variable accordingly
bool listenPacket(long int &csock, char* packet)
{
    int length;

    packet[0] = '\0';
    //read the packet from the sender
    if(sizeof(int) != recv(csock, &length, sizeof(int), 0)){
        return false;
    }
    if(length >= 1024)
    {
        printf("[error] packet to be sent is too long\n");
        return false;
    }
    if(length != recv(csock, packet, length, 0))
    {
        printf("[error] fail to read packet\n");
        return false;
    }
    packet[length] = '\0';

    return true;
}

std::string makeHash(const std::string& input)
{
    CryptoPP::SHA512 hash;
    byte digest[ CryptoPP::SHA512::DIGESTSIZE ];

    hash.CalculateDigest( digest, (byte*) input.c_str(), input.length() );

    CryptoPP::HexEncoder encoder;
    std::string output;
    encoder.Attach( new CryptoPP::StringSink( output ) );
    encoder.Put( digest, sizeof(digest) );
    encoder.MessageEnd();

    return output;
}

//Function generates a random alphanumeric string of length len
std::string randomString(const unsigned int len)
{
    static const char alphanum[] =
        "0123456789"
        "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
        "abcdefghijklmnopqrstuvwxyz";

    CryptoPP::AutoSeededRandomPool prng;
    std::string s = "";

    //When adding each letter, generate a new word32, 
    //then compute it modulo alphanum's size - 1
    for(unsigned int i = 0; i < len; ++i)
    {
        s += alphanum[prng.GenerateWord32() % (sizeof(alphanum) - 1)];
    } //end for generate random string

    /*std::string s = "";
    for (int i = 0; i < len; ++i) {
        s += alphanum[rand() % (sizeof(alphanum) - 1)];
    }
    */
    return s;
}