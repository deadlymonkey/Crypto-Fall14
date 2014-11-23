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


using CryptoPP::GCM;
using CryptoPP::AES;
using CryptoPP::CCM;

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

bool isDouble(std::string questionable_string)
{
    long double value = strtold(questionable_string.c_str(), NULL);
    if(value == 0)
    {
        return false;
    } //end if no valid conversion
    return true;
}

std::string to_string(int number)
{
   std::stringstream ss;
   ss << number;
   return ss.str();
}

void padCommand(std::string &command){
    //return;
    //pad end of packet with '~' then 'a's
    //printf("Before pad size: %d\n", (int)command.size());
    if (command.size() < 460){ //1022 because buildPacket() has two '\0's
        command += "~";
    }
    while(command.size() < 460){
        command += "a";
    }
}

void buildPacket(char* packet, std::string command)
{
    packet[0] = '\0';
    padCommand(command);
    //printf("Post padding command size: %d\n", (int)command.size());
    //Check if command overflows
    if(command.size() <= 1022)
    {
        strcpy(packet, (command + '\0').c_str());
        packet[command.size()] = '\0';
    } //end if command does not overflow

}

void sleepTime(unsigned int sleepMS){
    #ifdef LINUX
        usleep(sleepMS%1000000); //usleep takes microseconds
    #endif
    #ifdef WINDOWS
        Sleep(sleepMS%1000); //Sleep takes milliseconds
    #endif
}

bool sendPacket(long int &csock, void* packet)
{
    CryptoPP::AutoSeededRandomPool prng;
    sleepTime(prng.GenerateWord32()); //wait for random amount of time

    int length = 0;

    length = strlen((char*)packet);
    //printf("Packet size: %d\n", length);
    if(sizeof(int) != send(csock, &length, sizeof(int), 0))
    {
        printf("[error] fail to send packet length\n");
        return false;
    }
    if(length != send(csock, packet, length, 0))
    {
        printf("[error] fail to send packet\n");
        return false;
    }

    return true;
}
void unpadPacket(std::string &plaintext)
{
    bool markerFound = false;
    int position = -1;
    for(unsigned int i = 0; i < plaintext.size(); ++i)
    {
        if(plaintext[i] == '~')
        {
            if(markerFound)
            {
                markerFound = false;
                position = -1;
            } else {
                markerFound = true;
                position = i;
            }
            continue;
        }
        if(plaintext[i] != 'a' && markerFound)
        {
            markerFound = false;
            position = -1;
        }
    }
    if(position > 0)
    {
        plaintext = plaintext.substr(0,position);
    }
    return;
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

bool encryptPacket(char* packet, byte* aes_key)
{
    try
    {
        std::string plaintext(packet);

        //Decode the key from the file
        GCM< AES >::Encryption p;
        //iv will help us with keying out cipher
        //it is also randomly generated
        byte iv[ AES::BLOCKSIZE ];
        CryptoPP::AutoSeededRandomPool prng;
        prng.GenerateBlock( iv, sizeof(iv) );

        //Merge the iv and key
        p.SetKeyWithIV( aes_key, CryptoPP::AES::DEFAULT_KEYLENGTH, iv, sizeof(iv) );

        //Encode the IV
        std::string encoded_iv;
        CryptoPP::StringSource(iv, sizeof(iv), true,
            new CryptoPP::HexEncoder(
                new CryptoPP::StringSink(encoded_iv)
            ) // HexEncoder
        );

        //Create the ciphertext from the plaintext
        std::string ciphertext;
        CryptoPP::StringSource(plaintext, true,
            new CryptoPP::AuthenticatedEncryptionFilter(p,
                new CryptoPP::StringSink(ciphertext)
            )
        );

        //Encode the cipher to be sent
        std::string encodedCipher;
        CryptoPP::StringSource(ciphertext, true,
            new CryptoPP::HexEncoder(
                new CryptoPP::StringSink(encodedCipher)
            ) // HexEncoder
        );

        //replace the packet with the econded ciphertext
        strcpy(packet, (encoded_iv+encodedCipher).c_str());
        packet[(encoded_iv+encodedCipher).size()] = '\0';
        //printf("Encrypted packet size: %d\n", (int)strlen(packet));
    }
    catch(std::exception e)
    {
        return false;
    }
    
    return true;
}

bool decryptPacket(char* packet, byte* aes_key)
{
    try
    {
        //Setup the iv to be retrieved
        byte iv[ AES::BLOCKSIZE];
        std::string iv_string = std::string(packet).substr(0,32);

        //Decode the iv
        CryptoPP::StringSource(iv_string, true,
            new CryptoPP::HexDecoder(
                new CryptoPP::ArraySink(iv,CryptoPP::AES::DEFAULT_KEYLENGTH)
            )
        );

        //Decode the ciphertext
        std::string ciphertext;
        CryptoPP::StringSource(std::string(packet).substr(32), true,
            new CryptoPP::HexDecoder(
                new CryptoPP::StringSink(ciphertext)
            ) // HexEncoder
        );

        GCM< AES >::Decryption d;
        d.SetKeyWithIV( aes_key, CryptoPP::AES::DEFAULT_KEYLENGTH, iv, sizeof(iv));
        
        //Decrypt the ciphertext into plaintext
        std::string plaintext;
        CryptoPP::StringSource s(ciphertext, true, 
            new CryptoPP::AuthenticatedDecryptionFilter(d,
                new CryptoPP::StringSink(plaintext)
            ) // StreamTransformationFilter
        );

        //Replace the packet with the plaintext
        unpadPacket(plaintext);
        //printf("Plaintext: %s\n", plaintext.c_str());
        strcpy(packet, plaintext.c_str());
        packet[plaintext.size()] = '\0';
    }
    catch(std::exception e)
    {
        return false;
    }

    return true;
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

void generateRandomKey(std::string name, byte* key, long unsigned int length)
{
    CryptoPP::AutoSeededRandomPool prng;

    //byte key[CryptoPP::AES::DEFAULT_KEYLENGTH];
    prng.GenerateBlock(key, length);

    std::string encoded;

    CryptoPP::StringSource(key, length, true,
        new CryptoPP::HexEncoder(
            new CryptoPP::StringSink(encoded)
        ) // HexEncoder
    ); // StringSource

        std::ofstream outfile;

    std::string keyFile = "keys/" + name + ".key";

    std::ofstream file_out(keyFile.c_str());
    if(file_out.is_open())
    {
        file_out << encoded;
    } //end if valid outfstream
    file_out.close();
}