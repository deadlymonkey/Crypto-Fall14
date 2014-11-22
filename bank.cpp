/**
	@file bank.cpp
	@brief Top level bank implementation file
 */
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <stdlib.h>
#include <stdio.h>
#include <pthread.h>
#include <string.h>

void* client_thread(void* arg);
void* console_thread(void* arg);

int main(int argc, char* argv[])
{
	if(argc != 2)
	{
		printf("Usage: bank listen-port\n");
		return -1;
	}
	
	unsigned short ourport = atoi(argv[1]);
	
	//socket setup
	int lsock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if(!lsock)
	{
		printf("fail to create socket\n");
		return -1;
	}
	
	//listening address
	sockaddr_in addr_l;
	memset(&addr_l,0,sizeof(addr_l));
	addr_l.sin_family = AF_INET;
	addr_l.sin_port = htons(ourport);
	unsigned char* ipaddr = reinterpret_cast<unsigned char*>(&addr_l.sin_addr);
	ipaddr[0] = 127;
	ipaddr[1] = 0;
	ipaddr[2] = 0;
	ipaddr[3] = 1;
	if(0 != bind(lsock, reinterpret_cast<sockaddr*>(&addr_l), sizeof(addr_l)))
	{
		printf("failed to bind socket\n");
		return -1;
	}
	if(0 != listen(lsock, SOMAXCONN))
	{
		printf("failed to listen on socket\n");
		return -1;
	}
	
	//Create the bank
	Bank * bank = new Bank();
	
	//Create the structs to help move data
        BankSocketThread* bankSocketThread = new BankSocketThread();
        bankSocketThread->bank = bank;
        bank->appSalt = "THISISTHESALTFORHASHINGDATA";
	
	pthread_t cthread;
	pthread_create(&cthread, NULL, console_thread, NULL);
	
	//loop forever accepting new connections
	while(1)
	{
		sockaddr_in unused;
		socklen_t size = sizeof(unused);
		int csock = accept(lsock, reinterpret_cast<sockaddr*>(&unused), &size);
		if(csock < 0)	//bad client, skip it
			continue;
		bankSocketThread->csock = &csock;
		pthread_t thread;
		pthread_create(&thread, NULL, client_thread, (void*)csock);
	}
	delete bank;
        delete bankSocketThread;
}

void* client_thread(void* arg)
{
	BankSocketThread* bankSocketThread = (BankSocketThread*) arg;
    	Bank* bank = bankSocketThread->bank;
    	BankSession* bankSession = new BankSession();
	bankSession->state = 0;
    	bankSession->bank = bank;
    	bankSession->key = 0;

        long int csock = (long int)*(bankSocketThread->csock);
	
	printf("[bank] client ID #%d connected\n", csock);
	
	//input loop
	int length;
    	char packet[1024];
    	bool fatalError = false;
    	std::vector<std::string> tokens;
    	while(1)
	{
	  fatalError = false;
	  tokens.clear();
        
          if(!listenPacket(csock, packet))
          {
              printf("[bank] fail to read packet\n");
              break;
          }
          if(!bankSession->key)
          {
              if(bankSession->state != 0)
              {
                  printf("[error] Unexpected state\n");
                  break;
              }
              for(unsigned int i = 0; i < bank->keys.size(); ++i)
              {
                  if(bank->keysInUse[i])
                  {
                     continue;
                  }
                  if(decryptPacket((char*)packet,bank->keys[i])
                      && std::string(packet).substr(0,9) == "handshake")
                  {
                      bankSession->key = bank->keys[i];
                      bank->keysInUse[i] = true;
                      break;
                  }
              }
              if(!bankSession->key)
              {
                  printf("[error] Key not found.\n");
                  break;
              }
          } else {
              if(!decryptPacket((char*)packet, bankSession->key))
              {
                  printf("[error] Invalid key\n");
                  break;
              }
          }   
		
		//TODO: process packet data
		split(std::string(packet),',', tokens);
		
		if(token.size() < 1){
			continue; // If there is nothing in the packet skip it
		}
		
		if(token[0] == "Logout"){
			bankSession->endSession(); // Kill the Bank
			break; // Break the loop
		}
		//TODO: put new data in packet
		
		//send the new packet back to the client
		if(sizeof(int) != send(csock, &length, sizeof(int), 0))
		{
			printf("[bank] fail to send packet length\n");
			break;
		}
		if(length != send(csock, (void*)packet, length, 0))
		{
			printf("[bank] fail to send packet\n");
			break;
		}

	}

	printf("[bank] client ID #%d disconnected\n", csock);

	close(csock);
	return NULL;
}

void* console_thread(void* arg)
{
	char buf[80];
	while(1)
	{
		printf("bank> ");
		fgets(buf, 79, stdin);
		buf[strlen(buf)-1] = '\0';	//trim off trailing newline
		
		//TODO: your input parsing code has to go here
	}
}
