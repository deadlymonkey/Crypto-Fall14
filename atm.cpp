/**
	@file atm.cpp
	@brief Top level ATM implementation file
 */
#include <unistd.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>	
#include <iostream>
#include "Otherfuncs.cpp"

int main(int argc, char* argv[])
{
	if(argc != 2)
	{
		printf("Usage: atm proxy-port\n");
		return -1;
	}
	
	//socket setup
	unsigned short proxport = atoi(argv[1]);
	int sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if(!sock)
	{
		printf("fail to create socket\n");
		return -1;
	}
	sockaddr_in addr;
	addr.sin_family = AF_INET;
	addr.sin_port = htons(proxport);
	unsigned char* ipaddr = reinterpret_cast<unsigned char*>(&addr.sin_addr);
	ipaddr[0] = 127;
	ipaddr[1] = 0;
	ipaddr[2] = 0;
	ipaddr[3] = 1;
	if(0 != connect(sock, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)))
	{
		printf("fail to connect to proxy\n");
		return -1;
	}
	
	//input loop
	char buf[80] = "";
	std::string buf_string = "";
	buf_string.resize(80);
	std::string packet = "";
	packet.resize(1024);
	std::vector<std::string> user_args;
	while(1)
	{
		std::cout << "ready for next command." << std::endl;
		buf[0] = '\0';
		buf_string = "";
		packet = "";
		user_args.clear();
		printf("atm> ");
		fgets(buf, 79, stdin);
		buf[strlen(buf)-1] = '\0';	//trim off trailing newline
		buf_string = std::string(buf);
		user_args = split(buf_string, ' ', user_args);
		//TODO: your input parsing code has to put data here
		//char packet[1024];
		int length = 1;
		
		//input parsing
		
		if(buf_string == "logout")
		{
			break;
		}
		else if (buf_string.compare(0, 5, "login") == 0)
		{
			if (user_args.size() != 2)
			{
				std::cerr << "Error: login arguments." << std::endl;
				continue;
			}
			else
			{
				packet += user_args[0] + " " + user_args[1];
			}
		}
		else if (buf_string == "balance")
		{
			packet += buf_string;
		}
		else if (buf_string.compare(0, 8, "withdraw") == 0)
		{
			if (user_args.size() != 2)
			{
				std::cerr << "Error: withdraw arguments." << std::endl;
				continue;
			}
			else
			{
				packet += user_args[0] + " " + user_args[1];
			}
		}
		else if (buf_string.compare(0, 8, "transfer") == 0)
		{
			if (user_args.size() != 3)
			{
				std::cerr << "Error: transfer arguments." << std::endl;
				continue;
			}
			else
			{
				packet += user_args[0] + " " + user_args[1] + " " +
						  user_args[2];
			}
		}
		else
		{
			std::cerr << "Error: Incorrect command." << std::endl;
			continue;
		}
		
		length = packet.length();
		char packet_copy[packet.length()+1];
		strcpy(packet_copy, packet.c_str());
		std::cout << packet << " " << length << std::endl;
		
		//send the packet through the proxy to the bank
		if(sizeof(int) != send(sock, &length, sizeof(int), 0))
		{
			std::cout << "fail to send packet length" << std::endl;
			break;
		}
		if(length != send(sock, &packet_copy, length, 0))
		{
			std::cout << "fail to send packet" << std::endl;
			break;
		}
		//TODO: do something with response packet
		if(sizeof(int) != recv(sock, &length, sizeof(int), 0))
		{
			std::cout << "fail to read packet length" << std::endl;
			break;
		}
		if(length >= 1024)
		{
			std::cout << "packet too long" << std::endl;
			break;
		}
		if(length != recv(sock, &packet_copy, length, 0))
		{
			std::cout << "fail to read packet" << std::endl;
			break;
		}
		std::cout << "received packet: " << packet_copy << std::endl;
	}
	
	//cleanup
	close(sock);
	return 0;
}
