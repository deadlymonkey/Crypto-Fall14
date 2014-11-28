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
#include <fstream>
#include <streambuf>
#include <iostream>
#include <string>
#include <vector>
#include <sstream>
#include <iterator>
#include <termios.h>
#include "Sharedfuncs.h"
#include "atm.h"

using std::cout;
using std::cin;
using std::endl;

//Gets next character, used by getPassword.
int getNextChar() {
    int next_char;
    struct termios t_old, t_new;

    tcgetattr(STDIN_FILENO, &t_old);
    t_new = t_old;
    t_new.c_lflag &= ~(ICANON | ECHO);
    tcsetattr(STDIN_FILENO, TCSANOW, &t_new);
    next_char = getchar();
    tcsetattr(STDIN_FILENO, TCSANOW, &t_old);
    
    return next_char;
}

//Gets PIN from user while only displaying asterisks to hide from nearby people.
std::string getPassword(const char *prompt, bool display_stars=true)
{
    std::string password;
    unsigned char next_char = 0;
    const char RETURN = 10;
    const char BACKSPACE = 127;

    cout << prompt;
    while((next_char = getNextChar()) != RETURN)
    {
        if(next_char == BACKSPACE)
        {
            if(password.length() != 0)
            {
                if(display_stars)
                {
                    cout <<"\b \b";
				}
                password.resize(password.length()-1);
            }
        }
        else{
            password += next_char;
            if(display_stars)
            {
                cout <<'*';
			}
        }
    }
    cout << endl;
    return password;
}

//Attempts a handshake with bank, checking for proper nonces along the way.
bool AtmSession::handshake(long int &csock)
{
    char packet[1024];
    std::vector<std::string> tokens;
    state = 0;
    atm_nonce = makeHash(randomString(128));

    if(atm_nonce == "")
    {
        atm_nonce = "";
        return false;
    }
    buildPacket(packet,"handshake," + atm_nonce);
    if(!this->key)
    {
        return false;
    }
    if(!encryptPacket(packet, this->key))
    {
        atm_nonce = "";
        return false;
    }
    if(!sendPacket(csock, packet))
    {
        atm_nonce = "";
        return false;
    }
    state = 1;
    if(!listenPacket(csock, packet))
    {
        atm_nonce = "";
        return false;
    }
    
    decryptPacket((char*)packet, this->key);
    split(std::string(packet), ',', tokens);
    if(tokens.size() < 3 || tokens[0] != "handshakeResponse" ||
	   tokens[1].size() != 128 || tokens[1] != atm_nonce || 
	   tokens[2].size() != 128)
    {
        atm_nonce = "";
        return false;
    }

    bank_nonce = tokens[2];
    state = 2;
    return true;
}

//Attaches nonces to a command, creates a packet, and sends it.
bool AtmSession::sendThePacket(long int &csock, void* packet, std::string command)
{
    atm_nonce = makeHash(randomString(128));
    command = command + "," + atm_nonce + "," + bank_nonce;
    if(command.size() >= 460)
    {
        return false;
    }
    buildPacket((char*)packet, command);
	if(!encryptPacket((char*)packet, this->key))
    {
        return false;
    }
    return sendPacket(csock, packet);
}

//Listens for packet from bank, checks against atm_nonce, and sets bank_nonce.
bool AtmSession::listenForPacket(long int &csock, char* packet)
{
    if(!listenPacket(csock,packet) ||
	   !decryptPacket((char*)packet, this->key))
    {
        return false;
    }
	try
    {
		std::string response(packet);
		if(response.substr(0, 4) == "kill")
		{
			return false;
		}
		if(response.substr(response.size()-257, 128) != atm_nonce)
		{
			return false;
		}
		bank_nonce = response.substr(response.size()-128, 128);
		return true;
	}
	catch (std::exception e)
	{
		cout << "Exception: Failure while listening for packet." << endl;
		return false;
	}
}


int main(int argc, char* argv[])
{
    if(argc != 3)
    {
        cout << "Usage: atm proxy-port atm-number(1-50)" << endl;
        return -1;
    }

    unsigned short proxy_port = atoi(argv[1]);
    long int sock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if(!sock)
    {
        cout << "Failure to create socket" << endl;
        return -1;
    }
    sockaddr_in addr;
    memset(&addr, 0, sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(proxy_port);
    unsigned char* ipaddr = reinterpret_cast<unsigned char*>(&addr.sin_addr);
    ipaddr[0] = 127;
    ipaddr[1] = 0;
    ipaddr[2] = 0;
    ipaddr[3] = 1;
    if(connect(sock, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)) != 0)
    {
        cout << "Failure to connect to proxy" << endl;
        return -1;
    }
    
    const std::string Salt = "WHATISANAMAZINGSALTFORHASHING";
    AtmSession atmSession = AtmSession();
    
	//Construct key filename.
	std::string filename = "keys/" + std::string(argv[2]) + ".key";	
	
	//Attempt to read in key.
	std::string key;
	std::ifstream key_file(filename.c_str());
	if(key_file.is_open())
	{
		key_file >> key;
	}
	key_file.close();

	byte atm_key[CryptoPP::AES::DEFAULT_KEYLENGTH];
	//Generate ATM's private AES key. 	
	CryptoPP::StringSource(key, true, new CryptoPP::HexDecoder(
			new CryptoPP::ArraySink(atm_key,CryptoPP::AES::DEFAULT_KEYLENGTH)));
    atmSession.key = atm_key;

    while(1)
    {
        char buf[80];
        char packet[1024];
        int length;
        int sendPacket = 0;
        std::vector<std::string> user_args;
        std::vector<std::string> tokens;
        buf[0] = '\0';
        packet[0] = '\0';

        cout << "atm> ";
        fgets(buf, 79, stdin);
        buf[strlen(buf)-1] = '\0';
        split((std::string) buf, ' ', user_args);
        if(std::string(buf).size() >= 204)
        {
            cout << "Invalid input. Try again." << endl;
            continue;
        }

        //Parse user input and attempt to execute their request.
        if(user_args.size() >= 1 && user_args[0] != "")
        {
            std::string command = user_args[0];
            if(command == "logout" || command == "exit")
            {   
                if(atmSession.state > 0)
                {
                    atmSession.sendThePacket(sock, packet, "logout");
                }
                break;
            }
            //Attempt login request. Limit name to 30 characters.
            else if(command == "login" && atmSession.state == 0)
            {   
                if(user_args.size() == 2)
                {
                    std::string username = user_args[1].substr(0, 30);
                    std::ifstream cardFile(("cards/" + username + ".card").c_str());
                    if(cardFile)
                    {
						//Attempt handshake.
                        atmSession.handshake(sock);
                        if(atmSession.state != 2)
                        {
                            cout << "Error occurred during handshake." << endl;
                            break;
                        }
                        sendPacket = 1;

                        //Hash the contents of the card file.
                        std::string cardHash((std::istreambuf_iterator<char>(cardFile)),
											  std::istreambuf_iterator<char>());
                        cardHash = cardHash.substr(0,128);
                        cout << "User: " << user_args[1] << '\n';

                        std::string pin = getPassword("PIN: ", true);

                        //Create final hash to send to bank.
                        std::string accountHash = makeHash(cardHash + pin + Salt);
                      
                        //Attempt to send packet containing information to bank.
                        if(!atmSession.sendThePacket(sock, packet, std::string("login," 
						   + accountHash + "," + username)))
                        {
                            cout << "Error occurred while sending packet." << endl;
                            break;
                        }
                        atmSession.state = 3;

						//Listen for "ack" packet from bank.
                        if(!atmSession.listenForPacket(sock, packet) ||
						   std::string(packet).substr(0, 3) != "ack")
                        {
                            cout << "Error occurred during login: " << endl;
                            if (std::string(packet).substr(0, 3) == "err")
                            {
								cout << "Please make sure your PIN is correct " <<
										"and try again." << endl;
								break;
							}
                        }
                        atmSession.state = 4;
                    }
                    //Problem locating card.
                    else
                    {
                        cout << "ATM Card not found." << endl;
                    }
                }
				//User passes improper arguments to login function.
                else
                {
                    cout << "Usage: login [username]" << endl;
                }
            }
            //Attempt balance request.
            else if(command == "balance" && atmSession.state == 4)
            {
                atmSession.sendThePacket(sock, packet, "balance");
                atmSession.listenForPacket(sock, packet);
                split(std::string(packet), ',', tokens);
                if(tokens[0] == "denied")
                {
                    cout << "Transaction denied." << endl;
                }
                else
                {
                    cout << "Transaction complete!" << endl << "Current balance: "
						 << tokens[0].c_str() << endl;
                }
                atmSession.state = 5;
            }
            //Attempt withdraw request.
            else if(command == "withdraw" && atmSession.state == 4)
            {
                if(user_args.size() == 2 && isDouble(user_args[1]))
                {
                    atmSession.sendThePacket(sock, packet, "withdraw," + user_args[1]);
                    atmSession.listenForPacket(sock, packet);
                    split(std::string(packet), ',', tokens);
                    if(tokens[0] == "denied")
                    {
                        cout << "Transaction denied." << endl;
                    }
                    else
                    {
                        cout << "Transaction complete!" << endl << 
								"Current balance: " << tokens[0].c_str() << 
								endl;
                    }
                    atmSession.state = 5;
                }
				//User passes improper arguments to withdraw function.
                else
                {
                    cout << "Usage: withdraw [amount]\n";
                }
            }
            //Attempt transfer request.
			else if(command == "transfer" && atmSession.state == 4)
			{
				if(user_args.size() == 3)
				{
					//Ensure that user_args[1] is a name and user_args[2] > 0.
					long double is_double = string_to_Double(user_args[1]);
					long double transfer_amount = string_to_Double(user_args[2]);
					if(is_double == 0 && transfer_amount > 0)
					{
						atmSession.sendThePacket(sock, packet, "transfer," + 
												 user_args[1]+ "," + user_args[2]);
						atmSession.listenForPacket(sock, packet);
						split(std::string(packet), ',', tokens);
						if(tokens[0] == "denied")
						{
							cout << "Transaction denied." << endl;
						}
						else if(tokens[0] == "same")
						{
							cout << "You can't transfer to yourself." << endl;
						}
						else
						{
							cout << "Transaction complete!" << endl <<
									"Current balance: " << tokens[0].c_str() <<
									endl;
						}
						atmSession.state = 5;
					}
					else if (transfer_amount <= 0)
					{
						cout << "Invalid transfer amount." << endl;
						break; 
					}
				}
				//User passes improper arguments to transfer function.
				else
				{
					cout << "Usage: transfer [other_account] [amount]" << endl;
				}
			}
			//User inputs improper command.
            else
            {
                cout << "Command \"" << command << "\" not recognized." << endl;
            }
            if(atmSession.state == 5)
            {
                break;
            }
        }
        //User inputs nothing.
        else
        {
            cout << "Usage: [command] [+argument]" << endl;
        } 
    }
    close(sock);
    return 0;
}
