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
#include "account.h"
#include "bank.h"
#include "Sharedfuncs.h"
#include <exception>

void* client_thread(void* arg);
void* console_thread(void* arg);

int main(int argc, char* argv[])
{
    if(argc != 2)
    {
        printf("Usage: bank listen-port\n");
        return -1;
    }
    
    unsigned short port = atoi(argv[1]);
    
    //socket setup
    int msock = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
    if(!msock)
    {
        printf("fail to create socket\n");
        return -1;
    }
    
    //listening address
    sockaddr_in addr;
    memset(&addr,0,sizeof(addr));
    addr.sin_family = AF_INET;
    addr.sin_port = htons(port);
    unsigned char* ip_addr = reinterpret_cast<unsigned char*>(&addr.sin_addr);
    ip_addr[0] = 127;
    ip_addr[1] = 0;
    ip_addr[2] = 0;
    ip_addr[3] = 1;
    if(0 != bind(msock, reinterpret_cast<sockaddr*>(&addr), sizeof(addr)))
    {
        printf("failed to bind socket\n");
        return -1;
    }
    if(0 != listen(msock, SOMAXCONN))
    {
        printf("failed to listen on socket\n");
        return -1;
    }

    //Create the bank
    Bank* bank = new Bank();

    //Create the structs to help move data around
    BankSocketThread* bankSocketThread = new BankSocketThread();
    bankSocketThread->bank = bank;
    bank->Salt = "WHATISANAMAZINGSALTFORHASHING";
    
    pthread_t cthread;
    pthread_create(&cthread, NULL, console_thread, (void*)bankSocketThread);

    //loop forever accepting new connections
    while(1)
    {
        sockaddr_in empty;
        socklen_t size = sizeof(empty);
        int c_sock = accept(msock, reinterpret_cast<sockaddr*>(&empty), &size);
        if(c_sock < 0)   //bad client, skip it
            continue;
        bankSocketThread->c_sock = &c_sock;
        pthread_t thread;
        pthread_create(&thread, NULL, client_thread, (void*)bankSocketThread);
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

    long int c_sock = (long int)*(bankSocketThread->c_sock);
    
    printf("[bank] client ID #%ld connected\n", c_sock);
    
    //input loop
    int length;
    char packet[1024];
    bool critialError = false;
    std::vector<std::string> token;
    while(1)
    {
        critialError = false;
        token.clear();
        
        if(!listenPacket(c_sock, packet))
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
                }            }
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

        //Parse the packet
        //std::string strPacket = packet;
        split(std::string(packet),',', token);

        //We should get something, if not ignore this packet
        if(token.size() < 1)
        {
            continue;
        }

        if(token[0] == "logout")
        {
            bankSession->endSession();
            break;
        }

        //Now we're compare what we go to what state we expect to be in
        switch(bankSession->state)
        {
            case 0:
            case 1:
                if(token.size() == 2 && token[0] == "handshake" && token[1].size() == 128)
                {
                    bankSession->atmNonce = token[1];
                    bankSession->bankNonce = makeHash(randomString(128));
                    if(bankSession->bankNonce.size() == 0)
                    {
                        printf("Unexpected error\n");
                        critialError = true;
                        break;
                    }
                    buildPacket(packet, "handshakeResponse," + bankSession->atmNonce + "," + bankSession->bankNonce);
                    if(!encryptPacket((char*)packet,bankSession->key))
                    {
                        printf("Unexpected error\n");
                        critialError = true;
                        break;
                    }
                    if(!sendPacket(c_sock, packet))
                    {
                        printf("Unexpected error\n");
                        critialError = true;
                        break;
                    }
                    bankSession->state = 2;
                }
                break;
            //Expecting a login
            case 2:
                if(!bankSession->validateNonce(std::string(packet)))
                {
                    printf("Unexpected error\n");
                    critialError = true;
                    break;
                }
                if(token.size() == 5 && token[0] == "login" && token[1].size() == 128)
                {
                    //Now we'll try to find the account
                    //bankSession->account = bank->tryLoginHash(token[1]);
                    bankSession->account = bank->getAccountByName(token[2]);
                    if(!bankSession->account || !bankSession->account->tryHash(token[1]))
                    {
                        //Failed login
                        //TODO Blacklist hash
                        bankSession->error = true;
                        //printf("[notice] Failed login!\n");
                    }
                    bankSession->account->inUse = true;
                    bankSession->state = 5;
                    if(!bankSession->sendP(c_sock,packet, "ack"))
                    {
                        printf("Unexpected error!\n");
                        critialError = true;
                        break;
                    }
                }
                break;
            case 5:
                bool returnBalance = false;
                bool same_name = false;
                bankSession->state = 4;
                if(bankSession->error)
                {
                    returnBalance = false;
                } 
                else if(token.size() == 3 && token[0] == "balance")
                {
                    returnBalance = true;
                }
                else if(token.size() == 4 && token[0] == "withdraw" && isDouble(token[1]))
                {
                    double amount = atof(token[1].c_str());
                    if(!bankSession->account->Withdraw(amount))
                    {
                        printf("[error] Failed withdraw\n");
                        returnBalance = false;
                        bankSession->error = true;
                    }
                    returnBalance = true;
                }
                else if(token.size() == 5 && token[0] == "transfer" && !isDouble(token[1])
                    && isDouble(token[2]))
                {
                    Account* accountTo = bank->getAccountByName(token[1]);
                    double amount = atof(token[2].c_str());
                    same_name = false;
                    if(accountTo == bankSession->account)
                    {
                    	printf("[error] Same Account Transfer\n");
                        returnBalance = false;
                        same_name = true;
                    }
                    if(!bankSession->account->Transfer(amount, accountTo))
                    {
                        printf("[error] Failed transfer\n");
                        returnBalance = false;
                        bankSession->error = true;
                    }
                    returnBalance = true;
                }

                if(bankSession->error)
                {
                    bankSession->sendP(c_sock, packet, "denied");
                }
                else if(same_name)
                {
                    bankSession->sendP(c_sock, packet, "same");
                }
                else if(returnBalance)
                {
                    char money[256];
                    sprintf(money,"%.2Lf",bankSession->account->getBalance());
                    bankSession->sendP(c_sock, packet, std::string(money));
                }

                //Reset back to initial state
                bankSession->endSession();
                break;
        }
        
        if(critialError)
        {
            bankSession->endSession();
            break;
        }
    }

    bankSession->endSession();

    printf("[bank] client ID #%ld disconnected\n", c_sock);

    close(c_sock);
    delete bankSession;
    return NULL;
}

void* console_thread(void* arg)
{
    BankSocketThread* bankSocketThread = (BankSocketThread*) arg;
    Bank* bank = bankSocketThread->bank;

    //Let's generate our keys
    for(unsigned int i = 1; i <= 50; ++i)
    {
        byte* key = new byte[CryptoPP::AES::DEFAULT_KEYLENGTH];
        generateRandomKey(to_string((int)i),key, CryptoPP::AES::DEFAULT_KEYLENGTH);
        bank->keys.push_back(key);
        bank->keysInUse.push_back(false);
    }

    //Create Accounts
    Account* new_account = new Account();

    //Alice
    new_account->createAccount(std::string("alice"), 1, std::string("123456"), bank->Salt);
    new_account->Deposit(100);
    bank->addAccount(new_account);

    //Bob
    new_account = new Account();
    new_account->createAccount(std::string("bob"), 2, std::string("234567"), bank->Salt);
    new_account->Deposit(50);
    bank->addAccount(new_account);

    //Eve
    new_account = new Account();
    new_account->createAccount(std::string("eve"), 3, std::string("345678"), bank->Salt);
    new_account->Deposit(0);
    bank->addAccount(new_account);

    char buffer[80];
    while(1)
    {
        printf("bank> ");
        fgets(buffer, 79, stdin);
        buffer[strlen(buffer)-1] = '\0';  //trim off trailing newline

        std::vector<std::string> token;
        split(buffer,' ',token);

        if(token.size() <= 0)
        {
            printf("Invalid input\n");
            continue;
        }
        if(token[0] == "balance")
        {
            if(token.size() != 2)
            {
                printf("Invalid input\n");
                continue;
            }

            Account* current = bank->getAccountByName(token[1]);
            if(!current)
            {
                printf("Invalid account\n");
                continue;
            }
            printf("Balance: %.2Lf\n", current->getBalance());
            continue;
        }

        if(token[0] == "deposit")
        {
            if(token.size() != 3)
            {
                printf("Invalid input\n");
                continue;
            }

            long double amount = atof(token[2].c_str());

            if(amount <= 0)
            {
                printf("Invalid amount\n");
                continue;
            }

            Account* current = bank->getAccountByName(token[1]);
            if(!current)
            {
                printf("Invalid account\n");
                continue;
            }

            if(current->Deposit(amount))
            {
                long double balance = current->getBalance();
                printf("Money deposited!\nNew balance: %.2Lf\n", balance);
            } else {
                printf("Error depositing money!\n");
            }
            continue;
        }
        
    }
}

void Bank::addAccount(Account* account)
{
    this->accounts.push_back(account);
}

Account* Bank::getAccountByName(const std::string& username)
{
    for(unsigned int i = 0; i < this->accounts.size(); ++i)
    {
        if(this->accounts[i]->getAccountHolder() == username)
        {
            return this->accounts[i];
        }
    }
    return 0;
}

Account* Bank::tryLoginHash(const std::string& hash)
{
    for(unsigned int i = 0; i < this->accounts.size(); ++i)
    {
        if(this->accounts[i]->tryHash(hash))
        {
            return this->accounts[i];
        }
    }
    return 0;
}

Bank::~Bank()
{
    for(unsigned int i = 0; i < this->accounts.size(); ++i)
    {
        delete this->accounts[i];
    }

    for(unsigned int i = 0; i < this->keys.size(); ++i)
    {
        delete this->keys[i];
    }
}


bool BankSession::sendP(long int &c_sock, void* packet, std::string command)
{
    if(!this->key)
    {
        return false;
    }

    bankNonce = makeHash(randomString(128));
    command = command + "," + atmNonce + "," + bankNonce;
    if(command.size() >= 460)
    {
        return false;
    }
    buildPacket((char*)packet, command);
    if(!encryptPacket((char*)packet,this->key))
    {
        return false;
    }

    return sendPacket(c_sock, packet);
}

bool BankSession::validateNonce(std::string packet)
{
    try
    {
        if(packet.substr(packet.size()-128, 128) != bankNonce)
        {
            return false;
        }
        atmNonce = packet.substr(packet.size()-257, 128);

        return true;
    }
    catch(std::exception e)
    {
        return false;
    }
}

void BankSession::endSession()
{
    if(this->account)
    {
        this->account->inUse = false;
    }
    this->account = 0;
    if(this->key)
    {
        for(unsigned int i = 0; i < this->bank->keys.size(); ++i)
        {
            if(this->key == this->bank->keys[i])
            {
                this->bank->keysInUse[i] = false;
            }
        }
    }
    this->key = 0;
    this->state = 0;
}
