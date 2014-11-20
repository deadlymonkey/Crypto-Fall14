#ifndef __account_h__
#define __account_h__
#include <string>
#include "includes/cryptopp/sha.h"

class Account
{
public:
	//Construct
	Account();

	//Transfer functions
	bool tryTransfer(long double funds, const Account* toAccount) const;
	bool Transfer(long double funds, Account* toAccount);

	//Withdraw functions
	bool tryWithdraw(long double funds) const;
	bool Withdraw(long double funds);

	//Deposit functions
	bool tryDeposit(long double funds) const;
	bool Deposit(long double funds);

	//Other functions
	const long double getBalance(){ return this->balance; }
	const std::string getAccountHolder(){ return this->accountName; }
	bool setPIN(const std::string& pin, const std::string& bankSalt);
	bool createAccount(const std::string& accountName, const int& accountNum, const std::string& pin, const std::string& bankSalt);
	bool attemptLogin(const std::string& pin, const std::string& bankSalt);

	//Public variables
	bool inUse;
private:
	std::string hash;
	std::string accountName;
	std::string salt;
	std::string card;
	int accountNum;
	long double balance;
	long double withdrawLimitRemaining;
	long double depositLimitRemaining;
	int transferAttemptsRemaining;
	int failsRemaining;
	bool locked;
};
#endif