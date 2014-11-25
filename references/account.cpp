#include "account.h"
#include <string.h>
#include <fstream>
#include <util.h>
#include <iostream>

//Constuctor function which sets initial values

Account::Account()
{
	islocked = true;
	inUse = false;
	failsRemaining = 3;
	transferAttemptsRemaining = 3;
	withdrawLimitRemaining = 1000;
	depositLimitRemaining = 1000000000;
	balance = 0;
	accountNum = 0;
	hash = "";
}

//Transfer functions to move funds between accounts
bool Account::tryTransfer(long double funds, const Account* toAccount) const
{
	if(!this->transferAttemptsRemaining)
	{
		return false;
	}
	if(!toAccount)
	{
		return false;
	}
	if(!tryWithdraw(funds))
	{
		return false;
	}


	if(!toAccount->tryDeposit(funds))
	{
		return false;
	}

	return true;
}
bool Account::Transfer(long double funds, Account* toAccount)
{
	if(funds == 0)
	{
		return false;
	}

	if(tryTransfer(funds, toAccount))
	{
		Withdraw(funds);
		toAccount->Deposit(funds);
		return true;
	}
	if(this->transferAttemptsRemaining > 0)
	{
		this->transferAttemptsRemaining--;
	}
	return false;
}

// Withdraw function to handle user withdrawing from account
bool Account::tryWithdraw(long double funds) const
{
	//do not allow withdrawing more than user has
	if(this->balance - funds < 0)
	{
		return false;
	}
	if(funds < 0)
	{
		return false;
	}

	//Check if funds is exceeding remaining limit
	if(funds > this->withdrawLimitRemaining)
	{
		return false;
	}

	//Prevent overflow
	if(doubleOverflow(this->balance,funds*-1))
	{
		return false;
	}



	return true;
}

bool Account::Withdraw(long double funds)
{
	if(tryWithdraw(funds))
	{
		this->balance -= funds;
		this->withdrawLimitRemaining -= funds;
		return true;
	}

	return false;
}

// Deposit functions to allow for adding of fundss to account

bool Account::tryDeposit(long double funds) const
{
	if(funds < 0)
	{
		return false;
	}
	
	if(funds > this->depositLimitRemaining){
		return false;
	}

	if(!doubleOverflow(this->balance,funds))
	{
		return true;
	} else {
		return false;
	}
}

bool Account::Deposit(long double funds)
{
	if(tryDeposit(funds))
	{
		this->balance += funds;
		this->depositLimitRemaining -= funds;
		return true;
	}
	return false;
}


//create account with given paramters 

bool Account::createAccount(const std::string& accountName, const int& accountNum, const std::string& pin, const std::string& bankSalt)
{
	if(accountName == "")
	{
		return false;
	}
	this->accountName = accountName;
	if(accountNum <= 0)
	{
		return false;
	}
	this->accountNum = accountNum;

	this->salt = makeHash(randomString(128));

	std::string card = makeHash(to_string(this->accountNum) + salt);

	this->card = card;

	std::ofstream outfile;

	std::string cardFile = "cards/" + this->accountName + ".card";

	std::ofstream file_out(cardFile.c_str());
	// write values to cards
	if(file_out.is_open())
	{
		file_out << card;
	} 
	file_out.close();

	//If oin sucessfully set then the account can be unlocked for use.
	if(setPIN(pin, bankSalt))
	{
		islocked = false;
	} else {
		islocked = true;
	}

	return true;
}

bool Account::setPIN(const std::string& pin, const std::string& bankSalt)
{
	//require pin length of at least 6 but no more than 32
	if(pin.length() < 6 || pin.length() > 32)
	{
		return false;
	}
	std::string hash = makeHash(this->card + pin + bankSalt);

	//verify that hash was created
	if(hash.length() > 0)
	{
		this->hash = hash;
		return true;
	} else {
		return false;
	}
}

bool Account::tryLogin(const std::string& pin, const std::string& bankSalt)
{
	if(this->islocked || this->inUse)
	{
		return false;
	}

	std::string attemptedHash = makeHash(this->card + pin + bankSalt);

	if(this->hash == attemptedHash)
	{
		return true;
	} else {
		failCount();
		return false;
	}
}

bool Account::tryHash(const std::string& attemptedHash)
{
	if(this->islocked || this->inUse)
	{
		return false;
	}
	if(this->hash == attemptedHash)
	{
		return true;
	} else {
		failCount();
		return false;
	}	
}

void Account::failCount()
{
	if(failsRemaining > 1)
	{
		this->failsRemaining -= 1;
	} else {
		this->islocked = true;
	}
}
