#include "account.h"
#include <string.h>
#include <fstream>
#include <iostream>

/*
 * Constuct
 */

Account::Account()
{
	locked = true;
	inUse = false;
	failsRemaining = 3;
	transferAttemptsRemaining = 3;
	withdrawLimitRemaining = 1000;
	depositLimitRemaining = 1000000000;
	balance = 0;
	accountNum = 0;
	hash = "";
}

/*
 * Transfer
 */
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

/*
 * Withdraw
 */
//Funds is what you're withdrawing
bool Account::tryWithdraw(long double funds) const
{
	//We don't allow overdraft
	if(this->balance - funds < 0)
	{
		return false;
	}
	if(funds < 0)
	{
		return false;
	}

	//You cannot exceed your withdrawal limit
	if(funds > this->withdrawLimitRemaining)
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

/*
 * Deposit
 */

bool Account::tryDeposit(long double funds) const
{
	if(funds < 0)
	{
		return false;
	}
	
	if(funds > this->depositLimitRemaining){
		return false;
	}

	return true;
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


/*
 * Other functions
 */

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


	std::string card = makeHash(to_string(this->accountNum) + bankSalt);

	this->card = card;

	std::ofstream outfile;

	std::string cardFile = "cards/" + this->accountName + ".card";

	std::ofstream file_out(cardFile.c_str());
	if(file_out.is_open())
	{
		file_out << card;
	} //end if valid outfstream
	file_out.close();
	//outfile.open (cardFile.c_str(), std::ios_base::out|std::ios_base::trunc);
	//if(outfile.is_open())
	//{
	//	outfile << card;
	//}
	//outfile.close();

	//If you successfully set the pin then the account can be unlocked for use.
	if(setPIN(pin, bankSalt))
	{
		locked = false;
	} else {
		locked = true;
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

	//verify that hash was actually created
	if(hash.length() > 0)
	{
		this->hash = hash;
		return true;
	} else {
		return false;
	}
}

bool Account::tryHash(const std::string& attemptedHash)
{
	if(this->locked || this->inUse)
	{
		return false;
	}
	if(this->hash == attemptedHash)
	{
		return true;
	} else {
			if(failsRemaining > 1)
		{
			this->failsRemaining -= 1;
		} 	else {
			this->locked = true;
		}
		return false;
	}	
}


bool Account::attemptLogin(const std::string& pin, const std::string& bankSalt)
{
	if(this->locked || this->inUse)
	{
		return false;
	}

	std::string attemptedHash = makeHash(this->card + pin + bankSalt);

	if(this->hash == attemptedHash)
	{
		return true;
	} else {
		if(failsRemaining > 1)
		{
			this->failsRemaining -= 1;
		} else {
			this->locked = true;
		}
		return false;
	}
}
