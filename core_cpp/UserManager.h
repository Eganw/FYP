#pragma once
#include <string>
#include <sqlite3.h> // NEW: Include SQLite

class UserManager {
private: 
    sqlite3* db; // NEW: The database connection pointer

public:
    UserManager();
    ~UserManager(); // NEW: Destructor to cleanly close the database

    bool registerUser(const std::string& email, const std::string& password);
    bool verifyUser(const std::string& email, const std::string& password);

    std::string generateTOTPSecret(const std::string& email);
    std::string getTOTPUri(const std::string& email, const std::string& issuer);
    std::string getTOTPSecret(const std::string& email);

    std::string generateResetToken(const std::string& email);
    bool resetPassword(const std::string& email, const std::string& token, const std::string& newPassword);

    std::string generateChallenge();
    bool verifyChallengeResponse(const std::string& email, const std::string& challenge, const std::string& response);
    
    bool updatePassword(const std::string& email, const std::string& newPassword);
};