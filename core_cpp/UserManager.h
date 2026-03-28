#pragma once
#include <string>
#include <unordered_map>

class UserManager {
private: 
    std::unordered_map<std::string, std::string> userDatabase;
    std::unordered_map<std::string, std::string> totpDatabase; // Store TOTP secrets for users
public:
    UserManager();
    bool registerUser(const std::string& username, const std::string& password);
    bool verifyUser(const std::string& username, const std::string& password);

    std::string generateTOTPSecret(const std::string& username);
    std::string getTOTPUri(const std::string& username, const std::string& issuer);
    std::string getTOTPSecret(const std::string& username);

};

