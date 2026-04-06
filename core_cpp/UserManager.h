#pragma once
#include <string>
#include <unordered_map>

class UserManager {
private: 
    std::unordered_map<std::string, std::string> userDatabase;
    std::unordered_map<std::string, std::string> totpDatabase; // Store TOTP secrets for users
    std::unordered_map<std::string, std::string> resetTokens; // Store active reset tokens
    std::unordered_map<std::string, std::string> chapSecrets;
public:
    UserManager();
    bool registerUser(const std::string& username, const std::string& password);
    bool verifyUser(const std::string& username, const std::string& password);

    std::string generateTOTPSecret(const std::string& username);
    std::string getTOTPUri(const std::string& username, const std::string& issuer);
    std::string getTOTPSecret(const std::string& username);

    std::string generateResetToken(const std::string& email);
    bool resetPassword(const std::string& email, const std::string& token, const std::string& newPassword);

    std::string generateChallenge();
    bool verifyChallengeResponse(const std::string& email, const std::string& challenge, const std::string& response);
    
    bool updatePassword(const std::string& email, const std::string& newPassword);
    

};

