#include "UserManager.h"
#include <sodium.h>
#include <iostream>

// Constructor: Initializes the libsodium cryptography library
UserManager::UserManager() {
    if (sodium_init() < 0) {
        std::cerr << "Panic: Cryptography library failed to initialize!" << std::endl;
    }
}

// R1 & R2: Register a user and hash their password securely
bool UserManager::registerUser(const std::string& username, const std::string& password) {
    // Check if user already exists
    if (userDatabase.find(username) != userDatabase.end()) {
        return false; 
    }

    // Prepare an array to hold the hashed password. 
    // crypto_pwhash_STRBYTES is the exact length needed for Argon2id.
    char hashed_password[crypto_pwhash_STRBYTES];

    // Hash the password using Argon2id (Secure salting is built-in automatically!)
    if (crypto_pwhash_str(
            hashed_password, 
            password.c_str(), 
            password.length(),
            crypto_pwhash_OPSLIMIT_INTERACTIVE, // CPU difficulty
            crypto_pwhash_MEMLIMIT_INTERACTIVE  // Memory difficulty
        ) != 0) {
        return false; // Hashing failed (e.g., ran out of system memory)
    }

    // Save the user and their securely hashed password to our database
    userDatabase[username] = std::string(hashed_password);
    return true;
}

// R1: Verify a user's login attempt
bool UserManager::verifyUser(const std::string& username, const std::string& password) {
    // Find the user in the database
    auto it = userDatabase.find(username);
    if (it == userDatabase.end()) {
        return false; // User not found
    }

    // Grab the saved Argon2id hash from the database
    std::string saved_hash = it->second;

    // libsodium compares the plaintext password against the saved hash securely
    if (crypto_pwhash_str_verify(saved_hash.c_str(), password.c_str(), password.length()) == 0) {
        return true; // Password matches!
    }
    
    return false; // Incorrect password
}

// R3: Generate a secure 16-character Base32 secret for Google Authenticator
std::string UserManager::generateTOTPSecret(const std::string& username) {
    const char base32_chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    std::string secret = "";
    
    // Generate 16 random characters from the Base32 alphabet
    for(int i = 0; i < 16; i++) {
        // libsodium's randombytes_uniform is cryptographically secure!
        uint32_t random_index = randombytes_uniform(32); 
        secret += base32_chars[random_index];
    }
    
    // Save it to our in-memory database
    totpDatabase[username] = secret;
    return secret;
}

// R3: Format the standard URI needed to generate a QR Code
std::string UserManager::getTOTPUri(const std::string& username, const std::string& issuer) {
    if (totpDatabase.find(username) == totpDatabase.end()) {
        return ""; // User doesn't have a secret yet
    }
    std::string secret = totpDatabase[username];
    // This is the official RFC format for authenticator apps
    return "otpauth://totp/" + issuer + ":" + username + "?secret=" + secret + "&issuer=" + issuer;
}

std::string UserManager::getTOTPSecret(const std::string& username) {
    if (totpDatabase.find(username) != totpDatabase.end()) {
        return totpDatabase[username]; // Return the secret if found
    }
    return "";
}

// R4: Generate a secure, random hex token for password resets
std::string UserManager::generateResetToken(const std::string& email) {
    // Only generate a token if the user actually exists
    if (userDatabase.find(email) == userDatabase.end()) {
        return ""; 
    }

    // Generate 16 bytes of cryptographically secure random data
    unsigned char token_bytes[16];
    randombytes_buf(token_bytes, sizeof(token_bytes));

    // Convert those bytes into a readable 32-character hex string
    char hex_token[33];
    sodium_bin2hex(hex_token, sizeof(hex_token), token_bytes, sizeof(token_bytes));

    std::string token_str(hex_token);
    
    // Save it to our database
    resetTokens[email] = token_str;
    return token_str;
}

// R4: Verify the token and update the password
bool UserManager::resetPassword(const std::string& email, const std::string& token, const std::string& newPassword) {
    // 1. Check if the token exists and matches the one provided
    if (resetTokens.find(email) == resetTokens.end() || resetTokens[email] != token) {
        return false; // Invalid or expired token
    }

    // 2. Hash the new password
    char hashed_password[crypto_pwhash_STRBYTES];
    if (crypto_pwhash_str(
            hashed_password, 
            newPassword.c_str(), 
            newPassword.length(),
            crypto_pwhash_OPSLIMIT_INTERACTIVE, 
            crypto_pwhash_MEMLIMIT_INTERACTIVE
        ) != 0) {
        return false; 
    }

    // 3. Update the database with the new password
    userDatabase[email] = std::string(hashed_password);
    
    // 4. IMPORTANT: Erase the token so it cannot be reused (Single-Use!)
    resetTokens.erase(email);
    
    return true;
}