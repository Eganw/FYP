#include "UserManager.h"
#include <sodium.h>
#include <iostream>

// Constructor: Initializes cryptography and opens the database file
UserManager::UserManager() {
    if (sodium_init() < 0) {
        std::cerr << "Panic: Cryptography library failed to initialize!" << std::endl;
    }

    // Open (or create) the SQLite database file
    if (sqlite3_open("egan_auth.db", &db) != SQLITE_OK) {
        std::cerr << "Error opening database: " << sqlite3_errmsg(db) << std::endl;
    }

    // Create the users table if it doesn't exist
    const char* sql = "CREATE TABLE IF NOT EXISTS users ("
                      "email TEXT PRIMARY KEY, "
                      "password_hash TEXT NOT NULL, "
                      "chap_secret TEXT NOT NULL, "
                      "totp_secret TEXT, "
                      "reset_token TEXT);";
    char* errMsg = nullptr;
    if (sqlite3_exec(db, sql, nullptr, nullptr, &errMsg) != SQLITE_OK) {
        std::cerr << "SQL error: " << errMsg << std::endl;
        sqlite3_free(errMsg);
    }
}

// Destructor ensures the database is safely closed when the app shuts down
UserManager::~UserManager() {
    if (db) {
        sqlite3_close(db);
    }
}

bool UserManager::registerUser(const std::string& email, const std::string& password) {
    char hashed_password[crypto_pwhash_STRBYTES];
    if (crypto_pwhash_str(hashed_password, password.c_str(), password.length(), crypto_pwhash_OPSLIMIT_INTERACTIVE, crypto_pwhash_MEMLIMIT_INTERACTIVE) != 0) return false;

    unsigned char chap_hash[crypto_hash_sha256_BYTES];
    crypto_hash_sha256(chap_hash, (const unsigned char*)password.c_str(), password.length());
    char hex_chap[crypto_hash_sha256_BYTES * 2 + 1];
    sodium_bin2hex(hex_chap, sizeof(hex_chap), chap_hash, sizeof(chap_hash));

    const char* sql = "INSERT INTO users (email, password_hash, chap_secret) VALUES (?, ?, ?);";
    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) != SQLITE_OK) return false;

    sqlite3_bind_text(stmt, 1, email.c_str(), -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 2, hashed_password, -1, SQLITE_STATIC);
    sqlite3_bind_text(stmt, 3, hex_chap, -1, SQLITE_STATIC);

    int rc = sqlite3_step(stmt);
    sqlite3_finalize(stmt);
    return rc == SQLITE_DONE;
}

bool UserManager::verifyUser(const std::string& email, const std::string& password) {
    const char* sql = "SELECT password_hash FROM users WHERE email = ?;";
    sqlite3_stmt* stmt;
    bool isValid = false;

    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, email.c_str(), -1, SQLITE_STATIC);
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            const char* saved_hash = (const char*)sqlite3_column_text(stmt, 0);
            if (saved_hash && crypto_pwhash_str_verify(saved_hash, password.c_str(), password.length()) == 0) {
                isValid = true;
            }
        }
        sqlite3_finalize(stmt);
    }
    return isValid;
}

std::string UserManager::generateTOTPSecret(const std::string& email) {
    const char base32_chars[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";
    std::string secret = "";
    for(int i = 0; i < 16; i++) {
        secret += base32_chars[randombytes_uniform(32)];
    }
    
    const char* sql = "UPDATE users SET totp_secret = ? WHERE email = ?;";
    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, secret.c_str(), -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 2, email.c_str(), -1, SQLITE_STATIC);
        sqlite3_step(stmt);
        sqlite3_finalize(stmt);
    }
    return secret;
}

std::string UserManager::getTOTPSecret(const std::string& email) {
    const char* sql = "SELECT totp_secret FROM users WHERE email = ?;";
    sqlite3_stmt* stmt;
    std::string secret = "";

    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, email.c_str(), -1, SQLITE_STATIC);
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            const char* text = (const char*)sqlite3_column_text(stmt, 0);
            if (text) secret = text;
        }
        sqlite3_finalize(stmt);
    }
    return secret;
}

std::string UserManager::getTOTPUri(const std::string& email, const std::string& issuer) {
    std::string secret = getTOTPSecret(email);
    if (secret.empty()) return "";
    return "otpauth://totp/" + issuer + ":" + email + "?secret=" + secret + "&issuer=" + issuer;
}

std::string UserManager::generateResetToken(const std::string& email) {
    unsigned char token_bytes[16];
    randombytes_buf(token_bytes, sizeof(token_bytes));
    char hex_token[33];
    sodium_bin2hex(hex_token, sizeof(hex_token), token_bytes, sizeof(token_bytes));

    const char* sql = "UPDATE users SET reset_token = ? WHERE email = ?;";
    sqlite3_stmt* stmt;
    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, hex_token, -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 2, email.c_str(), -1, SQLITE_STATIC);
        sqlite3_step(stmt);
        sqlite3_finalize(stmt);
    }
    return std::string(hex_token);
}

bool UserManager::resetPassword(const std::string& email, const std::string& token, const std::string& newPassword) {
    // 1. Verify token
    const char* check_sql = "SELECT reset_token FROM users WHERE email = ?;";
    sqlite3_stmt* check_stmt;
    std::string saved_token = "";
    if (sqlite3_prepare_v2(db, check_sql, -1, &check_stmt, nullptr) == SQLITE_OK) {
        sqlite3_bind_text(check_stmt, 1, email.c_str(), -1, SQLITE_STATIC);
        if (sqlite3_step(check_stmt) == SQLITE_ROW) {
            const char* t = (const char*)sqlite3_column_text(check_stmt, 0);
            if (t) saved_token = t;
        }
        sqlite3_finalize(check_stmt);
    }

    if (saved_token.empty() || saved_token != token) return false;

    // 2. Perform Update
    return updatePassword(email, newPassword); 
}

std::string UserManager::generateChallenge() {
    unsigned char challenge_bytes[16];
    randombytes_buf(challenge_bytes, sizeof(challenge_bytes));
    char hex_challenge[33];
    sodium_bin2hex(hex_challenge, sizeof(hex_challenge), challenge_bytes, sizeof(challenge_bytes));
    return std::string(hex_challenge);
}

bool UserManager::verifyChallengeResponse(const std::string& email, const std::string& challenge, const std::string& response) {
    const char* sql = "SELECT chap_secret FROM users WHERE email = ?;";
    sqlite3_stmt* stmt;
    std::string chap_secret = "";

    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, email.c_str(), -1, SQLITE_STATIC);
        if (sqlite3_step(stmt) == SQLITE_ROW) {
            const char* t = (const char*)sqlite3_column_text(stmt, 0);
            if (t) chap_secret = t;
        }
        sqlite3_finalize(stmt);
    }

    if (chap_secret.empty()) return false;

    std::string combined = chap_secret + challenge;
    unsigned char expected_hash[crypto_hash_sha256_BYTES];
    crypto_hash_sha256(expected_hash, (const unsigned char*)combined.c_str(), combined.length());
    char hex_expected[crypto_hash_sha256_BYTES * 2 + 1];
    sodium_bin2hex(hex_expected, sizeof(hex_expected), expected_hash, sizeof(expected_hash));

    return std::string(hex_expected) == response;
}

bool UserManager::updatePassword(const std::string& email, const std::string& newPassword) {
    char hashed_password[crypto_pwhash_STRBYTES];
    if (crypto_pwhash_str(hashed_password, newPassword.c_str(), newPassword.length(), crypto_pwhash_OPSLIMIT_INTERACTIVE, crypto_pwhash_MEMLIMIT_INTERACTIVE) != 0) return false;

    unsigned char chap_hash[crypto_hash_sha256_BYTES];
    crypto_hash_sha256(chap_hash, (const unsigned char*)newPassword.c_str(), newPassword.length());
    char hex_chap[crypto_hash_sha256_BYTES * 2 + 1];
    sodium_bin2hex(hex_chap, sizeof(hex_chap), chap_hash, sizeof(chap_hash));

    const char* sql = "UPDATE users SET password_hash = ?, chap_secret = ?, reset_token = NULL WHERE email = ?;";
    sqlite3_stmt* stmt;
    bool success = false;

    if (sqlite3_prepare_v2(db, sql, -1, &stmt, nullptr) == SQLITE_OK) {
        sqlite3_bind_text(stmt, 1, hashed_password, -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 2, hex_chap, -1, SQLITE_STATIC);
        sqlite3_bind_text(stmt, 3, email.c_str(), -1, SQLITE_STATIC);
        if (sqlite3_step(stmt) == SQLITE_DONE && sqlite3_changes(db) > 0) {
            success = true;
        }
        sqlite3_finalize(stmt);
    }
    return success;
}