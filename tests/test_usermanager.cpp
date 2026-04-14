#define CATCH_CONFIG_MAIN 
#include "catch.hpp"
#include "../core_cpp/UserManager.h"

TEST_CASE("Core Cryptography and Password Handling", "[crypto]") {
    UserManager auth;
    std::string test_email = "fyp_test@gmail.com";
    std::string test_pwd = "SuperSecretPassword123!";

    SECTION("Registering a new user succeeds") {
        REQUIRE(auth.registerUser(test_email, test_pwd) == true);
    }

    SECTION("Verifying with correct password succeeds") {
        REQUIRE(auth.verifyUser(test_email, test_pwd) == true);
    }

    SECTION("Verifying with wrong password fails") {
        REQUIRE(auth.verifyUser(test_email, "WrongPassword!") == false);
    }
}

TEST_CASE("MFA Code Generation", "[mfa]") {
    UserManager auth;
    std::string test_email = "fyp_test@gmail.com";
    
    SECTION("Generated SMS code is exactly 6 digits long") {
        std::string code = auth.generateSMSCode(test_email);
        REQUIRE(code.length() == 6);
    }
}