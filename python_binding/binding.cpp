#include <pybind11/pybind11.h>
#include "../core_cpp/UserManager.h"

namespace py = pybind11;

PYBIND11_MODULE(egan_auth, m) {
    m.doc() = "Egan's Core Authentication Library (C++ Core)";
    
    py::class_<UserManager>(m, "UserManager")
        .def(py::init<>())
        .def("register_user", &UserManager::registerUser, "Register a new user")
        .def("verify_user", &UserManager::verifyUser, "Verify a user's password")
        .def("generate_totp_secret", &UserManager::generateTOTPSecret, "Generate Base32 secret")
        .def("get_totp_uri", &UserManager::getTOTPUri, "Get URI for QR Code generation")
        .def("get_totp_secret", &UserManager::getTOTPSecret, "Retrieve a user's TOTP secret")
        .def("generate_reset_token", &UserManager::generateResetToken, "Generate a password reset token")
        .def("reset_password", &UserManager::resetPassword, "Reset the user's password with a token")
        .def("generate_challenge", &UserManager::generateChallenge, "Generate a random login challenge")
        .def("verify_challenge_response", &UserManager::verifyChallengeResponse, "Verify the challenge response")
        .def("update_password", &UserManager::updatePassword, "Update an existing user's password")
        .def("enroll_sms", &UserManager::enrollSMS, "Enroll a phone number for SMS MFA")
        .def("get_phone_number", &UserManager::getPhoneNumber, "Get the enrolled phone number")
        .def("generate_sms_code", &UserManager::generateSMSCode, "Generate and store an SMS code")
        .def("verify_sms_code", &UserManager::verifySMSCode, "Verify the 6-digit SMS code");

        
        
}