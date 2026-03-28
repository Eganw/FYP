#include <pybind11/pybind11.h>
#include "../core_cpp/UserManager.h"

namespace py = pybind11;

PYBIND11_MODULE(egan_auth, m) {
    m.doc() = "Egan's Core Authentication Library (C++ Core)";
    
    py::class_<UserManager>(m, "UserManager")
        .def(py::init<>())
        .def("register_user", &UserManager::registerUser, "Register a new user")
        .def("verify_user", &UserManager::verifyUser, "Verify a user's password")
        // NEW BINDINGS FOR R3
        .def("generate_totp_secret", &UserManager::generateTOTPSecret, "Generate Base32 secret")
        .def("get_totp_uri", &UserManager::getTOTPUri, "Get URI for QR Code generation");
}
