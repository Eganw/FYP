cmake_minimum_required(VERSION 3.15)
project(egan_auth_project)

# --- NEW: Tell the compiler to use Modern C++ ---
set(CMAKE_CXX_STANDARD 14)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
# ------------------------------------------------

# Find pybind11
find_package(pybind11 REQUIRED)

# Find Libsodium on the Mac (installed via Homebrew)
find_library(SODIUM_LIB sodium)
find_path(SODIUM_INCLUDE_DIR sodium.h)

# Find SQLite3 (comes pre-installed on Mac)
find_library(SQLITE_LIB sqlite3)

# ==========================================
# 1. BUILD THE PYTHON BINDING (For the Web App)
# ==========================================
pybind11_add_module(egan_auth 
    python_binding/binding.cpp 
    core_cpp/UserManager.cpp
)
target_include_directories(egan_auth PRIVATE ${SODIUM_INCLUDE_DIR} core_cpp)
target_link_libraries(egan_auth PRIVATE ${SODIUM_LIB} ${SQLITE_LIB})

# ==========================================
# 2. BUILD THE C++ UNIT TESTS (For the FYP Report)
# ==========================================
add_executable(run_tests 
    tests/test_usermanager.cpp 
    core_cpp/UserManager.cpp
)
target_include_directories(run_tests PRIVATE ${SODIUM_INCLUDE_DIR} core_cpp)
target_link_libraries(run_tests PRIVATE ${SODIUM_LIB} ${SQLITE_LIB})