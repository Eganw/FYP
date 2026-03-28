cmake_minimum_required(VERSION 3.15)
project(egan_auth_project)

# Find pybind11
find_package(pybind11 REQUIRED)

# Find Libsodium on the Mac (installed via Homebrew)
find_library(SODIUM_LIB sodium)
find_path(SODIUM_INCLUDE_DIR sodium.h)

# Tell CMake to compile BOTH our binding and our core logic
pybind11_add_module(egan_auth 
    python_binding/binding.cpp 
    core_cpp/UserManager.cpp
)

# Link the libraries to our project
target_include_directories(egan_auth PRIVATE ${SODIUM_INCLUDE_DIR} core_cpp)
target_link_libraries(egan_auth PRIVATE ${SODIUM_LIB})
