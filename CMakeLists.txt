cmake_minimum_required(VERSION 3.15)

project(qiling VERSION 1.4.11 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

# No -Werror initially (PORT_PLAN.md 8): 100k lines of fresh C++ will emit noise
# worth triaging before it is promoted to errors. Revisit after Phase 8.
if(MSVC)
    add_compile_options(/W4 /utf-8)
else()
    add_compile_options(-Wall -Wextra)
endif()

# Engine libraries are consumed from Phase 1 onward; resolving them here keeps the
# whole vcpkg manifest validated on every configure (unicorn pinned to 2.1.4, D15).
# unicorn and keystone vcpkg ports ship no CMake config files — engine-deps.cmake
# locates their headers/libs and defines the imported targets manually.
find_package(capstone CONFIG REQUIRED)
find_package(LIEF CONFIG REQUIRED)
find_package(nlohmann_json CONFIG REQUIRED)
find_package(spdlog CONFIG REQUIRED)
find_package(cxxopts CONFIG REQUIRED)
find_package(GTest CONFIG REQUIRED)
include(${CMAKE_CURRENT_LIST_DIR}/cmake/engine-deps.cmake)

# vcpkg toolchain; VS runtime deprecation noise is not useful for this port.
if(MSVC)
    add_compile_definitions(_CRT_SECURE_NO_WARNINGS NOMINMAX)
endif()

add_subdirectory(qiling)
add_subdirectory(qltool)
add_subdirectory(tools)

enable_testing()
add_subdirectory(tests)
