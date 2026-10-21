cmake_minimum_required(VERSION 3.15)

project(qiling VERSION 1.4.11 LANGUAGES CXX)

# the default `make install` destination, overridable with -DTAOTE_INSTALL_DIRNAME=
set(TAOTE_INSTALL_DIRNAME "deploy" CACHE STRING "Build-tree directory `make install` targets")

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

enable_testing()

add_subdirectory(qiling)
add_subdirectory(qltool)
add_subdirectory(tools)
add_subdirectory(tests)

# ---- install -------------------------------------------------------------
#
# `make install` populates build/deploy by default (bin/ + lib/ + include/ +
# share/), so the whole tree can be copied somewhere else and used as-is:
#
#   build/deploy/bin/qltool
#   build/deploy/bin/parity_trace
#   build/deploy/bin/gap_census
#   build/deploy/bin/qiling_tests        (the suite, for a deployed smoke test)
#   build/deploy/lib/libqiling.a
#   build/deploy/include/qiling/...
#   build/deploy/share/qiling/profiles/*.ql
#
# The dependency set resolved through vcpkg is static (LIEF, unicorn, capstone,
# keystone, spdlog/fmt), so the binaries only need the host C++ runtime. The
# profiles are found relative to the executable (see profile_dir() in core.cpp),
# which is what keeps the copied tree relocatable; TAOTE_PROFILE_DIR overrides.
#   cmake --install build            or: make -C build install
#   cmake --install build --prefix /opt/taote
include(GNUInstallDirs)

# Default the prefix into the build tree. An explicit -DTAOTE_DEPLOY_DIR= (or a
# -DCMAKE_INSTALL_PREFIX= at first configure) wins, and `cmake --install build
# --prefix <dir>` overrides at install time regardless.
set(TAOTE_DEPLOY_DIR "${CMAKE_BINARY_DIR}/${TAOTE_INSTALL_DIRNAME}" CACHE PATH
    "Where `make install` puts the deployable tree")
if(CMAKE_INSTALL_PREFIX STREQUAL "/usr/local" OR CMAKE_INSTALL_PREFIX STREQUAL "")
    set(CMAKE_INSTALL_PREFIX "${TAOTE_DEPLOY_DIR}" CACHE PATH
        "Where `make install` puts the deployable tree" FORCE)
endif()

install(TARGETS qiling
        ARCHIVE DESTINATION "${CMAKE_INSTALL_LIBDIR}")
install(TARGETS qltool parity_trace gap_census qiling_tests
        RUNTIME DESTINATION "${CMAKE_INSTALL_BINDIR}")
install(DIRECTORY qiling/
        DESTINATION "${CMAKE_INSTALL_INCLUDEDIR}/qiling"
        FILES_MATCHING PATTERN "*.hpp")
install(DIRECTORY qiling/profiles/
        DESTINATION "${CMAKE_INSTALL_DATADIR}/qiling/profiles"
        FILES_MATCHING PATTERN "*.ql")
