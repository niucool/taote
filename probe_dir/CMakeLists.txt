cmake_minimum_required(VERSION 3.15)
project(probe CXX)
set(CMAKE_CXX_STANDARD 17)
add_compile_definitions(NOMINMAX)
if(MSVC)
    add_compile_options(/utf-8)
endif()
add_executable(probe probe_main.cpp
    "E:/Projects/github/taote/qiling/core_hooks.cpp"
    "E:/Projects/github/taote/qiling/arch/x86.cpp"
    "E:/Projects/github/taote/qiling/arch/arch.cpp"
    "E:/Projects/github/taote/qiling/arch/register.cpp"
    "E:/Projects/github/taote/qiling/arch/utils.cpp"
    "E:/Projects/github/taote/qiling/exception.cpp"
    "E:/Projects/github/taote/qiling/utils.cpp"
    "E:/Projects/github/taote/qiling/log.cpp"
    "E:/Projects/github/taote/qiling/core_struct.cpp" "E:/Projects/github/taote/qiling/core_struct.cpp" "E:/Projects/github/taote/qiling/os/memory.cpp" "E:/Projects/github/taote/qiling/snapshot.cpp" "E:/Projects/github/taote/qiling/os/fcall.cpp" "E:/Projects/github/taote/qiling/cc/cc.cpp" "E:/Projects/github/taote/qiling/cc/intel.cpp")
target_include_directories(probe PRIVATE "E:/Projects/github/taote" "E:/Projects/github/taote/build/vcpkg_installed/x64-windows/include")
target_link_directories(probe PRIVATE "E:/Projects/github/taote/build/vcpkg_installed/x64-windows/lib" "E:/Projects/github/taote/build/vcpkg_installed/x64-windows/bin")
target_link_libraries(probe PRIVATE unicorn capstone keystone spdlog fmt)
