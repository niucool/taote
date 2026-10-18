add_executable(qiling_tests
    Util_Test.cpp Util_Factory_Test.cpp Qiling_Test.cpp Path_Test.cpp FsMapper_Test.cpp Loader_Test.cpp Arch_Utils_Test.cpp Loader_Pe_Test.cpp Windows_Handle_Test.cpp Posix_Test.cpp Loader_Elf_Test.cpp Windows_Subsystems_Test.cpp Windows_Api_Test.cpp
    Log_Test.cpp
    Profile_Test.cpp
    Exception_Test.cpp
    Arch_X86_Test.cpp
    Arch_Models_Test.cpp
    Cc_Test.cpp
    Struct_Test.cpp
    CoreHooks_Test.cpp
    Memory_Test.cpp
    Fcall_Test.cpp
    Snapshot_Test.cpp
    Host_Test.cpp
    Cc_Arch_Test.cpp
    Arch_Arm_Test.cpp
    Arch_Arm64_Test.cpp
    Arch_Mips_Test.cpp
    Arch_Ppc_Test.cpp
    Arch_Riscv_Test.cpp
)

# QILING_SOURCE_DIR lets the suites reach the bundled .ql profiles without install steps.
target_compile_definitions(qiling_tests PRIVATE QILING_SOURCE_DIR="${PROJECT_SOURCE_DIR}")

target_link_libraries(qiling_tests PRIVATE qiling GTest::gtest GTest::gtest_main)

include(GoogleTest)
gtest_discover_tests(qiling_tests)
