add_executable(qiling_tests
    Util_Test.cpp
    Log_Test.cpp
    Profile_Test.cpp
    Exception_Test.cpp
    Arch_X86_Test.cpp
    Arch_Models_Test.cpp
    Cc_Test.cpp
)

# QILING_SOURCE_DIR lets the suites reach the bundled .ql profiles without install steps.
target_compile_definitions(qiling_tests PRIVATE QILING_SOURCE_DIR="${PROJECT_SOURCE_DIR}")

target_link_libraries(qiling_tests PRIVATE qiling GTest::gtest GTest::gtest_main)

include(GoogleTest)
gtest_discover_tests(qiling_tests)
