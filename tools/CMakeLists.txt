add_executable(gap_census gap_census.cpp)
target_link_libraries(gap_census PRIVATE qiling LIEF::LIEF)

# tools/parity_trace.cpp — the taote side of the qiling-parity differential
# (PLAN_PARITY.md Phase 1.9). It reuses the tests' sample runner, so the tests
# directory has to be on the include path.
add_executable(parity_trace parity_trace.cpp)
target_include_directories(parity_trace PRIVATE ${CMAKE_SOURCE_DIR})
target_link_libraries(parity_trace PRIVATE qiling LIEF::LIEF)

find_program(TAOTE_PYTHON3 NAMES python3 python)
if(TAOTE_PYTHON3)
    # the smoke gate: the differential has to find at least one clean sample.
    # it SKIPs (77) when the reference checkout or a python with qiling's
    # dependencies is not available on the host.
    add_test(NAME Tools.ParityVsQilingSmoke
             COMMAND ${TAOTE_PYTHON3} ${CMAKE_SOURCE_DIR}/tools/parity_vs_qiling.py
                     --quiet --require-match 1
                     --taote-trace $<TARGET_FILE:parity_trace>)
    set_tests_properties(Tools.ParityVsQilingSmoke PROPERTIES
                         SKIP_RETURN_CODE 77
                         TIMEOUT 900)
endif()

# tools/taote.cpp — the packed-PE unpacker (PLAN_UNPACK.md). The flag
# surface is pegasus's so its evaluation harness drives taote unmodified.
add_executable(taote taote.cpp)
target_include_directories(taote PRIVATE ${CMAKE_SOURCE_DIR})
target_link_libraries(taote PRIVATE qiling_unpack LIEF::LIEF)
