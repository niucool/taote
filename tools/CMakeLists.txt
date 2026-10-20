add_executable(gap_census gap_census.cpp)

target_link_libraries(gap_census PRIVATE qiling LIEF::LIEF)
