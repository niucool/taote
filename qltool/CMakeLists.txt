add_executable(qltool main.cpp)

target_compile_definitions(qltool PRIVATE QILING_VERSION="${PROJECT_VERSION}")

target_link_libraries(qltool PRIVATE qiling cxxopts::cxxopts)
