add_library(qiling STATIC
    exception.cpp
    log.cpp
    utils.cpp
    profiles/inireader.cpp
)

# Consumers include as "qiling/xxx.hpp" — the include root is the repository root,
# mirroring the Python package layout (port root = repo root, PORT_PLAN.md D16).
target_include_directories(qiling PUBLIC ${PROJECT_SOURCE_DIR})

target_link_libraries(qiling PUBLIC spdlog::spdlog)

add_library(qiling::qiling ALIAS qiling)
