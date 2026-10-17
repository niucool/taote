add_library(qiling STATIC
    exception.cpp
    log.cpp
    utils.cpp
    profiles/inireader.cpp
    arch/arch.cpp
    arch/msr.cpp
    arch/register.cpp
    arch/utils.cpp
    arch/arm.cpp
    arch/arm64.cpp
    arch/cpr.cpp
    arch/mips.cpp
    arch/ppc.cpp
    arch/riscv.cpp
    arch/x86.cpp
    cc/cc.cpp
    cc/arm.cpp
    cc/intel.cpp
    cc/mips.cpp
    cc/ppc.cpp
    cc/riscv.cpp
)

# Consumers include as "qiling/xxx.hpp" — the include root is the repository root,
# mirroring the Python package layout (port root = repo root, PORT_PLAN.md D16).
target_include_directories(qiling PUBLIC ${PROJECT_SOURCE_DIR})

target_link_libraries(qiling PUBLIC
    spdlog::spdlog
    unicorn::unicorn
    capstone::capstone
    keystone::keystone
)

add_library(qiling::qiling ALIAS qiling)
