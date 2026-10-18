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
    core_struct.cpp
    core_hooks.cpp
    core.cpp
    host.cpp
    os/memory.cpp
    os/fcall.cpp
    os/os.cpp
    os/stats.cpp
    os/path.cpp
    os/filestruct.cpp
    os/mapper.cpp
    os/posix/posix.cpp
    os/posix/syscall.cpp
    os/posix/syscall/abi.cpp
    os/windows/handle.cpp
    os/windows/fncc.cpp
    os/windows/windows.cpp
    os/windows/clipboard.cpp
    os/windows/fiber.cpp
    os/windows/thread.cpp
    os/blob/blob.cpp
    loader/loader.cpp
    loader/blob.cpp
    loader/pe.cpp
    loader/elf.cpp
    snapshot.cpp
    cc/cc.cpp
    cc/arm.cpp
    cc/intel.cpp
    cc/mips.cpp
    cc/ppc.cpp
    cc/riscv.cpp
)

# profile_setup reads the bundled .ql profiles; the source dir reaches the
# library the same way it reaches the test suites (no install steps needed)
target_compile_definitions(qiling PRIVATE QILING_SOURCE_DIR="${PROJECT_SOURCE_DIR}")

# Consumers include as "qiling/xxx.hpp" — the include root is the repository root,
# mirroring the Python package layout (port root = repo root, PORT_PLAN.md D16).
target_include_directories(qiling PUBLIC ${PROJECT_SOURCE_DIR})

find_package(LIEF CONFIG REQUIRED)

target_link_libraries(qiling PUBLIC
    spdlog::spdlog
    unicorn::unicorn
    capstone::capstone
    keystone::keystone
    LIEF::LIEF
)

add_library(qiling::qiling ALIAS qiling)
