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
    os/utils.cpp
    os/os.cpp
    os/stats.cpp
    os/path.cpp
    os/filestruct.cpp
    os/disk.cpp
    os/dos/dos.cpp
    os/dos/utils.cpp
    os/dos/interrupts.cpp
    os/mapper.cpp
    os/posix/posix.cpp
    os/linux/procfs.cpp
    os/linux/linux.cpp
    os/linux/thread.cpp
    os/linux/futex.cpp
    os/posix/kernel_api.cpp
    os/posix/const_mapping.cpp
    os/posix/stat.cpp
    os/posix/signal.cpp
    os/posix/socket.cpp
    os/posix/mman.cpp
    os/posix/syscall.cpp
    os/posix/syscall/abi.cpp
    os/freebsd/freebsd.cpp
    os/freebsd/syscall.cpp
    os/macos/macos.cpp
    os/macos/syscall.cpp
    os/macos/kernel_func.cpp
    os/macos/kernel_api.cpp
    os/macos/ev.cpp
    hw/hw.cpp
    hw/timer.cpp
    os/mcu.cpp
    hw/cm_nvic.cpp
    hw/cm_scb.cpp
    hw/stm32f1xx_gpio.cpp
    hw/stm32f4xx_usart.cpp
    hw/stm32f4xx_tim.cpp
    hw/stm32f1xx_exti.cpp
    hw/stm32f1xx_simple.cpp
    hw/stm32f1xx_interactive.cpp
    hw/sam3xa.cpp
    hw/gd32vf1xx.cpp
    hw/mk64f12.cpp
    loader/mcu.cpp
    os/macos/mach_msg.cpp
    os/macos/subsystems.cpp
    os/macos/utils.cpp
    os/qnx/qnx.cpp
    os/qnx/syscall.cpp
    os/qnx/helpers.cpp
    os/qnx/message.cpp
    os/windows/handle.cpp
    os/windows/fncc.cpp
    os/windows/windows.cpp
    os/windows/registry.cpp
    os/windows/clipboard.cpp
    os/windows/fiber.cpp
    os/windows/thread.cpp
    os/blob/blob.cpp
    loader/loader.cpp
    loader/blob.cpp
    loader/pe.cpp
    loader/elf.cpp
    loader/macho.cpp
    loader/dos.cpp
    loader/pe_uefi.cpp
    os/uefi/context.cpp
    os/uefi/uefi.cpp
    os/uefi/services.cpp
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

if(WIN32)
    # the posix socket layer rides winsock (the QlSocket host calls)
    target_link_libraries(qiling PUBLIC ws2_32)
endif()

add_library(qiling::qiling ALIAS qiling)
