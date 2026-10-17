#include "qiling/host.hpp"

#include "qiling/utils.hpp"

namespace qiling {

namespace {

// platform.system() equivalent
const char* host_system() {
#if defined(_WIN32)
    return "Windows";
#elif defined(__APPLE__)
    return "Darwin";
#elif defined(__linux__)
    return "Linux";
#elif defined(__FreeBSD__)
    return "FreeBSD";
#else
    return "";
#endif
}

// platform.machine() equivalent
const char* host_machine() {
#if defined(_M_X64) || defined(__x86_64__)
    return "AMD64";
#elif defined(_M_ARM64) || defined(__aarch64__)
    return "ARM64";
#elif defined(_M_ARM) || defined(__arm__)
    return "ARM";
#elif defined(__mips__)
    return "MIPS";
#elif defined(__riscv) && (__riscv_xlen == 64)
    return "RISCV64";
#elif defined(__riscv)
    return "RISCV";
#elif defined(__powerpc64__)
    return "PPC64";
#elif defined(__powerpc__)
    return "PPC";
#else
    return "";
#endif
}

}  // namespace

std::optional<QL_OS> QlHost::os() const {
    if (!os_done_) {
        os_ = os_convert(host_system());
        os_done_ = true;
    }
    return os_;
}

std::optional<QL_ARCH> QlHost::arch() const {
    if (!arch_done_) {
        arch_ = arch_convert(host_machine());
        arch_done_ = true;
    }
    return arch_;
}

}  // namespace qiling
