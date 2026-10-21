#include "qiling/host.hpp"

#include "qiling/utils.hpp"

#include <vector>

#if defined(_WIN32)
#include <windows.h>
#elif defined(__linux__)
#include <unistd.h>
#elif defined(__APPLE__)
#include <mach-o/dyld.h>
#endif

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

std::filesystem::path host_executable_path() {
#if defined(_WIN32)
    std::vector<char> buf(MAX_PATH);
    for (;;) {
        const auto len = ::GetModuleFileNameA(nullptr, buf.data(), static_cast<DWORD>(buf.size()));
        if (len == 0) {
            return {};
        }
        if (len < buf.size()) {
            return std::filesystem::path(std::string(buf.data(), len));
        }
        buf.resize(buf.size() * 2);
    }
#elif defined(__linux__)
    std::vector<char> buf(1024);
    for (;;) {
        const auto len = ::readlink("/proc/self/exe", buf.data(), buf.size());
        if (len < 0) {
            return {};
        }
        if (static_cast<std::size_t>(len) < buf.size()) {
            return std::filesystem::path(std::string(buf.data(), static_cast<std::size_t>(len)));
        }
        buf.resize(buf.size() * 2);
    }
#elif defined(__APPLE__)
    std::uint32_t size = 0;
    ::_NSGetExecutablePath(nullptr, &size);
    std::vector<char> buf(size + 1);
    if (::_NSGetExecutablePath(buf.data(), &size) != 0) {
        return {};
    }
    std::error_code ec;
    const auto canonical = std::filesystem::weakly_canonical(std::filesystem::path(buf.data()), ec);
    return ec ? std::filesystem::path(buf.data()) : canonical;
#else
    return {};
#endif
}

}  // namespace qiling
