#include "qiling/arch/utils.hpp"

#include <cstring>

#include <capstone/capstone.h>
#include <keystone/keystone.h>

#include "qiling/exception.hpp"

namespace qiling {

// ---- Cs (capstone) ----

Cs::Cs(cs_arch arch, cs_mode mode) {
    if (cs_open(arch, mode, &handle_) != CS_ERR_OK) {
        throw QlErrorArch("failed to initialize capstone");
    }
}

Cs::~Cs() {
    if (handle_ != 0) cs_close(&handle_);
}

Cs::Cs(Cs&& other) noexcept : handle_(other.handle_) { other.handle_ = 0; }

Cs& Cs::operator=(Cs&& other) noexcept {
    if (this != &other) {
        if (handle_ != 0) cs_close(&handle_);
        handle_ = other.handle_;
        other.handle_ = 0;
    }
    return *this;
}

std::vector<Cs::Insn> Cs::disasm(std::string_view bytes, std::uint64_t address) const {
    std::vector<Insn> out;
    const std::uint8_t* begin = reinterpret_cast<const std::uint8_t*>(bytes.data());
    const std::uint8_t* end = begin + bytes.size();

    while (begin < end) {
        cs_insn* raw = nullptr;
        const std::size_t count = cs_disasm(handle_, begin, static_cast<std::size_t>(end - begin), address, 1, &raw);
        if (count == 0) break;  // stop at an invalid instruction (Cs.disasm semantics)

        auto& insn = raw[0];
        out.push_back(Insn{insn.address, static_cast<std::uint16_t>(insn.size), insn.mnemonic, insn.op_str});
        address += insn.size;
        begin += insn.size;
        cs_free(raw, count);
    }
    return out;
}

// ---- Ks (keystone) ----

Ks::Ks(ks_arch arch, int mode) {
    if (ks_open(arch, mode, &handle_) != KS_ERR_OK) {
        throw QlErrorArch("failed to initialize keystone");
    }
}

Ks::~Ks() {
    if (handle_ != nullptr) ks_close(handle_);
}

Ks::Ks(Ks&& other) noexcept : handle_(other.handle_) { other.handle_ = nullptr; }

Ks& Ks::operator=(Ks&& other) noexcept {
    if (this != &other) {
        if (handle_ != nullptr) ks_close(handle_);
        handle_ = other.handle_;
        other.handle_ = nullptr;
    }
    return *this;
}

std::vector<std::uint8_t> Ks::assemble(std::string_view assembly) const {
    std::size_t size = 0;
    std::size_t stat_count = 0;
    unsigned char* encode = nullptr;

    // ks_asm returns the number of statements compiled, or a negative ks_err on error
    const int statements = ks_asm(handle_, std::string(assembly).c_str(), 0, &encode, &size, &stat_count);
    if (statements < 0) {
        throw QlErrorBase("assembly failed (ks_err " + std::to_string(statements) + "): " + std::string(assembly));
    }

    std::vector<std::uint8_t> out(encode, encode + size);
    ks_free(encode);
    return out;
}

// ---- standalone assembler factory (utils.py `assembler`, verbatim mapping) ----

Ks assembler(QL_ARCH arch, QL_ENDIAN endianness, bool is_thumb) {
    const int endian = endianness == QL_ENDIAN::EL ? KS_MODE_LITTLE_ENDIAN : KS_MODE_BIG_ENDIAN;
    const int thumb = is_thumb ? KS_MODE_THUMB : 0;

    switch (arch) {
        case QL_ARCH::CORTEX_M:
            return Ks(KS_ARCH_ARM, KS_MODE_ARM + KS_MODE_LITTLE_ENDIAN + KS_MODE_THUMB);
        case QL_ARCH::ARM:
            return Ks(KS_ARCH_ARM, KS_MODE_ARM + endian + thumb);
        case QL_ARCH::ARM64:
            return Ks(KS_ARCH_ARM64, KS_MODE_ARM);
        case QL_ARCH::MIPS:
            return Ks(KS_ARCH_MIPS, KS_MODE_MIPS32 + endian);
        case QL_ARCH::A8086:
            return Ks(KS_ARCH_X86, KS_MODE_16);
        case QL_ARCH::X86:
            return Ks(KS_ARCH_X86, KS_MODE_32);
        case QL_ARCH::X8664:
            return Ks(KS_ARCH_X86, KS_MODE_64);
        case QL_ARCH::PPC:
            return Ks(KS_ARCH_PPC, KS_MODE_PPC32 + KS_MODE_BIG_ENDIAN);
        default:
            throw QlErrorNotImplemented("no keystone support for this arch");
    }
}

}  // namespace qiling
