#include "qiling/arch/utils.hpp"

#include <cstdio>
#include <cstring>

#include <capstone/capstone.h>
#include <keystone/keystone.h>

#include "qiling/core.hpp"
#include "qiling/exception.hpp"
#include "qiling/log.hpp"
#include "qiling/os/memory.hpp"

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



namespace {

// the hex rendering of the instruction bytes (utils.py ibytes.hex())
std::string hex_bytes(const std::vector<std::uint8_t>& data, std::size_t pos, std::size_t len) {
    static const char* digits = "0123456789abcdef";
    std::string out;
    out.reserve(len * 2);
    for (std::size_t i = 0; i < len && pos + i < data.size(); ++i) {
        const auto byte = data[pos + i];
        out.push_back(digits[(byte >> 4) & 0xF]);
        out.push_back(digits[byte & 0xF]);
    }
    return out;
}

}  // namespace

// ---- QlArchUtils (arch/utils.py) ----

std::string basename_of(std::string_view path) {
    const auto slash = path.find_last_of("/\\");
    return std::string(slash == std::string_view::npos ? path : path.substr(slash + 1));
}

void QlArchUtils::shutdown() {
    if (disasm_hook_) {
        disasm_hook_->remove();
        disasm_hook_.reset();
    }
    if (block_hook_) {
        block_hook_->remove();
        block_hook_.reset();
    }
    base_cache_.clear();
}

QlArchUtils::QlArchUtils(Qiling& ql) : ql_(ql) {
}

QlArchUtils::~QlArchUtils() {
}

std::pair<std::uint64_t, std::string> QlArchUtils::get_base_and_name(std::uint64_t addr) {
    // executable images may be mapped in multiple consecutive regions, so
    // locating an address within a region doesn't mean its base address is
    // the base of the image: iterate the map regions as if coalesced by
    // label to find the image base (utils.py get_base_and_name, verbatim)
    const auto it = base_cache_.find(addr);
    if (it != base_cache_.end()) {
        return it->second;
    }

    std::string base_label = "?";
    std::uint64_t base_addr = static_cast<std::uint64_t>(-1);

    std::pair<std::uint64_t, std::string> result;

    const auto& regions = ql_.mem().map_info();
    for (const auto& region : regions) {
        // reached a different image?
        if (region.label != base_label) {
            base_addr = region.begin;
            base_label = region.label;
        }

        if (region.begin <= addr && addr < region.end) {
            result = {base_addr, region.label.empty() ? std::string("-") : basename_of(region.label)};
            base_cache_[addr] = result;
            return result;
        }
    }

    result = {addr, "-"};
    base_cache_[addr] = result;
    return result;
}

void QlArchUtils::disassembler(Qiling& ql, std::uint64_t address, std::uint32_t size) {

    const auto data = ql.mem().read(address, size);

    // the page-aligned address locates the containing image (utils.py: the
    // lru-cached base search, keyed on the aligned address)
    const auto [ba, name] = get_base_and_name(ql.mem().align(address));

    const int anibbles = ql.arch().bits() / 4;
    std::size_t pos = 0;

    for (const auto& insn : ql.arch().disassembler().disasm(std::string_view(reinterpret_cast<const char*>(data.data()), data.size()), address)) {
        const auto offset = insn.address - ba;
        char line[256];
        std::snprintf(line, sizeof(line), "%0*llx [%-20s + %#8llx]  %-22s %-16s %s",
                      anibbles, static_cast<unsigned long long>(insn.address),
                      name.c_str(), static_cast<unsigned long long>(offset),
                      hex_bytes(data, pos, insn.size).c_str(),
                      insn.mnemonic.c_str(), insn.op_str.c_str());
        ql.log().info(line);
        pos += insn.size;
    }

    if (ql.verbose() >= QL_VERBOSE::DUMP) {
        for (const auto& [reg, _] : ql.arch().regs().register_mapping()) {
            char line[64];
            std::snprintf(line, sizeof(line), "%-10s : %#llx", reg.c_str(),
                          static_cast<unsigned long long>(ql.arch().regs().read(reg)));
            (void)_;
            ql.log().info(line);
        }
    }
}

void QlArchUtils::setup_output(QL_VERBOSE verbosity) {
    // utils.py setup_output: drop the previous hooks, re-hook at >= DISASM;
    // the r2 extension branch has no C++ counterpart (python-only tooling)
    if (disasm_hook_) {
        disasm_hook_->remove();
        disasm_hook_.reset();
    }
    if (block_hook_) {
        block_hook_->remove();
        block_hook_.reset();
    }

    if (verbosity >= QL_VERBOSE::DISASM) {
        auto* self = this;
        disasm_hook_ = ql_.hook_code([self](std::uint64_t address, std::uint32_t size) -> int {
            self->disassembler(self->ql_, address, size);
            return 0;
        });

        if (verbosity >= QL_VERBOSE::DUMP) {
            auto* self2 = this;
            block_hook_ = ql_.hook_block([self2](std::uint64_t address, std::uint32_t) -> int {
                char line[64];
                std::snprintf(line, sizeof(line), "Tracing basic block at %#llx",
                              static_cast<unsigned long long>(address));
                self2->ql_.log().info(line);
                return 0;
            });
        }
    }
}

}  // namespace qiling
