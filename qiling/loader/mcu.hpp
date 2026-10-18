// Ported from qiling/loader/mcu.py (IhexParser + QlLoaderMCU). The loader
// guesses the file type by the suffix, walks the intel-hex records (the type
// 00 data / 02 extended-segment / 04 extended-linear, the coalescing walk
// verbatim) or the raw bin at the argv[1] map address, and resets through the
// memory writes + the arch init_context (the MSP/PC from the vector table).
//
// Deviations (documented):
// - the env items ride the port's string-map env with the ';' encoded records
//   "type;arg1;arg2" (the upstream walks the dict-of-dicts env): memory / mmio
//   / core as in mcu.py load_env; the peripheral-type items ride the explicit
//   create calls (the upstream load_all path).
// - the elf branch throws (the upstream rides pyelftools' PT_LOAD paddr walk;
//   it lands with the board-profile slice).
#pragma once

#ifndef QILING_LOADER_MCU_HPP
#define QILING_LOADER_MCU_HPP

#include "qiling/loader/loader.hpp"
#include "qiling/core_hooks.hpp"

#include <memory>
#include <string>
#include <utility>
#include <vector>

namespace qiling {

class Qiling;

namespace loader {

// mcu.py IhexParser
class IhexParser {
public:
    explicit IhexParser(const std::string& path);

    // the coalesced (begin, data) segments
    std::vector<std::pair<std::uint64_t, std::vector<std::uint8_t>>> segments;

private:
    void parse_line(const std::string& line);

    std::vector<std::pair<std::uint64_t, std::vector<std::uint8_t>>> mem_;
    std::uint64_t base_ = 0;
};

// mcu.py QlLoaderMCU
class QlLoaderMCU final : public QlLoader {
public:
    explicit QlLoaderMCU(Qiling* ql);

    void run() override;

private:
    enum class FileType { ELF, BIN, HEX };

    FileType guess_filetype() const;
    void reset();
    void load_env();

    Qiling& ql() noexcept { return *ql_; }

    FileType filetype_ = FileType::ELF;
    std::string path_;
    std::uint64_t map_address_ = 0;  // the bin branch (the argv[1] string)
    std::unique_ptr<IhexParser> ihex_;

    // the intr-hook handle held for the loader's lifetime (the discarded
    // HookRet RAII-unregisters immediately — the upstream discards the
    // returned hook object freely since the python wrapper does not have the
    // destroying-dtor semantics)
    std::unique_ptr<HookRet> intr_hook_; 
};

}  // namespace loader
}  // namespace qiling

#endif  // QILING_LOADER_MCU_HPP
