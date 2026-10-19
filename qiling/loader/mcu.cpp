// The implementation half of loader/mcu.hpp.
#include "qiling/loader/mcu.hpp"

#include "qiling/arch/arm.hpp"
#include "qiling/core.hpp"
#include "qiling/hw/hw.hpp"
#include "qiling/os/memory.hpp"

#include <algorithm>
#include <fstream>

namespace qiling {
namespace loader {
namespace {

std::vector<std::uint8_t> hex_to_bytes(const std::string& text) {
    // the hex pairs to bytes (the upstream bytes.fromhex)
    std::vector<std::uint8_t> out;
    out.reserve(text.size() / 2);
    for (std::size_t i = 0; i + 1 < text.size(); i += 2) {
        out.push_back(static_cast<std::uint8_t>(std::stoul(text.substr(i, 2), nullptr, 16)));
    }
    return out;
}

std::vector<std::string> split_env_record(const std::string& value) {
    std::vector<std::string> parts;
    std::string::size_type begin = 0;
    while (true) {
        const auto pos = value.find(';', begin);
        if (pos == std::string::npos) {
            parts.push_back(value.substr(begin));
            break;
        }
        parts.push_back(value.substr(begin, pos - begin));
        begin = pos + 1;
    }
    return parts;
}

}  // namespace

IhexParser::IhexParser(const std::string& path) {
    std::ifstream file(path);
    if (!file) {
        throw QlErrorBase("mcu loader: cannot open ihex file " + path);
    }

    std::string line;
    while (std::getline(file, line)) {
        if (!line.empty() && line.back() == '\r') {
            line.pop_back();
        }
        parse_line(line);
    }

    // the coalescing walk (mcu.py, verbatim: the contiguous runs merge, the
    // gaps split)
    std::uint64_t begin = 0;
    std::vector<std::uint8_t> stream;
    bool first = true;
    for (const auto& [addr, data] : mem_) {
        if (first || addr != begin + stream.size()) {
            if (!first) {
                segments.emplace_back(begin, std::move(stream));
            }
            begin = addr;
            stream = data;
            first = false;
        } else {
            stream.insert(stream.end(), data.begin(), data.end());
        }
    }
    if (!first) {
        segments.emplace_back(begin, std::move(stream));
    }
}

void IhexParser::parse_line(const std::string& line) {
    if (line.size() < 9) {
        return;
    }

    const std::string desc = line.substr(7, 2);
    const int size = static_cast<int>(std::stoul(line.substr(1, 2), nullptr, 16));

    const auto addr = hex_to_bytes(line.substr(3, 4));
    const auto data = hex_to_bytes(line.substr(9, static_cast<std::size_t>(size) * 2));

    if (desc == "00") {  // Data
        const std::uint64_t offset = (static_cast<std::uint64_t>(addr[0]) << 8) | addr[1];
        mem_.emplace_back(base_ + offset, std::move(data));
    } else if (desc == "02") {  // Extended Segment Address
        base_ = ((static_cast<std::uint64_t>(data[0]) << 8) | data[1]) * 0x10;
    } else if (desc == "04") {  // Extended Linear Address
        base_ = ((static_cast<std::uint64_t>(data[0]) << 8) | data[1]) * 0x10000;
    }
}

QlLoaderMCU::QlLoaderMCU(Qiling* ql) : QlLoader(ql) {
    entry_point = 0;
    load_address = 0;
    path_ = ql_->path();
    filetype_ = guess_filetype();

    if (filetype_ == FileType::ELF) {
        // the upstream rides pyelftools' ELFFile; the elf branch lands with
        // the board-profile slice
        ihex_ = nullptr;
    } else if (filetype_ == FileType::BIN) {
        // mcu.py: self.map_address = self.argv[1]
        const auto& args = ql_->argv();
        map_address_ = args.size() > 1 ? std::stoull(args[1], nullptr, 0) : 0;
    } else {  // hex
        ihex_ = std::make_unique<IhexParser>(path_);
    }
}

QlLoaderMCU::FileType QlLoaderMCU::guess_filetype() const {
    const auto ends_with = [](const std::string& text, const std::string& suffix) {
        return text.size() >= suffix.size() && text.compare(text.size() - suffix.size(), suffix.size(), suffix) == 0;
    };
    if (ends_with(path_, ".elf")) {
        return FileType::ELF;
    }
    if (ends_with(path_, ".bin")) {
        return FileType::BIN;
    }
    if (ends_with(path_, ".hex")) {
        return FileType::HEX;
    }
    return FileType::ELF;
}

void QlLoaderMCU::load_env() {
    // the upstream load_env walk over the env items; the port's env carries
    // the ';' encoded records "type;arg1;arg2" (the deviation documented in
    // the header)
    for (const auto& [name, value] : ql_->env()) {
        const auto parts = split_env_record(value);
        if (parts.empty()) {
            continue;
        }

        const auto& type = parts[0];
        const auto number = [](const std::string& text) {
            return std::stoull(text, nullptr, 0);
        };

        try {
            if (type == "memory" && parts.size() >= 3) {
                ql_->mem().map(number(parts[1]), number(parts[2]), UC_PROT_ALL, "[" + name + "]");
            } else if (type == "mmio" && parts.size() >= 3) {
                ql_->hw()->setup_mmio(number(parts[1]), number(parts[2]), name);
            } else if (type == "core" && parts.size() >= 3) {
                // the trailing "key=value" parts ride the kwargs map (the
                // upstream's env kwargs dicts)
                QlHwManager::PeripheralKwargs kwargs;
                for (std::size_t i = 3; i < parts.size(); ++i) {
                    const auto eq = parts[i].find('=');
                    if (eq != std::string::npos) {
                        kwargs[parts[i].substr(0, eq)] = number(parts[i].substr(eq + 1));
                    }
                }
                auto lower = name;
                std::transform(lower.begin(), lower.end(), lower.begin(), [](unsigned char c) {
                    return static_cast<char>(std::tolower(c));
                });
                ql_->hw()->create(lower, parts[1], number(parts[2]), kwargs);
            } else if (type == "peripheral" && parts.size() >= 3) {
                // the peripheral items ride the create walk (the port-side
                // fold-in of the upstream's load_all — the upstream load_env
                // ignores them with a debug log and the harnesses create the
                // peripherals explicitly); the upstream-missing struct names
                // degrade to null (the entity stays absent — the upstream's
                // "implementation not found" warn shape)
                QlHwManager::PeripheralKwargs kwargs;
                for (std::size_t i = 3; i < parts.size(); ++i) {
                    const auto eq = parts[i].find('=');
                    if (eq != std::string::npos) {
                        kwargs[parts[i].substr(0, eq)] = number(parts[i].substr(eq + 1));
                    }
                }
                auto lower = name;
                std::transform(lower.begin(), lower.end(), lower.begin(), [](unsigned char c) {
                    return static_cast<char>(std::tolower(c));
                });
                (void)ql_->hw()->create(lower, parts[1], number(parts[2]), kwargs);
            } else {
                // the unknown types log-and-ignore (the upstream debug walk)
            }
        } catch (const std::invalid_argument&) {
            throw QlErrorBase("mcu load_env: malformed env record for '" + name + "': " + value);
        }
    }
}

void QlLoaderMCU::reset() {
    if (filetype_ == FileType::HEX) {
        for (const auto& [begin, data] : ihex_->segments) {
            ql_->mem().write(begin, data);
        }
    } else if (filetype_ == FileType::BIN) {
        std::ifstream file(path_, std::ios::binary);
        if (!file) {
            throw QlErrorBase("mcu loader: cannot open bin file " + path_);
        }
        const std::vector<std::uint8_t> bytes((std::istreambuf_iterator<char>(file)), std::istreambuf_iterator<char>());
        ql_->mem().write(map_address_, bytes);
    } else {
        throw QlErrorNotImplemented("the mcu elf branch rides the board-profile slice");
    }

    auto& arm = dynamic_cast<QlArchCORTEX_M&>(ql_->arch());
    arm.init_context();
    entry_point = arm.regs().read("pc");
}

void QlLoaderMCU::run() {
    // mcu.py run(): load_profile (the env arrives via the options — the
    // port's profile/env update walks ride the board-profile slice),
    // load_env, the intr hook, reset
    load_env();

    auto& arch = dynamic_cast<QlArchCORTEX_M&>(ql_->arch());
    // the handle rides the loader's lifetime (the discarded HookRet would
    // RAII-unregister the hook at the temporary's destruction)
    intr_hook_ = std::make_unique<HookRet>(ql_->hook_intr([&arch](std::uint32_t intno) {
        arch.unicorn_exception_handler(static_cast<int>(intno));
        return 0;
    }));

    reset();
}

}  // namespace loader
}  // namespace qiling
