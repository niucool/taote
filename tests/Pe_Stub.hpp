// tests/Pe_Stub.hpp - the stub-dll synthesizer for the fixture rootfs.
//
// Upstream analogue: none. The upstream rootfs ships real dlls (the
// user-populated rootfs checkout) and its loader consumes whatever PE files
// the user places there. The deviation is documented in STATUS.md: the
// port's fixture utility SYNTHESIZES minimal PE images (correct headers,
// section layout, and export tables; no real code bodies) that ride the
// IDENTICAL loader path as the real dlls (the LIEF parse -> the section
// map -> the export walk -> the import_symbols_ keying -> the hook_winapi
// dispatch), making the sys_dlls loop deterministic without depending on
// the host's real dll internals.
#ifndef QILING_TESTS_PE_STUB_HPP
#define QILING_TESTS_PE_STUB_HPP

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

#include <LIEF/PE/enums.hpp>
#include <LIEF/PE.hpp>

namespace qiling {
namespace testing {

// builds a minimal x64 PE dll at {rootfs}/Windows/System32/{dll_name}
// carrying one named export per entry in `exports` (each export's cell is a
// single `ret` stub). The image entry point stays 0 so the loader's DllMain
// drive skips it (the entry-section gate). Returns the written path.
inline std::filesystem::path write_stub_dll(
    const std::filesystem::path& rootfs,
    const std::string& dll_name,
    const std::vector<std::string>& exports) {
  auto factory = LIEF::PE::Factory::create(LIEF::PE::PE_TYPE::PE32_PLUS);

  // one `ret` (0xC3) cell per export, 16 bytes each
  std::vector<std::uint8_t> code(exports.size() * 16, 0xC3);
  LIEF::PE::Section text(".text");
  text.content(code);
  text.virtual_size(static_cast<std::uint32_t>(code.size()));
  factory->add_section(text);

  auto bin = factory->get();

  // the export cells ride the .text section's assigned virtual address
  std::uint32_t text_rva = 0;
  for (const auto& sec : bin->sections()) {
    if (sec.name() == ".text") {
      text_rva = sec.virtual_address();
    }
  }

  std::vector<LIEF::PE::ExportEntry> entries;
  for (std::size_t i = 0; i < exports.size(); ++i) {
    entries.emplace_back(exports[i], text_rva + static_cast<std::uint32_t>(i * 16));
  }
  if (!entries.empty()) {
    bin->set_export(LIEF::PE::Export(dll_name, entries));
  }

  LIEF::PE::Builder::config_t cfg;
  cfg.exports = true;
  cfg.resources = false;
  cfg.relocations = false;
  cfg.load_configuration = false;
  cfg.tls = false;
  cfg.overlay = false;
  cfg.debug = false;
  cfg.dos_stub = false;
  LIEF::PE::Builder builder(*bin, cfg);
  builder.build();

  const auto dir = rootfs / "Windows" / "System32";
  std::filesystem::create_directories(dir);
  const auto path = dir / dll_name;
  std::ofstream out(path, std::ios::binary);
  const auto& bytes = builder.get_build();
  out.write(reinterpret_cast<const char*>(bytes.data()),
            static_cast<std::streamsize>(bytes.size()));
  return path;
}

}  // namespace testing
}  // namespace qiling

#endif  // QILING_TESTS_PE_STUB_HPP
