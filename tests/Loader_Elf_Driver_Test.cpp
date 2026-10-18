// Loader_Elf_Driver suite — the ET_REL kernel-module path (elf.py
// load_driver/lkm_get_init/lkm_dynlinker + os/linux/kernel_api).
#include <gtest/gtest.h>

#include <cstdint>
#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

#include "qiling/core.hpp"
#include "qiling/os/os.hpp"
#include "qiling/os/posix/posix.hpp"
#include "qiling/loader/elf.hpp"

using namespace qiling;


namespace {

std::filesystem::path ensure_rootfs() {
    static bool cleaned = false;
    const auto base = std::filesystem::temp_directory_path() / "ql_elf_driver_rootfs";
    if (!cleaned) {
        std::filesystem::remove_all(base);
        cleaned = true;
    }
    std::filesystem::create_directories(base);
    return base;
}

constexpr std::uint64_t LOADBASE = 0x8000000;       // elf.py run(): the ET_REL loadbase
constexpr std::uint64_t API_HOOK_MEM = 0x1000000;   // elf.py API_HOOK_MEM
constexpr std::uint64_t SYSCALL_MEM = 0x1001000;    // API_HOOK_MEM + 0x1000

// the ET_REL fixture: init_module calls sys_write (the builtin stub) and then
// sys_exit_group (the user override stops the emulation with the exit code)
struct RelFixture {
    std::vector<std::uint8_t> blob;

    // builds the object: [ehdr][.text][.rela.text][.symtab][.strtab][.shstrtab][shdrs]
    static RelFixture build() {
        // ---- the .text ----
        //  +0   bf 01 00 00 00     mov edi, 1
        //  +5   be <imm32>         mov esi, <msg addr>
        //  +10  ba 0d 00 00 00     mov edx, 13
        //  +15  b8 <imm32>         mov eax, <sys_write>   (R_X86_64_32 at +16)
        //  +20  ff d0              call rax
        //  +22  b8 <imm32>         mov eax, <sys_exit_group> (R_X86_64_32 at +23)
        //  +27  ff d0              call rax
        //  +29  00                 (padding; the string follows)
        constexpr std::uint64_t text_off = 64;
        constexpr std::uint64_t msg_off = text_off + 30;
        const std::uint64_t msg_addr = LOADBASE + msg_off;
        const std::uint32_t msg_addr32 = static_cast<std::uint32_t>(msg_addr);

        const std::vector<std::uint8_t> text = {
            0xBF, 0x01, 0x00, 0x00, 0x00,  // mov edi, 1
            0xBE, static_cast<std::uint8_t>(msg_addr32), static_cast<std::uint8_t>(msg_addr32 >> 8),
            static_cast<std::uint8_t>(msg_addr32 >> 16), static_cast<std::uint8_t>(msg_addr32 >> 24),
            0xBA, 0x0D, 0x00, 0x00, 0x00,  // mov edx, 13
            0xB8, 0x00, 0x00, 0x00, 0x00,  // mov eax, imm32 (reloc at +16)
            0xFF, 0xD0,                    // call rax
            0xB8, 0x00, 0x00, 0x00, 0x00,  // mov eax, imm32 (reloc at +23)
            0xFF, 0xD0,                    // call rax
            0x00,                          // the NUL the string sits behind
            'H', 'e', 'l', 'l', 'o', ',', ' ', 'Q', 'i', 'l', 'i', 'n', 'g', 0x00,
        };

        // ---- the .strtab ----
        const std::string strtab = std::string("\0init_module\0sys_write\0sys_exit_group\0", 38);
        constexpr std::size_t sym_init_module = 1;
        constexpr std::size_t sym_sys_write = 13;
        constexpr std::size_t sym_sys_exit_group = 23;

        // ---- the .symtab (24-byte entries) ----
        auto sym = [](std::uint32_t name, std::uint8_t info, std::uint16_t shndx, std::uint64_t value) {
            std::vector<std::uint8_t> e(24, 0);
            for (int i = 0; i < 4; ++i) {
                e[i] = static_cast<std::uint8_t>(name >> (8 * i));
            }
            e[4] = info;
            e[6] = static_cast<std::uint8_t>(shndx);
            e[7] = static_cast<std::uint8_t>(shndx >> 8);
            for (int i = 0; i < 8; ++i) {
                e[8 + i] = static_cast<std::uint8_t>(value >> (8 * i));
            }
            return e;
        };
        std::vector<std::uint8_t> symtab;
        const auto append = [&symtab](const std::vector<std::uint8_t>& e) {
            symtab.insert(symtab.end(), e.begin(), e.end());
        };
        append(sym(0, 0, 0, 0));                                            // [0] the null symbol
        append(sym(sym_init_module, 0x12, 1, 0));                           // GLOBAL FUNC in .text
        append(sym(sym_sys_write, 0x10, 0, 0));                             // GLOBAL NOTYPE UNDEF
        append(sym(sym_sys_exit_group, 0x10, 0, 0));                        // GLOBAL NOTYPE UNDEF

        // ---- the .rela.text (24-byte entries: r_offset, r_info, r_addend) ----
        auto rela = [](std::uint64_t off, std::uint32_t symidx, std::uint32_t type, std::int64_t addend) {
            std::vector<std::uint8_t> e(24, 0);
            for (int i = 0; i < 8; ++i) {
                e[i] = static_cast<std::uint8_t>(off >> (8 * i));
            }
            const std::uint64_t info = (static_cast<std::uint64_t>(symidx) << 32) | type;
            for (int i = 0; i < 8; ++i) {
                e[8 + i] = static_cast<std::uint8_t>(info >> (8 * i));
            }
            for (int i = 0; i < 8; ++i) {
                e[16 + i] = static_cast<std::uint8_t>(static_cast<std::uint64_t>(addend) >> (8 * i));
            }
            return e;
        };
        std::vector<std::uint8_t> rela_text;
        const auto append_rel = [&rela_text](const std::vector<std::uint8_t>& e) {
            rela_text.insert(rela_text.end(), e.begin(), e.end());
        };
        append_rel(rela(16, 2, 10, 0));  // R_X86_64_32 against sys_write
        append_rel(rela(23, 3, 10, 0));  // R_X86_64_32 against sys_exit_group

        // ---- the .shstrtab ----
        const std::string shstrtab = std::string("\0.text\0.rela.text\0.symtab\0.strtab\0.shstrtab\0", 45);
        constexpr std::uint32_t nm_text = 1;
        constexpr std::uint32_t nm_rela = 7;
        constexpr std::uint32_t nm_symtab = 18;
        constexpr std::uint32_t nm_strtab = 26;
        constexpr std::uint32_t nm_shstrtab = 34;

        // ---- the layout ----
        std::size_t off = text_off + text.size();
        const auto align8 = [&off]() {
            off = (off + 7) & ~std::size_t{7};
            return off;
        };
        const std::size_t rela_off = align8();
        off += rela_text.size();
        const std::size_t symtab_off = align8();
        off += symtab.size();
        const std::size_t strtab_off = align8();
        off += strtab.size();
        const std::size_t shstrtab_off = align8();
        off += shstrtab.size();
        const std::size_t shdrs_off = align8();
        const std::uint32_t shnum = 6;

        RelFixture f;
        f.blob.assign(shdrs_off + shnum * 64, 0);

        auto put = [&](std::size_t at, const std::uint8_t* data, std::size_t len) {
            for (std::size_t i = 0; i < len; ++i) {
                f.blob[at + i] = data[i];
            }
        };
        put(text_off, text.data(), text.size());
        put(rela_off, rela_text.data(), rela_text.size());
        put(symtab_off, symtab.data(), symtab.size());
        put(strtab_off, reinterpret_cast<const std::uint8_t*>(strtab.data()), strtab.size());
        put(shstrtab_off, reinterpret_cast<const std::uint8_t*>(shstrtab.data()), shstrtab.size());

        // ---- the ehdr ----
        f.blob[0] = 0x7f;
        f.blob[1] = 'E';
        f.blob[2] = 'L';
        f.blob[3] = 'F';
        f.blob[4] = 2;   // ELFCLASS64
        f.blob[5] = 1;   // ELFDATA2LSB
        f.blob[6] = 1;   // EV_CURRENT
        f.blob[16] = 1;  // ET_REL
        f.blob[18] = 62; // EM_X86_64
        f.blob[20] = 1;  // e_version
        // e_entry/e_phoff zero; e_shoff
        for (int i = 0; i < 8; ++i) {
            f.blob[40 + i] = static_cast<std::uint8_t>(shdrs_off >> (8 * i));
        }
        f.blob[52] = 64;         // e_ehsize
        f.blob[58] = 64;         // e_shentsize
        f.blob[60] = shnum;      // e_shnum
        f.blob[62] = 5;          // e_shstrndx

        // ---- the section headers ----
        auto shdr = [&](std::size_t idx, std::uint32_t name, std::uint32_t type, std::uint64_t flags,
                        std::uint64_t offset, std::uint64_t size, std::uint32_t link, std::uint32_t info,
                        std::uint64_t entsize) {
            const std::size_t at = shdrs_off + idx * 64;
            auto w32 = [&](std::size_t at2, std::uint32_t v) {
                for (int i = 0; i < 4; ++i) {
                    f.blob[at2 + i] = static_cast<std::uint8_t>(v >> (8 * i));
                }
            };
            auto w64 = [&](std::size_t at2, std::uint64_t v) {
                for (int i = 0; i < 8; ++i) {
                    f.blob[at2 + i] = static_cast<std::uint8_t>(v >> (8 * i));
                }
            };
            w32(at + 0, name);
            w32(at + 4, type);
            w64(at + 8, flags);
            w64(at + 16, 0);  // sh_addr
            w64(at + 24, offset);
            w64(at + 32, size);
            w32(at + 40, link);
            w32(at + 44, info);
            w64(at + 48, 1);  // sh_addralign
            w64(at + 56, entsize);
        };
        shdr(0, 0, 0, 0, 0, 0, 0, 0, 0);
        shdr(1, nm_text, 1 /*PROGBITS*/, 0x6 /*ALLOC|EXECINSTR*/, text_off, text.size(), 0, 0, 0);
        shdr(2, nm_rela, 4 /*RELA*/, 0x40 /*INFO_LINK*/, rela_off, rela_text.size(), 3 /*symtab*/, 1 /*.text*/, 24);
        shdr(3, nm_symtab, 2 /*SYMTAB*/, 0, symtab_off, symtab.size(), 4 /*strtab*/, 1 /*first global*/, 24);
        shdr(4, nm_strtab, 3 /*STRTAB*/, 0, strtab_off, strtab.size(), 0, 0, 0);
        shdr(5, nm_shstrtab, 3 /*STRTAB*/, 0, shstrtab_off, shstrtab.size(), 0, 0, 0);

        return f;
    }
};

void write_fixture(const std::filesystem::path& path, const std::vector<std::uint8_t>& bytes) {
    std::ofstream out(path, std::ios::binary);
    out.write(reinterpret_cast<const char*>(bytes.data()), static_cast<std::streamsize>(bytes.size()));
}

}  // namespace

TEST(LoaderElfDriver, LkmLoadsAndWiresHooks) {
    const auto rootfs = ensure_rootfs();
    const auto fixture = RelFixture::build();
    const auto path = rootfs / "lkm.ko";
    write_fixture(path, fixture.blob);

    QilingOptions options;
    options.argv = {path.string()};
    options.rootfs = rootfs.string();
    options.ostype = QL_OS::LINUX;
    options.archtype = QL_ARCH::X8664;

    Qiling ql{options};

    const auto& loader = static_cast<const loader::QlLoaderELF&>(ql.loader());

    // the entry point is init_module at loadbase + its file position
    EXPECT_EQ(ql.os().entry_point(), LOADBASE + 64);

    // the external sys_* symbols got api hook slots (aligned, in encounter
    // order), and the builtin read/write/open stubs follow them
    const auto* write_hook = loader.import_symbols_at(API_HOOK_MEM + 0);
    ASSERT_NE(write_hook, nullptr);
    EXPECT_EQ(write_hook->name, "sys_write");
    const auto* exit_hook = loader.import_symbols_at(API_HOOK_MEM + 8);
    ASSERT_NE(exit_hook, nullptr);
    EXPECT_EQ(exit_hook->name, "sys_exit_group");
    const auto* read_stub = loader.import_symbols_at(API_HOOK_MEM + 16);
    ASSERT_NE(read_stub, nullptr);
    EXPECT_EQ(read_stub->name, "sys_read");

    // the syscall table: slots 0/1/2 point at the api stubs; the sys_* loop
    // filled the exit_group slot with its hook address
    EXPECT_EQ(ql.mem().read_ptr(SYSCALL_MEM + 0 * 8), API_HOOK_MEM + 16);
    EXPECT_EQ(ql.mem().read_ptr(SYSCALL_MEM + 1 * 8), API_HOOK_MEM + 24);
    EXPECT_EQ(ql.mem().read_ptr(SYSCALL_MEM + 2 * 8), API_HOOK_MEM + 32);
    EXPECT_EQ(ql.mem().read_ptr(SYSCALL_MEM + 231 * 8), API_HOOK_MEM + 8);

    // the module image registered
    bool imaged = false;
    for (const auto& image : loader.images) {
        if (image.path.find("lkm.ko") != std::string::npos && image.base == LOADBASE) {
            imaged = true;
        }
    }
    EXPECT_TRUE(imaged);
}

TEST(LoaderElfDriver, LkmRunsThroughKernelApiHooks) {
    const auto rootfs = ensure_rootfs();
    const auto fixture = RelFixture::build();
    const auto path = rootfs / "lkm.ko";
    write_fixture(path, fixture.blob);

    QilingOptions options;
    options.argv = {path.string()};
    options.rootfs = rootfs.string();
    options.ostype = QL_OS::LINUX;
    options.archtype = QL_ARCH::X8664;

    Qiling ql{options};

    // the user override for sys_exit_group (hook.py: the raw callable shape)
    ql.os().set_api("sys_exit_group", [](Qiling& q, std::uint64_t, const std::string&) {
        q.os().set_exit_code(42);
        q.stop();
    });

    ql.run();
    EXPECT_EQ(ql.os().exit_code(), 42);
}
