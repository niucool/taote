// The SEH dispatch implementation — see seh.hpp for the design overview and
// the pegasus reference (src/windows/winemu.cpp dispatch_seh /
// _dispatch_seh_x86 / _continue_seh_x86).
#include <cstdio>
#include <cstdlib>
#include <unicorn/unicorn.h>

#include <cstring>
#include <vector>

#include "qiling/core.hpp"
#include "qiling/os/memory.hpp"
#include "qiling/os/windows/seh.hpp"

#include "qiling/os/windows/ntdefs.hpp"
#include "qiling/os/windows/windows.hpp"
#include "qiling/loader/pe.hpp"

#include <algorithm>
#include <cctype>
#include <map>
#include <filesystem>

namespace qiling {
namespace os {
namespace windows {

namespace {

// the x86 CONTEXT field offsets (pegasus deffs CONTEXT<4>):
//   0x000 ContextFlags, 0x004..0x018 Dr0-Dr7, 0x01c FloatSave (112),
//   0x08c SegGs, 0x090 SegFs, 0x094 SegEs, 0x098 SegDs,
//   0x09c Edi, 0x0a0 Esi, 0x0a4 Ebx, 0x0a8 Edx, 0x0ac Ecx, 0x0b0 Eax,
//   0x0b4 Ebp, 0x0b8 Eip, 0x0bc SegCs, 0x0c0 EFlags, 0x0c4 Esp, 0x0c8 SegSs,
//   0x0cc ExtendedRegisters (512) — the fixed part ends at 0xcc
constexpr std::size_t kCtxContextFlags = 0x0;
constexpr std::size_t kCtxSegGs = 0x8c;
constexpr std::size_t kCtxSegFs = 0x90;
constexpr std::size_t kCtxSegEs = 0x94;
constexpr std::size_t kCtxSegDs = 0x98;
constexpr std::size_t kCtxEdi = 0x9c;
constexpr std::size_t kCtxEsi = 0xa0;
constexpr std::size_t kCtxEbx = 0xa4;
constexpr std::size_t kCtxEdx = 0xa8;
constexpr std::size_t kCtxEcx = 0xac;
constexpr std::size_t kCtxEax = 0xb0;
constexpr std::size_t kCtxEbp = 0xb4;
constexpr std::size_t kCtxEip = 0xb8;
constexpr std::size_t kCtxSegCs = 0xbc;
constexpr std::size_t kCtxEFlags = 0xc0;
constexpr std::size_t kCtxEsp = 0xc4;
constexpr std::size_t kCtxSegSs = 0xc8;

// CONTEXT_FULL: the debug registers + the floating point + the segments +
// the integer registers (winnt.h)
constexpr std::uint32_t kContextFull = 0x10007;

void put_u32(std::vector<std::uint8_t>& image, std::size_t off, std::uint32_t v) {
    image[off + 0] = static_cast<std::uint8_t>(v);
    image[off + 1] = static_cast<std::uint8_t>(v >> 8);
    image[off + 2] = static_cast<std::uint8_t>(v >> 16);
    image[off + 3] = static_cast<std::uint8_t>(v >> 24);
}

std::uint32_t get_u32(const std::vector<std::uint8_t>& image, std::size_t off) {
    return static_cast<std::uint32_t>(image[off]) |
           (static_cast<std::uint32_t>(image[off + 1]) << 8) |
           (static_cast<std::uint32_t>(image[off + 2]) << 16) |
           (static_cast<std::uint32_t>(image[off + 3]) << 24);
}

}  // namespace

// map the sentinel page: the staged return address for the guest SEH
// handlers / filters. The page is deliberately NON-executable so the
// handler's `ret` to it faults (UC_MEM_FETCH_PROT) and the dispatcher
// continues the walk — and mapped (rw) so the address never gets reused by
// the guest allocations
bool QlOsWindows::seh_map_sentinel() {
    if (seh_sentinel_ != 0) {
        return true;
    }
    try {
        const auto base = ql_->mem().find_free_space(0x1000, 0x70000000ull, 0x78000000ull, 0x1000);
        // rw without exec: the fetch at the sentinel faults PROT
        ql_->mem().map(base, 0x1000, UC_PROT_READ | UC_PROT_WRITE, "[SEH sentinel]");
        seh_sentinel_ = base;
        return true;
    } catch (...) {
        return false;
    }
}

bool QlOsWindows::seh_fault_trampoline(uc_engine*, uc_mem_type access, std::uint64_t address,
                                        std::uint32_t /*size*/, std::int64_t /*value*/, void* user_data) {
    auto* self = static_cast<QlOsWindows*>(user_data);
    // this trampoline is a C boundary (unicorn calls it directly): a C++
    // exception escaping here reaches std::terminate, i.e. a host abort on a
    // guest fault - never acceptable. The failure becomes the run's entry-point
    // error and the fault goes on to surface normally.
    try {
        return self->seh_on_fault(static_cast<int>(access), address);
    } catch (const std::exception& e) {
        self->on_emulation_error(e.what());
        return false;
    } catch (...) {
        self->on_emulation_error("SEH dispatch failed");
        return false;
    }
}

// the raw invalid-memory hook: the first-chance SEH dispatch. Returns false
// (the fault surfaces to uc_emu_start's error) whenever the retarget is
// armed — the run loop in QlOsWindows::run then restarts the emulation at
// the staged target. Returning false also lets the later-registered hooks
// (the ql-layer mem hooks) still observe the fault (unicorn continues the
// hook list on a false return).
// Does the rootfs carry a *real* x86 CRT unwinder? `_except_handler4_common` is
// the MSVC CRT's SEH entry point; when a loaded image exports it with real code
// (rather than the synthesized stub rootfs's `ret` cell) the guest can walk its
// own exception frames, and it must be allowed to. Upstream has no synthetic SEH
// at all — no sentinel, no dispatch — it simply lets that code run, which is why
// it passes the x86 fixtures on a real rootfs.
//
// Keeping the pegasus-style dispatch armed in that situation makes the emulator
// drive a walk the guest is already driving: the dispatch stages its sentinel
// page as the return address for the guest's filters/handlers, the guest returns
// into it, `seh_continue` finds its own frames exhausted and the run dies on the
// fetch from 0x70000000 (GandCrab and both x86 C++ fixtures ended exactly there).
bool QlOsWindows::has_real_seh_unwinder() {
    // only the *positive* answer is cached: the probe runs during load too, when
    // the system DLLs are not mapped yet, and caching that "no" would pin the
    // dispatch on for the whole run (measured: the probe answered 0 while
    // ucrtbase's _except_handler4_common sat at a real 0x104c6ce0)
    if (real_seh_unwinder_.value_or(false)) {
        return true;
    }
    const auto lower_ascii = [](std::string v) {
        std::transform(v.begin(), v.end(), v.begin(),
                       [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
        return v;
    };
    bool real = false;
    try {
        const auto& pe_loader = static_cast<const loader::QlLoaderPE&>(ql_->loader());

        // The import tables are keyed by the *imported* name, which is what the
        // image's .idata asks for — not by the module the redirect ladder
        // resolved it to. A guest that imports the api-ms-win-crt-* groups
        // (every VC++ fixture does) therefore has no "ucrtbase.dll" key even
        // though the loader mapped ucrtbase as the redirect target: measured on
        // the Windows 11 x86 tree, the keys were exactly
        // api-ms-win-crt-{heap,locale,math,runtime,stdio}-l1-1-0.dll,
        // kernel32.dll, msvcp140.dll and vcruntime140.dll. So the symbol is
        // resolved through every table and attributed by *image ownership*.
        const auto tables = pe_loader.import_address_table_keys();
        for (const auto& image : pe_loader.images) {
            const auto name = lower_ascii(std::filesystem::path(image.path).filename().string());
            const bool crt_image = name.rfind("ucrtbase", 0) == 0 || name == "msvcrt.dll" ||
                                   name.rfind("api-ms-win-crt-", 0) == 0;
            if (!crt_image) {
                continue;
            }
            for (const auto& key : tables) {
                const auto* iat = pe_loader.import_address_table_at(key);
                if (iat == nullptr) {
                    continue;
                }
                const auto addr = iat->lookup("_except_handler4_common");
                if (addr == 0 || addr < image.base || addr >= image.end) {
                    continue;  // this table's answer is not code in a CRT image
                }
                std::vector<std::uint8_t> prologue;
                try {
                    prologue = ql_->mem().read(addr, 3);
                } catch (...) {
                    continue;
                }
                const bool synthesized_cell =
                    prologue.size() >= 1 &&
                    (prologue[0] == 0xC3 ||
                     (prologue.size() >= 3 && prologue[0] == 0x31 && prologue[1] == 0xC0 && prologue[2] == 0xC3));
                if (!synthesized_cell) {
                    real = true;
                    break;
                }
            }
            if (real) {
                break;
            }
        }
    } catch (...) {
        real = false;
    }
    if (real) {
        real_seh_unwinder_ = true;
    }
    return real;
}

// "is the CRT a genuine vendor binary?" — by image size, which is what actually
// distinguishes the two cases: the synthesized stub images are a few pages
// (measured 8-12K for ntdll/ucrtbase/vcruntime140 on a stub rootfs) while the
// real ones are hundreds of kilobytes (ucrtbase 1.1M, msvcrt 826K in the
// Windows 11 trees). No export probe here: x64 exports no
// _except_handler4_common, so an export-based test is x86-only by accident.
bool QlOsWindows::has_real_crt() {
    try {
        const auto& pe_loader = static_cast<const loader::QlLoaderPE&>(ql_->loader());
        for (const auto& image : pe_loader.images) {
            auto name = std::filesystem::path(image.path).filename().string();
            std::transform(name.begin(), name.end(), name.begin(),
                           [](unsigned char c) { return static_cast<char>(std::tolower(c)); });
            if (name.rfind("ucrtbase", 0) != 0 && name != "msvcrt.dll") {
                continue;
            }
            if (image.end > image.base && image.end - image.base > 0x10000) {
                return true;
            }
        }
    } catch (...) {
        return false;
    }
    return false;
}

bool QlOsWindows::seh_on_fault(int access, std::uint64_t address) {
    if (std::getenv("TAOTE_SEHDBG") != nullptr) {
        std::fprintf(stderr, "[fault] access=%d addr=0x%llx pc=0x%llx\n", access,
                     static_cast<unsigned long long>(address),
                     static_cast<unsigned long long>(ql_->arch().regs().arch_pc()));
    }
    if (bits_ != 32 || !seh_dispatch_enabled_) {
        return false;  // the dispatch is not armed (or switched off)
    }

    // A real CRT does NOT stand the dispatch down. The dispatch's job is to
    // *deliver* the fault — build the EXCEPTION_RECORD/CONTEXT and call the frame
    // handler in fs:[0] — and with a real CRT that handler is the guest's own
    // __except_handler4 (which calls the real _except_handler4_common). What must
    // not happen is taote decoding the scope table itself, and that is already
    // handled: the _except_handler4_common hook stands down when the rootfs has
    // real code (see the hook), so seh_frames_ stays empty and seh_continue only
    // applies what the guest's handler decided.
    //
    // Delivering it is required, not optional: al-khaser's static CRT takes a
    // genuine access violation (a NULL per-thread locale pointer) that the
    // sample's own handler catches and recovers from — measured at pc 0x411cd5
    // (`cmp dword ptr [eax + 0xa8], 0` with eax = 0). With the dispatch standing
    // down that fault surfaced as an emulation error and the sample never reached
    // upstream's stop address 0x4016ae.

    // Only the *program's* faults dispatch. The loader drives every DllMain from
    // `emu_start` while the emulation state is not STARTED, and a fault in one of
    // those drives is not the program's exception: treating it as one stages the
    // sentinel page as a guest return address (measured: fault 0xc3c3c3c7 at
    // pc 0x40104a during load, real_unwinder still 0 because the system DLLs are
    // not mapped yet), and the program later returns into it — the
    // UC_ERR_FETCH_PROT at 0x70000000 that the x86 C++ fixtures and GandCrab all
    // ended on.
    if (!loader_done()) {
        return false;
    }

    // the staged-return page is created on demand, and only past both gates:
    // with a real unwinder (or during load) the synthetic dispatch never runs,
    // so its page must never exist either
    if (seh_sentinel_ == 0 && !seh_map_sentinel()) {
        return false;
    }

    // the sentinel fetch: a guest SEH handler / filter returned — continue
    // the dispatch walk.
    //
    // The address is not always the page base: a real CRT handler that returns
    // normally arrives as a fetch at 0x70000001 (unicorn reports the byte after
    // the one it managed to fetch), so the whole page counts — but only on the
    // real-CRT path (no synthetic frame recorded). With a synthetic walk in
    // progress the exact address is the contract, because there the sentinel is
    // reached by taote's own staged `ret` and any other fetch is a genuine
    // guest fault (measured: matching the page turned a stub-mode run that ends
    // cleanly into an exhausted-walk error).
    const bool in_sentinel_page = seh_sentinel_ != 0 && address >= seh_sentinel_ &&
                                  address < seh_sentinel_ + 0x1000;
    if ((access == UC_MEM_FETCH_PROT || access == UC_MEM_FETCH_UNMAPPED) &&
        (address == seh_sentinel_ || (in_sentinel_page && seh_frames_.empty()))) {
        return seh_continue();
    }

    // only the data faults dispatch (a read/write against unmapped memory);
    // the fetch faults elsewhere stay on the existing failure path
    if (access != UC_MEM_WRITE_UNMAPPED && access != UC_MEM_READ_UNMAPPED) {
        return false;
    }

    return seh_dispatch(address, access == UC_MEM_WRITE_UNMAPPED ? 1u : 0u);
}

// iretq: unicorn raises UC_ERR_EXCEPTION for it (a privileged instruction in
// ring 3), and nothing catches that — no memory hook, no UC_HOOK_INTR. But the
// guest reaches it legitimately: ntdll's KiUserExceptionDispatcher ends by
// restoring the CONTEXT and executing iretq to enter the guest's __except
// block, which is how every x64 SEH fixture resumes. Measured on TestSoftSEH
// against the Windows 11 x64 tree: the whole dispatch ran (real
// __C_specific_handler, RtlVirtualUnwind, RtlLookupFunctionEntry) and died at
// iretq, ntdll+0x1245b0. The instruction's effect is a five-qword pop
// (rip, cs, rflags, rsp, ss) in long mode, so the trace hook performs it and
// restarts the run at the restored rip.
bool QlOsWindows::seh_check_iret(std::uint64_t pc) {
    if (bits_ != 64) {
        return false;  // the x86 path has its own dispatch
    }
    std::vector<std::uint8_t> code;
    try {
        code = ql_->mem().read(pc, 2);
    } catch (...) {
        return false;
    }
    if (code.empty()) {
        return false;
    }
    const bool iretq = code[0] == 0xCF || (code[0] == 0x48 && code.size() > 1 && code[1] == 0xCF);
    if (!iretq) {
        return false;
    }

    auto& regs = ql_->arch().regs();
    const auto sp = static_cast<std::uint64_t>(regs.arch_sp());
    std::uint64_t rip = 0;
    std::uint64_t flags = 0;
    std::uint64_t new_sp = 0;
    try {
        rip = static_cast<std::uint64_t>(ql_->mem().read_ptr(sp, 8));
        flags = static_cast<std::uint64_t>(ql_->mem().read_ptr(sp + 0x10, 8));
        new_sp = static_cast<std::uint64_t>(ql_->mem().read_ptr(sp + 0x18, 8));
    } catch (...) {
        return false;
    }
    regs.write("rsp", new_sp);
    regs.write("eflags", flags & 0x3f7fd7ull);  // the user-settable arithmetic bits
    regs.set_arch_pc(rip);
    return true;
}

// the div/idiv pre-check: the trace hook runs before every instruction, so a
// zero divisor can be turned into the guest exception unicorn would otherwise
// surface as an uncatchable UC_ERR_EXCEPTION
bool QlOsWindows::seh_check_cpu_exception(std::uint64_t pc) {
    if (bits_ != 32 || !seh_dispatch_enabled_ || seh_sentinel_ == 0 || seh_retarget_ != 0) {
        return false;
    }
    std::vector<std::uint8_t> code;
    try {
        code = ql_->mem().read(pc, 3);
    } catch (...) {
        return false;
    }
    if (code.size() < 2) {
        return false;
    }

    const auto op = code[0];
    if (op != 0xF6 && op != 0xF7) {  // the div/idiv group
        return false;
    }
    const auto modrm = code[1];
    if ((modrm & 0xC0) != 0xC0) {  // only the register forms are decoded
        return false;
    }
    const auto reg = (modrm >> 3) & 7;
    if (reg != 6 && reg != 7) {  // /6 = div, /7 = idiv
        return false;
    }

    // the operand register (the 8-bit forms alias the classic high bytes)
    static const char* k32[] = {"eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"};
    static const char* k8[] = {"al", "cl", "dl", "bl", "ah", "ch", "dh", "bh"};
    const auto& regs = ql_->arch().regs();
    const auto divisor = regs.read(op == 0xF6 ? k8[modrm & 7] : k32[modrm & 7]);
    const auto width = op == 0xF6 ? 8 : 32;
    if ((divisor & ((1ull << width) - 1)) != 0) {
        return false;
    }

    // STATUS_INTEGER_DIVIDE_BY_ZERO against the div instruction itself
    if (!seh_dispatch(pc, 0u, 0xC0000094u)) {
        return false;
    }
    ql_->emu_stop();
    return true;
}

void QlOsWindows::seh_intr_trampoline(uc_engine* /*uc*/, std::uint32_t intno, void* user_data) {
    auto* self = static_cast<QlOsWindows*>(user_data);
    try {
        (void)self->seh_on_interrupt(intno);
    } catch (const std::exception& e) {
        // same C-boundary rule as the fault trampoline
        self->on_emulation_error(e.what());
    } catch (...) {
        self->on_emulation_error("SEH interrupt dispatch failed");
    }
}

bool QlOsWindows::seh_on_interrupt(std::uint32_t intno) {
    if (std::getenv("TAOTE_SEHDBG") != nullptr) {
        auto& dbg_regs = ql_->arch().regs();
        std::fprintf(stderr, "[intr] intno=0x%x pc=0x%llx esi=0x%llx edx=0x%llx esp=0x%llx ebp=0x%llx ebx=0x%llx eax=0x%llx ecx=0x%llx edi=0x%llx\n", intno,
                     static_cast<unsigned long long>(dbg_regs.arch_pc()),
                     static_cast<unsigned long long>(dbg_regs.read("esi")),
                     static_cast<unsigned long long>(dbg_regs.read("edx")),
                     static_cast<unsigned long long>(dbg_regs.arch_sp()),
                     static_cast<unsigned long long>(dbg_regs.read("ebp")),
                     static_cast<unsigned long long>(dbg_regs.read("ebx")),
                     static_cast<unsigned long long>(dbg_regs.read("eax")),
                     static_cast<unsigned long long>(dbg_regs.read("ecx")),
                     static_cast<unsigned long long>(dbg_regs.read("edi")));
        if (intno == 0xd) {
            try {
                const auto esi = dbg_regs.read("esi");
                auto fp = ql_->mem().read(esi, 8);
                std::fprintf(stderr, "[intr]   [esi]=%02x %02x %02x %02x %02x %02x %02x %02x\n",
                             fp[0], fp[1], fp[2], fp[3], fp[4], fp[5], fp[6], fp[7]);
            } catch (...) {
                std::fprintf(stderr, "[intr]   [esi] unreadable\n");
            }
        }
    }
    if (bits_ != 32 || !seh_dispatch_enabled_ || seh_retarget_ != 0) {
        return false;
    }
    // map the sentinel on demand (the TF single-step trap can be the run's
    // first fault, before any memory fault has created the page)
    if (seh_sentinel_ == 0 && !seh_map_sentinel()) {
        return false;
    }
    // Map the hardware exception vector to its NT status, matching the
    // reference's intr_to_ntstatus (unpacker.cpp:66-79). #GP (13) and #PF (14)
    // are access violations, not illegal instructions — misclassifying them as
    // 0xC000001D leaves the guest SEH handler (which selects on the code)
    // un-consumed and escalates to a #DF double fault. Vectors outside the
    // table are software `int` probes (int 0x20/0x29/0x2d): ignore them and
    // let the instruction pass, as the reference does.
    static const std::map<std::uint32_t, std::uint32_t> kIntrToNt = {
        {0,  0xC0000094u}, // #DE  -> STATUS_INTEGER_DIVIDE_BY_ZERO
        {1,  0x80000004u}, // int1 -> STATUS_SINGLE_STEP
        {3,  0x80000003u}, // int3 -> STATUS_BREAKPOINT
        {5,  0xC000008Cu}, // #BR  -> STATUS_ARRAY_BOUNDS_EXCEEDED
        {6,  0xC000001Du}, // #UD  -> STATUS_ILLEGAL_INSTRUCTION
        {13, 0xC0000005u}, // #GP  -> STATUS_ACCESS_VIOLATION
        {14, 0xC0000005u}, // #PF  -> STATUS_ACCESS_VIOLATION
        {17, 0x80000002u}, // #AC  -> STATUS_DATATYPE_MISALIGNMENT
    };
    const auto it = kIntrToNt.find(intno);
    if (it == kIntrToNt.end()) {
        return true;
    }
    const auto code = it->second;
    const auto pc = ql_->arch().regs().arch_pc();
    if (std::getenv("TAOTE_SEHDBG") != nullptr) {
        try {
            const auto ch = ql_->mem().read_ptr(FS_SEGMENT_ADDR, 4);
            std::fprintf(stderr, "[intr]   chain=%08llx next=%08llx handler=%08llx\n",
                         static_cast<unsigned long long>(ch),
                         static_cast<unsigned long long>(ql_->mem().read_ptr(ch, 4)),
                         static_cast<unsigned long long>(ql_->mem().read_ptr(ch + 4, 4)));
        } catch (const std::exception& e) {
            std::fprintf(stderr, "[intr]   chain-read-fail: %s\n", e.what());
        }
    }
    if (!seh_dispatch(pc, 0u, code)) {
        return false;
    }
    // On real x86 the single-step trap CLEARS TF in the live EFLAGS before the
    // handler runs (the saved CONTEXT keeps TF=1 for NtContinue to restore).
    // Clearing it here (after the CONTEXT was built) keeps the handler from
    // re-trapping on its own instructions, which the reference records as an
    // infinite dispatch loop.
    if (code == 0x80000004u) {
        auto& regs = ql_->arch().regs();
        regs.write("eflags", regs.read("eflags") & ~0x100ull);
    }
    ql_->emu_stop();
    return true;
}

bool QlOsWindows::seh_write_prot_trampoline(uc_engine*, uc_mem_type /*type*/, std::uint64_t address,
                                            std::uint32_t size, std::int64_t value, void* user_data) {
    auto* self = static_cast<QlOsWindows*>(user_data);
    try {
        return self->seh_on_write_prot(address, size, static_cast<std::uint64_t>(value));
    } catch (const std::exception& e) {
        self->on_emulation_error(e.what());
        return false;
    } catch (...) {
        self->on_emulation_error("SEH write-prot dispatch failed");
        return false;
    }
}

bool QlOsWindows::seh_on_write_prot(std::uint64_t address, std::uint32_t size, std::uint64_t value) {
    if (bits_ != 32 || !seh_dispatch_enabled_ || !loader_done()) {
        return false;
    }
    if (seh_sentinel_ == 0 && !seh_map_sentinel()) {
        return false;
    }
    if (seh_dispatch(address, 1u, 0xC0000005u)) {
        ql_->emu_stop();
        return true;
    }
    // nothing handled the AV: complete the write so the stub can proceed (the
    // reference's unpack-mode survive behavior — Alienyze scrubs import
    // descriptors inside a read-only .rsrc and must not die on the fault)
    try {
        const auto page = address & ~0xfffull;
        ql_->mem().protect(page, 0x1000, UC_PROT_ALL);
        std::vector<std::uint8_t> bytes;
        const auto n = std::min<std::uint32_t>(size, 8);
        for (std::uint32_t i = 0; i < n; ++i) {
            bytes.push_back(static_cast<std::uint8_t>((value >> (8 * i)) & 0xff));
        }
        ql_->mem().write(address, bytes);
        return true;
    } catch (...) {
        return false;
    }
}

bool QlOsWindows::seh_dispatch_cpu(std::uint32_t exception_code) {
    if (bits_ != 32 || !seh_dispatch_enabled_ || seh_retarget_ != 0) {
        return false;
    }
    // the ICEBP is the run's first fault: no memory fault has mapped the
    // sentinel yet, so it is created on demand here (same rule as seh_on_fault)
    if (seh_sentinel_ == 0 && !seh_map_sentinel()) {
        return false;
    }
    const auto pc = ql_->arch().regs().arch_pc();
    if (!seh_dispatch(pc, 0u, exception_code)) {
        return false;
    }
    // clear TF in the live EFLAGS after the CONTEXT snapshot, so the handler
    // runs untrapped (mirrors seh_on_interrupt's single-step path)
    if (exception_code == 0x80000004u) {
        auto& regs = ql_->arch().regs();
        regs.write("eflags", regs.read("eflags") & ~0x100ull);
    }
    ql_->emu_stop();
    return true;
}

// stage one fs:[0] frame handler call:
//   handler(ExceptionRecord, EstablisherFrame, ContextRecord, DispatcherContext)
// with the sentinel as the return address. Shared by the first dispatch and by
// the outward walk `seh_continue` performs when a handler answers
// EXCEPTION_CONTINUE_SEARCH.
bool QlOsWindows::seh_call_frame(std::uint64_t frame) {
    auto& regs = ql_->arch().regs();
    auto& mem = ql_->mem();

    const auto handler = mem.read_ptr(frame + 4, 4);
    if (handler == 0 || handler == 0xffffffffull) {
        return false;  // a malformed frame: rather fail than dispatch garbage
    }

    // the ms_exc convention: the EXCEPTION_POINTERS pointer just below the
    // registration record — the compiled __except filters read it through
    // the ebp-based locals ([ebp-0x14] -> the frame slot)
    mem.write_ptr(frame - 4, seh_walk_ptrs_, 4);

    auto esp = regs.arch_sp();
    esp -= 4; mem.write_ptr(esp, 0, 4);                        // DispatcherContext
    esp -= 4; mem.write_ptr(esp, seh_context_addr_, 4);         // ContextRecord
    esp -= 4; mem.write_ptr(esp, frame, 4);                     // EstablisherFrame
    esp -= 4; mem.write_ptr(esp, seh_walk_record_, 4);          // ExceptionRecord
    esp -= 4; mem.write_ptr(esp, seh_sentinel_, 4);             // the return address
    regs.set_arch_sp(esp);

    seh_walk_frame_ = frame;
    seh_retarget_ = handler;
    return true;
}

// pegasus _dispatch_seh_x86: stage the fs:[0] frame handler call and arm the
// retarget. Returns true when the dispatch took the fault.
bool QlOsWindows::seh_dispatch(std::uint64_t fault_addr, std::uint32_t access_type,
                                std::uint32_t exception_code) {
    auto& regs = ql_->arch().regs();
    auto& mem = ql_->mem();

    // the exception list head (fs:[0]; the TEB rides the FS segment base)
    const auto chain = mem.read_ptr(FS_SEGMENT_ADDR, 4);
    if (chain == 0 || chain == 0xffffffffull) {
        return false;  // no registered frame: the fault propagates
    }
    const auto next = mem.read_ptr(chain, 4);
    const auto handler = mem.read_ptr(chain + 4, 4);
    if (handler == 0 || handler == 0xffffffffull) {
        return false;  // a malformed frame: rather fail than dispatch garbage
    }
    if (next != 0 && next != 0xffffffffull && (next < 0x1000 || next >= 0xfffff000)) {
        return false;
    }

    // the repeat guard: an identical (pc, address) fault storm (a handler
    // that resumes without fixing anything) must not spin forever
    const auto pc = regs.arch_pc();
    if (pc == seh_fault_pc_ && fault_addr == seh_fault_addr_) {
        if (++seh_repeat_count_ > 16) {
            return false;
        }
    } else {
        seh_fault_pc_ = pc;
        seh_fault_addr_ = fault_addr;
        seh_repeat_count_ = 1;
    }

    // the structures page: the EXCEPTION_POINTERS at +0, the
    // EXCEPTION_RECORD at +0x10, the CONTEXT at +0x100. A fresh page per
    // dispatch, deliberately: every record a live frame still points at has
    // to stay readable (a filter reads its own CONTEXT), so nothing is
    // recycled while the walk nests. The allocation is one page from the
    // 0x70000000-0x78000000 arena, i.e. a 32k-dispatch budget
    std::uint64_t page = 0;
    try {
        page = mem.find_free_space(0x1000, 0x70000000ull, 0x78000000ull, 0x1000);
        mem.map(page, 0x1000, UC_PROT_ALL, "[SEH]");
    } catch (...) {
        return false;
    }
    const auto p_ptrs = page;
    const auto p_record = page + 0x10;
    const auto p_ctx = page + 0x100;

    // EXCEPTION_POINTERS {ExceptionRecord, ContextRecord}
    mem.write_ptr(p_ptrs, p_record, 4);
    mem.write_ptr(p_ptrs + 4, p_ctx, 4);

    // EXCEPTION_RECORD: the ACCESS_VIOLATION code, the faulting pc, the
    // read/write type + the faulting address in the info params
    std::vector<std::uint8_t> rec(SEH_RECORD_SIZE, 0);
    using namespace ntdefs;
    put_u32(rec, EXCEPTION_RECORD_OFF_CODE, exception_code);
    put_u32(rec, EXCEPTION_RECORD_OFF_FLAGS, 0);
    put_u32(rec, 8, 0);           // ExceptionRecord (nested chains: none)
    put_u32(rec, EXCEPTION_RECORD_OFF_ADDRESS_X86, static_cast<std::uint32_t>(pc));
    put_u32(rec, EXCEPTION_RECORD_OFF_NUMBER_PARAMS_X86, 2);
    put_u32(rec, EXCEPTION_RECORD_OFF_NUMBER_PARAMS_X86 + 4, access_type);
    put_u32(rec, EXCEPTION_RECORD_OFF_INFORMATION_X86, static_cast<std::uint32_t>(fault_addr));
    mem.write(p_record, rec);

    // the x86 CONTEXT image
    seh_build_context(p_ctx);

    // reset the walk state: _except_handler4_common re-records the frames
    seh_frames_.clear();
    seh_dispatch_armed_ = true;
    seh_context_addr_ = p_ctx;
    seh_walk_ptrs_ = p_ptrs;
    seh_walk_record_ = p_record;

    // stage the frame handler call and arm the retarget
    return seh_call_frame(chain);
}

// pegasus _continue_seh_x86: the sentinel return — walk the recorded frames.
// The guest eax carries the last return value (the trampoline's
// ExceptionContinueSearch from _except_handler4_common, or the filter's
// verdict).
bool QlOsWindows::seh_continue() {
    auto& regs = ql_->arch().regs();
    const auto ret = static_cast<std::uint32_t>(regs.read("eax"));
    if (std::getenv("TAOTE_SEHDBG") != nullptr) {
        // the walk's decision points, for diagnosing a fixture: which answer the
        // handler gave (1 = execute handler, 0 = continue search, -1 = continue
        // execution), how many synthetic frames are recorded, and which frame
        // the outward walk is on
        std::fprintf(stderr, "[sehc] ret=%u frames=%zu walk=0x%llx ctx=0x%llx esp=0x%llx eip=0x%llx\n",
                     ret, seh_frames_.size(), (unsigned long long)seh_walk_frame_,
                     (unsigned long long)seh_context_addr_, (unsigned long long)regs.arch_sp(),
                     (unsigned long long)regs.arch_pc());
    }

    if (seh_frames_.empty()) {
        // No synthetic frame was recorded, i.e. the handler that just returned
        // was the guest's own CRT one. Windows' dispatcher does two things with
        // its answer: EXCEPTION_EXECUTE_HANDLER means "resume at the handler the
        // CRT patched into the CONTEXT" (EH4 stores the __except block's address
        // in ContextRecord->Eip and the frame in Ebp before answering), and
        // EXCEPTION_CONTINUE_EXECUTION means "resume at the faulting context the
        // handler repaired". Both are a context load plus a retarget.
        //
        // Measured need: pegasus's seh_test_x86.exe deliberately writes to
        // address 0 (`movl $0x14,0x0` — the file has no relocation there, it is
        // the sample's own access violation) and expects its __except block to
        // run. On stubs the synthetic walk did that; with the Windows 11 tree the
        // run died on the write because nothing applied the disposition.
        if (ret == kExceptionExecuteHandler || ret == kExceptionContinueExecution) {
            seh_load_context();
            seh_retarget_ = regs.arch_pc();
            return true;
        }

        // EXCEPTION_CONTINUE_SEARCH: this frame does not handle the fault, so
        // the dispatcher walks outward — the *next* registration in fs:[0]
        // becomes the establisher frame and its handler is called with the same
        // record and context. Real EH4 handlers only ever answer
        // CONTINUE_SEARCH when they are not interested (when they do handle,
        // they RtlUnwind/RtlRestoreContext instead of returning), so returning
        // here means "try the next frame".
        //
        // Measured need: al-khaser's static CRT takes a genuine access
        // violation in `_getptd`/locale setup; the first frame's handler
        // declines it, and without the walk the run died fetching the sentinel
        // page (0x70000001) with the handler's ContinUE_SEARCH in eax.
        const auto next = ql_->mem().read_ptr(seh_walk_frame_, 4);
        if (next == 0 || next == 0xffffffffull || next < 0x1000 || next >= 0xfffff000) {
            return false;  // the chain is exhausted: the fault is unhandled
        }
        return seh_call_frame(next);
    }

    for (auto& frame : seh_frames_) {
        if (frame.searched) {
            continue;
        }
        auto& scope = frame.scope;

        // the filter first (the __except (expression) evaluation)
        if (!scope.filter_called && scope.filter != 0 && scope.filter != 0xffffffffu) {
            auto esp = regs.arch_sp() - 4;
            ql_->mem().write_ptr(esp, seh_sentinel_, 4);
            regs.set_arch_sp(esp);
            seh_retarget_ = scope.filter;
            scope.filter_called = true;
            return true;
        }

        if (ret == kExceptionExecuteHandler || scope.filter == 0) {
            if (!scope.handler_called && scope.handler != 0 && scope.handler != 0xffffffffu) {
                seh_retarget_ = scope.handler;
                scope.handler_called = true;
                return true;
            }
        } else if (ret == kExceptionContinueExecution) {
            // reload the saved CONTEXT (the handler may have patched Eip)
            // and resume
            seh_load_context();
            seh_retarget_ = regs.arch_pc();
            return true;
        }
        // EXCEPTION_CONTINUE_SEARCH: the next frame
        frame.searched = true;
    }

    // the walk exhausted: unhandled — the fault surfaces (the run loop sees
    // no retarget and the emu error propagates)
    return false;
}

// capture the current guest state into the x86 CONTEXT image
void QlOsWindows::seh_build_context(std::uint64_t dest) const {
    const auto& regs = ql_->arch().regs();

    std::vector<std::uint8_t> ctx(SEH_CONTEXT_SIZE, 0);
    put_u32(ctx, kCtxContextFlags, kContextFull);
    put_u32(ctx, kCtxSegGs, static_cast<std::uint32_t>(regs.read("gs")));
    put_u32(ctx, kCtxSegFs, static_cast<std::uint32_t>(regs.read("fs")));
    put_u32(ctx, kCtxSegEs, static_cast<std::uint32_t>(regs.read("es")));
    put_u32(ctx, kCtxSegDs, static_cast<std::uint32_t>(regs.read("ds")));
    put_u32(ctx, kCtxEdi, static_cast<std::uint32_t>(regs.read("edi")));
    put_u32(ctx, kCtxEsi, static_cast<std::uint32_t>(regs.read("esi")));
    put_u32(ctx, kCtxEbx, static_cast<std::uint32_t>(regs.read("ebx")));
    put_u32(ctx, kCtxEdx, static_cast<std::uint32_t>(regs.read("edx")));
    put_u32(ctx, kCtxEcx, static_cast<std::uint32_t>(regs.read("ecx")));
    put_u32(ctx, kCtxEax, static_cast<std::uint32_t>(regs.read("eax")));
    put_u32(ctx, kCtxEbp, static_cast<std::uint32_t>(regs.read("ebp")));
    put_u32(ctx, kCtxEip, static_cast<std::uint32_t>(regs.arch_pc()));
    put_u32(ctx, kCtxSegCs, static_cast<std::uint32_t>(regs.read("cs")));
    put_u32(ctx, kCtxEFlags, static_cast<std::uint32_t>(regs.read("eflags")));
    put_u32(ctx, kCtxEsp, static_cast<std::uint32_t>(regs.arch_sp()));
    put_u32(ctx, kCtxSegSs, static_cast<std::uint32_t>(regs.read("ss")));
    ql_->mem().write(dest, ctx);
}

// restore the guest state from the saved CONTEXT (the handler-patched image)
void QlOsWindows::seh_load_context() {
    if (seh_context_addr_ == 0) {
        return;
    }
    seh_apply_context(ql_->mem().read(seh_context_addr_, SEH_CONTEXT_SIZE));
}

// apply a guest x86 CONTEXT image to the emulated CPU. Shared by the synthetic
// dispatch (which owns the image it built) and the NtContinue path (which is
// handed one by real CRT code).
void QlOsWindows::seh_apply_context(const std::vector<std::uint8_t>& image) {
    if (image.size() < SEH_CONTEXT_SIZE) {
        return;
    }
    auto& regs = ql_->arch().regs();

    regs.write("edi", get_u32(image, kCtxEdi));
    regs.write("esi", get_u32(image, kCtxEsi));
    regs.write("ebx", get_u32(image, kCtxEbx));
    regs.write("edx", get_u32(image, kCtxEdx));
    regs.write("ecx", get_u32(image, kCtxEcx));
    regs.write("eax", get_u32(image, kCtxEax));
    regs.write("ebp", get_u32(image, kCtxEbp));
    regs.write("eflags", get_u32(image, kCtxEFlags));
    regs.set_arch_sp(get_u32(image, kCtxEsp));
    regs.set_arch_pc(get_u32(image, kCtxEip));
}

// NtContinue / RtlRestoreContext: the CRT's exception transfer hands the
// dispatcher a fully built CONTEXT whose Eip is the __except block (or the
// repaired faulting instruction). The API handler cannot apply it directly —
// the call's own unwind would overwrite Eax/Esp afterwards — so it parks the
// image here and stops the emulation; the run loop applies it at the restart.
void QlOsWindows::set_continue_context(const std::vector<std::uint8_t>& image) {
    if (image.size() < SEH_CONTEXT_SIZE) {
        return;
    }
    continue_context_ = image;
    continue_context_pc_ = get_u32(image, kCtxEip);
}

void QlOsWindows::apply_continue_context() {
    if (continue_context_.empty()) {
        return;
    }
    const auto image = continue_context_;
    continue_context_.clear();
    seh_dispatch_armed_ = false;
    seh_apply_context(image);
}

void QlOsWindows::seh_record_frame(std::uint64_t frame, const SehScopeRecord& scope) {
    seh_frames_.push_back(SehFrame{frame, scope, false});
}

}  // namespace windows
}  // namespace os
}  // namespace qiling
