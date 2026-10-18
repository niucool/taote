#include "qiling/arch/arm.hpp"

#include "qiling/os/memory.hpp"

#include <unicorn/arm.h>
#include <unicorn/unicorn.h>

namespace qiling {

// ---- register maps (the arm_const.py tables, resolved against UC_ARM_REG_*; D3) ----

namespace {

using RegMap = QlRegisterManager::RegMap;

RegMap reg_map() {
    return {
        {"r0", UC_ARM_REG_R0},   {"r1", UC_ARM_REG_R1},   {"r2", UC_ARM_REG_R2},   {"r3", UC_ARM_REG_R3},
        {"r4", UC_ARM_REG_R4},   {"r5", UC_ARM_REG_R5},   {"r6", UC_ARM_REG_R6},   {"r7", UC_ARM_REG_R7},
        {"r8", UC_ARM_REG_R8},   {"r9", UC_ARM_REG_R9},   {"r10", UC_ARM_REG_R10}, {"r11", UC_ARM_REG_R11},
        {"r12", UC_ARM_REG_R12}, {"sp", UC_ARM_REG_SP},   {"lr", UC_ARM_REG_LR},   {"pc", UC_ARM_REG_PC},

        {"apsr", UC_ARM_REG_APSR}, {"cpsr", UC_ARM_REG_CPSR}, {"spsr", UC_ARM_REG_SPSR},
        {"fpexc", UC_ARM_REG_FPEXC},
    };
}

RegMap reg_vfp() {
    RegMap m;
    for (int i = 0; i <= 31; ++i) m.emplace("d" + std::to_string(i), UC_ARM_REG_D0 + i);
    m.emplace("fpscr", UC_ARM_REG_FPSCR);
    return m;
}

RegMap reg_map_q() {
    RegMap m;
    for (int i = 0; i <= 15; ++i) m.emplace("q" + std::to_string(i), UC_ARM_REG_Q0 + i);
    return m;
}

RegMap reg_map_s() {
    RegMap m;
    for (int i = 0; i <= 31; ++i) m.emplace("s" + std::to_string(i), UC_ARM_REG_S0 + i);
    return m;
}

// arm_const.py reg_cpr (coprocessor descriptor tuples)
QlCprManager::RegMap reg_cpr() {
    return {
        {"CPACR",    QlCprManager::Desc{15, 0,  1, 0, 2, 0, false}},
        {"TPIDRURO", QlCprManager::Desc{15, 0, 13, 0, 3, 0, false}},
    };
}

// cortex_m_const.py reg_map: the ARM base registers + the M-profile specials
RegMap cortex_m_reg_map() {
    RegMap m{
        {"r0", UC_ARM_REG_R0},   {"r1", UC_ARM_REG_R1},   {"r2", UC_ARM_REG_R2},   {"r3", UC_ARM_REG_R3},
        {"r4", UC_ARM_REG_R4},   {"r5", UC_ARM_REG_R5},   {"r6", UC_ARM_REG_R6},   {"r7", UC_ARM_REG_R7},
        {"r8", UC_ARM_REG_R8},   {"r9", UC_ARM_REG_R9},   {"r10", UC_ARM_REG_R10}, {"r11", UC_ARM_REG_R11},
        {"r12", UC_ARM_REG_R12}, {"sp", UC_ARM_REG_SP},   {"lr", UC_ARM_REG_LR},   {"pc", UC_ARM_REG_PC},

        {"msp", UC_ARM_REG_MSP},         {"psp", UC_ARM_REG_PSP},     {"xpsr", UC_ARM_REG_XPSR},
        {"apsr", UC_ARM_REG_APSR},       {"ipsr", UC_ARM_REG_IPSR},   {"epsr", UC_ARM_REG_EPSR},
        {"primask", UC_ARM_REG_PRIMASK}, {"faultmask", UC_ARM_REG_FAULTMASK},
        {"basepri", UC_ARM_REG_BASEPRI}, {"control", UC_ARM_REG_CONTROL},
        {"xpsr_nzcvqg", UC_ARM_REG_XPSR_NZCVQG},
    };
    return m;
}

template <typename... Rest>
RegMap merge(RegMap base, Rest... rest) {
    (base.merge(std::move(rest)), ...);
    return base;
}

}  // namespace

// ---- QlArchARM ----

QlArchARM::QlArchARM(Qiling* ql, std::optional<ARM_CPU_MODEL> cputype, QL_ENDIAN endian, bool thumb, int extra_mode)
    : QlArch(ql, cputype.has_value() ? std::optional<std::uint32_t>(static_cast<std::uint32_t>(*cputype)) : std::nullopt),
      init_endian_(endian),
      init_thumb_(thumb) {
    uc_mode mode = UC_MODE_ARM;
    if (endian == QL_ENDIAN::EB) mode = static_cast<uc_mode>(mode | UC_MODE_BIG_ENDIAN);
    if (thumb) mode = static_cast<uc_mode>(mode | UC_MODE_THUMB);
    if (extra_mode != 0) mode = static_cast<uc_mode>(mode | extra_mode);

    uc_engine* raw = nullptr;
    if (uc_open(UC_ARCH_ARM, mode, &raw) != UC_ERR_OK) {
        throw QlErrorArch("failed to initialize unicorn arm");
    }
    uc_.reset(raw);

    if (cputype.has_value()) {
        const auto model = static_cast<uc_cpu_arm>(*cputype);
        if (uc_ctl(uc_.get(), UC_CTL_WRITE(UC_CTL_CPU_MODEL, 1), model) != UC_ERR_OK) {
            throw QlErrorArch("failed to set cpu model");
        }
    }

    regs_ = QlRegisterManager(*uc_, merge(reg_map(), reg_vfp(), reg_map_q(), reg_map_s()), "pc", "sp");
    cpr_ = QlCprManager(*uc_, reg_cpr());
}

QlRegisterManager& QlArchARM::regs() { return *regs_; }

std::uint32_t QlArchARM::read_cpsr() const noexcept {
    std::uint32_t value = 0;
    uc_reg_read(uc_.get(), UC_ARM_REG_CPSR, &value);
    return value;
}

std::uint64_t QlArchARM::read_pc() const noexcept {
    std::uint64_t value = 0;
    uc_reg_read(uc_.get(), UC_ARM_REG_PC, &value);
    return value;
}

bool QlArchARM::is_thumb() const { return (read_cpsr() & (1u << 5)) != 0; }

std::uint64_t QlArchARM::effective_pc() const {
    // append 1 to pc if in thumb mode, or 0 otherwise (arm.py, verbatim)
    return read_pc() | static_cast<std::uint64_t>(is_thumb());
}

QL_ENDIAN QlArchARM::endian() const noexcept {
    // arm.py: endian is the live CPSR E bit (bit 9), not the init value
    return (read_cpsr() & (1u << 9)) != 0 ? QL_ENDIAN::EB : QL_ENDIAN::EL;
}

QlCprManager& QlArchARM::cpr() { return *cpr_; }

std::uint32_t QlArchARM::cs_mode_for(bool thumb, bool big_endian) noexcept {
    cs_mode mode = CS_MODE_ARM;
    if (big_endian) mode = static_cast<cs_mode>(mode | CS_MODE_BIG_ENDIAN);
    if (thumb) mode = static_cast<cs_mode>(mode | CS_MODE_THUMB);
    return mode;
}

int QlArchARM::ks_mode_for(bool thumb, bool big_endian) noexcept {
    int mode = KS_MODE_ARM;
    if (big_endian) mode |= KS_MODE_BIG_ENDIAN;
    if (thumb) mode |= KS_MODE_THUMB;
    return mode;
}

Cs& QlArchARM::disassembler() {
    // thumb mode and endianness may change during execution; pick the cached
    // instance matching the current mode (arm.py __cached_disasm)
    const int mode = static_cast<int>(cs_mode_for(is_thumb(), endian() == QL_ENDIAN::EB));
    auto it = cs_cache_.find(mode);
    if (it == cs_cache_.end()) {
        it = cs_cache_.emplace(mode, Cs(CS_ARCH_ARM, static_cast<cs_mode>(mode))).first;
    }
    return it->second;
}

Ks& QlArchARM::assembler() {
    const int mode = ks_mode_for(is_thumb(), endian() == QL_ENDIAN::EB);
    auto it = ks_cache_.find(mode);
    if (it == ks_cache_.end()) {
        it = ks_cache_.emplace(mode, Ks(KS_ARCH_ARM, mode)).first;
    }
    return it->second;
}

void QlArchARM::enable_vfp() {
    // set full access to cp10 and cp11 (arm.py, verbatim)
    auto& manager = cpr();
    const auto cpacr = manager.read("CPACR");
    manager.write("CPACR", cpacr | (0b11 << 20) | (0b11 << 22));
    regs().write("fpexc", 0b1 << 30);
}

// ---- QlInterruptContext (cortex_m.py) ----

void QlInterruptContext::enter() {
    // pushes xpsr, pc, lr, r12, r3, r2, r1, r0 (cortex_m.py, verbatim order)
    for (const char* reg : {"xpsr", "pc", "lr", "r12", "r3", "r2", "r1", "r0"}) {
        arch_.stack_push(arch_.regs().read(reg));
    }
    entered_ = true;
}

void QlInterruptContext::exit() {
    if (!entered_) return;
    entered_ = false;

    const auto retval = arch_.effective_pc();
    if ((retval & static_cast<std::uint64_t>(EXC_RETURN::MASK)) != static_cast<std::uint64_t>(EXC_RETURN::MASK)) {
        // Interrupt Crash — stopping the emulation needs the Qiling facade
        // (ql.stop); degrades to an error until the composition root exists
        throw QlErrorBase("interrupt crash (EXC_RETURN without the magic value)");
    }

    // Exit handler mode
    arch_.regs().write("ipsr", 0);

    // switch the stack according to exc_return (cortex_m.py, verbatim)
    const auto old_ctrl = arch_.regs().read("control");
    if ((retval & static_cast<std::uint64_t>(EXC_RETURN::RETURN_SP)) != 0) {
        arch_.regs().write("control", old_ctrl | static_cast<std::uint64_t>(CONTROL::SPSEL));
    } else {
        arch_.regs().write("control", old_ctrl & ~static_cast<std::uint64_t>(CONTROL::SPSEL));
    }

    // Restore stack (reversed push order)
    for (const char* reg : {"r0", "r1", "r2", "r3", "r12", "lr", "pc", "xpsr"}) {
        const auto value = arch_.stack_pop();
        arch_.regs().write(reg == std::string_view{"xpsr"} ? "XPSR_NZCVQG" : reg, value);
    }
}

// ---- QlArchCORTEX_M (cortex_m.py) ----

QlArchCORTEX_M::QlArchCORTEX_M(Qiling* ql, std::optional<ARM_CPU_MODEL> cputype)
    // cortex_m.py uc: Uc(UC_ARCH_ARM, UC_MODE_ARM + UC_MODE_MCLASS + UC_MODE_THUMB) —
    // the Python uc is a MultiTaskUnicorn; the plain instance ports the smoke
    // surface until the fiber scheduler phase wires multitask.
    : QlArchARM(ql, cputype, QL_ENDIAN::EL, /*thumb=*/true, UC_MODE_MCLASS) {
    regs_ = QlRegisterManager(*uc_, cortex_m_reg_map(), "pc", "sp");
    cpr_ = QlCprManager(*uc_, reg_cpr());
}

// cortex_m.py disassembler: Cs(CS_ARCH_ARM, CS_MODE_ARM + CS_MODE_MCLASS + CS_MODE_THUMB);
// assembler: Ks(KS_ARCH_ARM, KS_MODE_ARM + KS_MODE_THUMB). Cached per instance.
Cs& QlArchCORTEX_M::disassembler() {
    if (!cortex_cs_.has_value()) {
        cortex_cs_ = Cs(CS_ARCH_ARM, static_cast<cs_mode>(CS_MODE_ARM + CS_MODE_MCLASS + CS_MODE_THUMB));
    }
    return *cortex_cs_;
}

Ks& QlArchCORTEX_M::assembler() {
    if (!cortex_ks_.has_value()) {
        cortex_ks_ = Ks(KS_ARCH_ARM, KS_MODE_ARM + KS_MODE_THUMB);
    }
    return *cortex_ks_;
}

bool QlArchCORTEX_M::is_handler_mode() {
    return regs().read("ipsr") > 1;
}

bool QlArchCORTEX_M::using_psp() {
    return !is_handler_mode() && (regs().read("control") & static_cast<std::uint64_t>(CONTROL::SPSEL)) != 0;
}

void QlArchCORTEX_M::init_context() {
    // reads the initial MSP/PC from the vector table (cortex_m.py) through
    // the attached memory manager
    if (mem_ == nullptr) {
        throw QlErrorBase("init_context requires the memory manager (attach_memory)");
    }

    regs().write("lr", 0xffffffffu);
    regs().write("msp", mem_->read_ptr(0x0, 4));
    regs().write("pc", mem_->read_ptr(0x4, 4));
}

void QlArchCORTEX_M::unicorn_exception_handler(int intno) {
    // forwards to ql.hw.nvic — the hw peripheral tree is deferred with the
    // bare-metal path (PORT_PLAN.md §10, OQ 9)
    (void)intno;
    throw QlErrorNotImplemented("cortex-m exception forwarding requires ql.hw.nvic (deferred bare-metal path)");
}

}  // namespace qiling
