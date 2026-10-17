// Ported from qiling/cc/intel.py — the Intel x86/x86-64 calling conventions.
// Stack-based argument slots need the memory manager (exercised from Phase 2);
// the register-file behavior is covered by tests/Cc_Test.cpp in Phase 1.
#ifndef QILING_CC_INTEL_HPP
#define QILING_CC_INTEL_HPP

#include "qiling/cc/cc.hpp"

namespace qiling {
namespace cc {

// Calling convention base class for Intel-based systems. Supports arguments
// passing over registers and stack; return address lives on the stack.
class QlIntelBaseCC : public QlCommonBaseCC {
public:
    using QlCommonBaseCC::QlCommonBaseCC;

    std::uint64_t getReturnAddress() override;
    void setReturnAddress(std::uint64_t addr) override;
    std::uint64_t unwind(int nslots) override;
};

// Calling convention base class for Intel-based 64-bit systems.
class QlIntel64 : public QlIntelBaseCC {
public:
    using QlIntelBaseCC::QlIntelBaseCC;

    static int getNumSlots(int argbits) { return argbits > 64 ? argbits / 64 : 1; }
};

// Calling convention base class for Intel-based 32-bit systems.
class QlIntel32 : public QlIntelBaseCC {
public:
    using QlIntelBaseCC::QlIntelBaseCC;

    static int getNumSlots(int argbits) { return argbits > 32 ? argbits / 32 : 1; }

    std::uint64_t getRawParam(int slot, int argbits = 0) override;
    void setRawParam(int slot, std::uint64_t value, int argbits = 0) override;
};

// Default calling convention for POSIX (x86-64). First 6 arguments are passed
// in regs, the rest are passed on the stack.
class amd64 : public QlIntel64 {
public:
    explicit amd64(QlArch& arch);
};

// Default calling convention for Windows and UEFI (x86-64). First 4 arguments
// are passed in regs, the rest on the stack; each stack frame starts with a
// shadow space in size of 4 items.
class ms64 : public QlIntel64 {
public:
    explicit ms64(QlArch& arch);
};

// Default calling convention for Mac OS (x86-64). First 6 arguments are passed
// in regs, the rest are passed on the stack.
class macosx64 : public QlIntel64 {
public:
    explicit macosx64(QlArch& arch);
};

// Calling convention used by all operating systems (x86). All arguments are
// passed on the stack; the caller is responsible to unwind the stack.
//
// Python class name: `cdecl` — MSVC reserves `cdecl` as an archaic calling-
// convention keyword, so the C++ class is named QlCdecl (the errno_value()
// precedent: verbatim name impossible on the target compiler).
class QlCdecl : public QlIntel32 {
public:
    explicit QlCdecl(QlArch& arch);
};

// Calling convention used by all operating systems (x86). All arguments are
// passed on the stack; the callee is responsible to unwind the stack.
// Python class name: `stdcall` — MSVC keyword; see the QlCdecl note.
class QlStdcall : public QlIntel32 {
public:
    explicit QlStdcall(QlArch& arch);

    std::uint64_t unwind(int nslots) override;
};

}  // namespace cc
}  // namespace qiling

#endif  // QILING_CC_INTEL_HPP
