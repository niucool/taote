#include <cstdio>
#include <unicorn/unicorn.h>
#include "qiling/arch/x86.hpp"
#include "qiling/cc/intel.hpp"
#include "qiling/os/fcall.hpp"
#include "qiling/os/memory.hpp"
#include "qiling/core_struct.hpp"

using namespace qiling;

int main() {
    qiling::QlArchX8664 arch(nullptr);
    QlCoreStructs structs(QL_ENDIAN::EL, 64);
    QlMemoryManager mem(arch.uc(), structs, 64);
    arch.attach_memory(mem);
    mem.map(0x7FF000000ull, 0x100000, UC_PROT_ALL, "stack");
    arch.regs().write("sp", 0x7FF000000ull + 0x80000);
    std::printf("sp = %#llx\n", (unsigned long long)arch.regs().arch_sp());
    return 0;
}
