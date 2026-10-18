// Ported from qiling/os/blob/blob.py — QlOsBlob: the bare-binary OS glue.
// "For bare binary such as u-boot, it's ready to be mapped and executed
// directly, where there is (may be) no concept of os?" (blob.py docstring)
#ifndef QILING_OS_BLOB_BLOB_HPP
#define QILING_OS_BLOB_BLOB_HPP

#include "qiling/os/memory.hpp"
#include "qiling/os/os.hpp"

namespace qiling {

class QlOsBlob final : public QlOs {
public:
    explicit QlOsBlob(Qiling* ql);

    QL_OS type() const noexcept override { return QL_OS::BLOB; }

    // blob.py run(): resolve the entry/exit points and start the emulation;
    // creates the heap when the profile carries the CODE heap settings
    void run() override;

private:
    std::unique_ptr<QlMemoryHeap> heap_;
};

}  // namespace qiling

#endif  // QILING_OS_BLOB_BLOB_HPP
