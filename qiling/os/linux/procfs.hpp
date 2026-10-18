// Ported from qiling/os/linux/procfs.py — the /proc pseudo files the Linux
// os exposes through the fs mapper (FsMappedStream carries the buffered
// content; the factories produce it at open time).
#ifndef QILING_OS_LINUX_PROCFS_HPP
#define QILING_OS_LINUX_PROCFS_HPP

#include <string>
#include <vector>

#include "qiling/os/filestruct.hpp"

namespace qiling {

class Qiling;
class QlMemoryManager;

namespace os {
namespace linux {

// procfs.py FsMappedStream — the buffered pseudo file (the content is fixed
// at construction; the reads replay it)
class FsMappedStream : public QlFsMappedObject {
public:
    FsMappedStream(std::string fname, std::vector<std::uint8_t> content)
        : content_(std::move(content)), name_(std::move(fname)) {}

    std::vector<std::uint8_t> read(std::size_t read_len) override;
    std::size_t write(const std::vector<std::uint8_t>&) override;
    void close() override {}
    const std::string& name() const override { return name_; }

private:
    std::vector<std::uint8_t> content_;
    std::size_t cursor_ = 0;
    std::string name_;
};

// procfs.py QlProcFS — the /proc/self/* producers
class QlProcFS {
public:
    // the auxv blob: the paired key/value words until AUXV.AT_NULL
    static std::vector<std::uint8_t> self_auxv(class QlOsLinux& os);

    // the argv joined with NUL terminators
    static std::vector<std::uint8_t> self_cmdline(class QlOsLinux& os);

    // the environment as K=V, NUL-separated
    static std::vector<std::uint8_t> self_environ(class QlOsLinux& os);

    // the executable image bytes
    static std::vector<std::uint8_t> self_exe(class QlOsLinux& os);

    // the memory map lines (the get_mapinfo rendering)
    static std::vector<std::uint8_t> self_map(QlMemoryManager& mem);
};

}  // namespace linux
}  // namespace os
}  // namespace qiling

#endif  // QILING_OS_LINUX_PROCFS_HPP
