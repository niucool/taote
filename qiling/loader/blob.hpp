// Ported from qiling/loader/blob.py — QlLoaderBLOB (loader/blob.hpp holds the
// class declaration).
#ifndef QILING_LOADER_BLOB_HPP
#define QILING_LOADER_BLOB_HPP

#include "qiling/loader/loader.hpp"

namespace qiling {
namespace loader {

class QlLoaderBLOB final : public QlLoader {
public:
    explicit QlLoaderBLOB(Qiling* ql);

    void run() override;
};

}  // namespace loader
}  // namespace qiling

#endif  // QILING_LOADER_BLOB_HPP
