// Ported from qiling/exception.py — the QlError* hierarchy carries over verbatim
// (PORT_PLAN.md 5.4). QlErrorBase derives from std::runtime_error so host code can
// catch std::exception uniformly.
//
// Discipline (PORT_PLAN.md 5.4, enforced in review):
//   - exceptions may be thrown from syscall/API handlers and hook callbacks
//   - they must be caught by the hook trampoline (5.1) or at the os.run() boundary
//   - they never cross a Unicorn C frame (5.1) and never cross a fiber switch (5.3)
#ifndef QILING_EXCEPTION_HPP
#define QILING_EXCEPTION_HPP

#include <stdexcept>
#include <string>

namespace qiling {

class QlErrorBase : public std::runtime_error {
public:
    explicit QlErrorBase(const std::string& msg) : std::runtime_error(msg) {}
};

// Plain subclasses of QlErrorBase (verbatim names from exception.py). The
// `using`-inherited constructors keep them zero-boilerplate.
class QlErrorStructConversion : public QlErrorBase { public: using QlErrorBase::QlErrorBase; };
class QlErrorFileNotFound : public QlErrorBase { public: using QlErrorBase::QlErrorBase; };
class QlErrorFileType : public QlErrorBase { public: using QlErrorBase::QlErrorBase; };
class QlErrorOsType : public QlErrorBase { public: using QlErrorBase::QlErrorBase; };
class QlErrorOutput : public QlErrorBase { public: using QlErrorBase::QlErrorBase; };
class QlErrorArch : public QlErrorBase { public: using QlErrorBase::QlErrorBase; };
class QlErrorRuntype : public QlErrorBase { public: using QlErrorBase::QlErrorBase; };
class QlErrorJsonDecode : public QlErrorBase { public: using QlErrorBase::QlErrorBase; };
class QlErrorNotImplemented : public QlErrorBase { public: using QlErrorBase::QlErrorBase; };
class QlErrorELFFormat : public QlErrorBase { public: using QlErrorBase::QlErrorBase; };
class QlErrorMACHOFormat : public QlErrorBase { public: using QlErrorBase::QlErrorBase; };
class QlErrorModuleFunctionNotFound : public QlErrorBase { public: using QlErrorBase::QlErrorBase; };
class QlErrorModuleNotFound : public QlErrorBase { public: using QlErrorBase::QlErrorBase; };
class QlErrorExecutionStop : public QlErrorBase { public: using QlErrorBase::QlErrorBase; };
class QlErrorSyscallError : public QlErrorBase { public: using QlErrorBase::QlErrorBase; };
class QlErrorSyscallNotFound : public QlErrorBase { public: using QlErrorBase::QlErrorBase; };
class QlErrorCoreHook : public QlErrorBase { public: using QlErrorBase::QlErrorBase; };
class QlOutOfMemory : public QlErrorBase { public: using QlErrorBase::QlErrorBase; };
class QlMemoryMappedError : public QlErrorBase { public: using QlErrorBase::QlErrorBase; };
class QlGDTError : public QlErrorBase { public: using QlErrorBase::QlErrorBase; };
class QlProxyConnectionError : public QlErrorBase { public: using QlErrorBase::QlErrorBase; };

// QlSyscallError carries an errno and renders as "[ Errno N] msg" (verbatim __str__).
// The `errno` attribute is renamed errno_value — `errno` is a macro in C.
class QlSyscallError : public QlErrorBase {
public:
    QlSyscallError(int err, const std::string& msg);
    int errno_value() const noexcept { return errno_; }

private:
    int errno_;
};

// QlPrintException (exception.py) is Python-traceback plumbing with no C++ counterpart
// and is intentionally not ported.

}  // namespace qiling

#endif  // QILING_EXCEPTION_HPP
