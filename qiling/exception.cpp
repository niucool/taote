#include "qiling/exception.hpp"

namespace qiling {

// exception.py: QlSyscallError.__str__ renders "[ Errno " + str(errno) + "] " + msg.
// The base stores msg; the C++ port renders eagerly into what() (the __str__
// analogue) while keeping the errno attribute as errno_value().
QlSyscallError::QlSyscallError(int err, const std::string& msg)
    : QlErrorBase("[ Errno " + std::to_string(err) + "] " + msg), errno_(err) {}

}  // namespace qiling
