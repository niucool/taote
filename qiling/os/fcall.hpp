// Ported from qiling/os/fcall.py — the function-call marshalling layer.
// Wraps a calling-convention instance and provides the per-type parameter
// accessors the OS layers use to read and write hooked-function arguments.
#ifndef QILING_OS_FCALL_HPP
#define QILING_OS_FCALL_HPP

#include <cstdint>
#include <functional>
#include <optional>
#include <string>
#include <utility>
#include <vector>

#include "qiling/cc/cc.hpp"
#include "qiling/os/const.hpp"

namespace qiling {

// TypedArg (fcall.py): the resolved parameter triple — type, name, value.
// The type is nullopt for the variadic expansion tail (fcall.py extends the
// types list with None).
struct TypedArg {
    std::optional<int> type;
    std::string name;
    std::uint64_t value = 0;
};

class QlFunctionCall {
public:
    // fcall.py __init__(ql, cc, accessors): the ql dependency is carried by
    // the cc (which holds the arch). The default accessors are built from the
    // calling convention's raw parameter accessors.
    //
    // OWNERSHIP: the port owns the cc through cc_owner_ — the borrowed-
    // reference form left the cc object freed at the end of the constructing
    // full expression (the caller's make_unique temporary), a use-after-free
    // the tests only surfaced through heap-layout luck.
    explicit QlFunctionCall(std::unique_ptr<cc::QlCC> cc) : cc_owner_(std::move(cc)), cc_(cc_owner_.get()) {
        build_default_accessors();
    }

    // the borrowed form stays available for the os-managed cc objects (the
    // windows fcall_table_ entries own their cc through the same table)
    explicit QlFunctionCall(cc::QlCC& cc) : cc_(&cc) {
        build_default_accessors();
    }

private:
    void build_default_accessors() {
        const auto bind = [this](int nbits) {
            Access a;
            a.reader = [this, nbits](int slot) { return cc_->getRawParam(slot, nbits); };
            a.writer = [this, nbits](int slot, std::int64_t value) { cc_->setRawParam(slot, value, nbits); };
            a.nslots = 1;
            return a;
        };

        accessors_.emplace_back(os::PARAM_INT8, bind(8));
        accessors_.emplace_back(os::PARAM_INT16, bind(16));
        accessors_.emplace_back(os::PARAM_INT32, bind(32));
        accessors_.emplace_back(os::PARAM_INT64, bind(64));
        accessors_.emplace_back(os::PARAM_INTN, bind(0));
    }

    // the concrete-convention slot counts (fcall.py cc.getNumSlots)
    template <typename CC>
    void rebind_slots() {
        const auto rebind = [this](int type, int nbits) {
            for (auto& [type_key, accessor] : accessors_) {
                if (type_key == type) {
                    accessor.nslots = CC::getNumSlots(nbits);
                }
            }
        };
        rebind(os::PARAM_INT8, 8);
        rebind(os::PARAM_INT16, 16);
        rebind(os::PARAM_INT32, 32);
        rebind(os::PARAM_INT64, 64);
        rebind(os::PARAM_INTN, 0);
    }

public:

    // Concrete-convention construction: binds the static getNumSlots of the
    // concrete convention into the default accessors (Python resolves
    // cc.getNumSlots through the instance type; the C++ static member needs
    // the concrete type at compile time).
    //
    // The OWNED-pointer spelling below is the one every os uses (the fcall
    // tables hold unique_ptrs): without the rebind the 32-bit conventions
    // leave the 64-bit types at one slot, so an x86 `unsigned __int64 _Options`
    // head parameter shifts every following argument by a slot — the
    // __stdio_common_vfprintf dispatch read _Format out of the _Stream cell
    // and the samples' formatted output turned into the read-at-0x1 walk.
    template <typename CC, typename = std::enable_if_t<!std::is_same_v<CC, cc::QlCC>>>
    explicit QlFunctionCall(std::unique_ptr<CC> cc)
        : cc_owner_(std::move(cc)), cc_(cc_owner_.get()) {
        build_default_accessors();
        rebind_slots<CC>();
    }

    template <typename CC>
    explicit QlFunctionCall(CC& cc) : QlFunctionCall(static_cast<cc::QlCC&>(cc)) {
        rebind_slots<CC>();
    }

    // custom accessor override (fcall.py: a mapping of parameter types to
    // methods that read and write their values)
    struct Accessor {
        std::function<std::int64_t(int slot)> reader;
        std::function<void(int slot, std::int64_t value)> writer;
        int nslots = 1;
    };
    void set_accessor(int type, Accessor accessor);

    // Walk the function parameters list and get their values (fcall.py
    // readParams). Unknown types fall back to the native accessor.
    std::vector<std::uint64_t> read_params(const std::vector<int>& ptypes) const;

    // Walk the function parameters list and set their values (writeParams)
    void write_params(const std::vector<std::pair<int, std::uint64_t>>& params);

    // Variadic argument reader (fcall.py readEllipsis): reads `count` values
    // following the typed arguments, slot-stepping through the native accessor
    std::vector<std::uint64_t> read_ellipsis(const std::vector<int>& ptypes, std::size_t count) const;

    // Execute a hooked function (fcall.py call): fires the on-enter / on-exit
    // hooks, invokes the hook, sets the return value, unwinds the frame.
    //
    //   proto   : the function prototype — ordered (name, type) entries
    //   params  : the argument mapping — ordered (name, value); variadic
    //             functions append extra entries
    //   returns : the resolved params mapping, the return value, the return
    //             address (-1 when the frame is not unwound)
    struct CallResult {
        std::vector<TypedArg> params;
        std::optional<std::uint64_t> retval;
        std::int64_t retaddr = -1;
    };

    using Params = std::vector<std::pair<std::string, std::uint64_t>>;
    using CallHook = std::function<std::optional<std::uint64_t>(std::uint64_t pc, const Params& params)>;
    using OnEnterHook = std::function<std::optional<std::pair<std::uint64_t, Params>>(std::uint64_t pc, const Params& params)>;
    using OnExitHook = std::function<std::optional<std::uint64_t>(std::uint64_t pc, const Params& params,
                                                                  std::optional<std::uint64_t> retval)>;

    CallResult call(const CallHook& func, const std::vector<std::pair<std::string, int>>& proto, const Params& params,
                    const OnEnterHook& hook_onenter, const OnExitHook& hook_onexit, bool passthru);

    // Call a native function after staging its arguments and return address
    // (fcall.py call_native)
    void call_native(std::uint64_t addr, const std::vector<std::pair<int, std::uint64_t>>& args,
                     std::optional<std::uint64_t> ret);

    // Answer a call without a handler body: set the return value and unwind the
    // frame as a real handler would (the unsupported-import path)
    void return_value(std::uint64_t value, int nslots) {
        cc_->setReturnValue(value);
        static_cast<void>(cc_->unwind(nslots));
    }

    // the post-emu_start frame unwind (fcall.py's cc.unwind(len(args)) ride
    // at the call_dll_entrypoint tail; the nslots form mirrors count_slots)
    void unwind_native(int nslots);

private:
    int count_slots(const std::vector<int>& ptypes) const;

    struct Access {
        std::function<std::int64_t(int)> reader;
        std::function<void(int, std::int64_t)> writer;
        int nslots = 1;
    };

    const Access& access_for(int type) const;

    // the owner must precede the borrowed pointer: the mem-init list runs in
    // declaration order, and cc_ reads cc_owner_.get()
    std::unique_ptr<cc::QlCC> cc_owner_;
    cc::QlCC* cc_ = nullptr;
    std::vector<std::pair<int, Access>> accessors_;  // insertion-ordered override map
};

}  // namespace qiling

#endif  // QILING_OS_FCALL_HPP
