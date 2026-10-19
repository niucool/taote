#include "qiling/os/fcall.hpp"

#include <cstdio>

namespace qiling {

void QlFunctionCall::set_accessor(int type, Accessor accessor) {
    // fcall.py: let the user override default accessors or add custom ones
    Access a;
    a.reader = std::move(accessor.reader);
    a.writer = std::move(accessor.writer);
    a.nslots = accessor.nslots;

    for (auto& [type_key, existing] : accessors_) {
        if (type_key == type) {
            existing = std::move(a);
            return;
        }
    }
    accessors_.push_back({type, std::move(a)});
}

const QlFunctionCall::Access& QlFunctionCall::access_for(int type) const {
    for (const auto& [type_key, accessor] : accessors_) {
        if (type_key == type) {
            return accessor;
        }
    }
    // unknown types fall back to the native accessor (fcall.py .get(default))
    return access_for(os::PARAM_INTN);
}

std::vector<std::uint64_t> QlFunctionCall::read_params(const std::vector<int>& ptypes) const {
    // fcall.py readParams: walk the parameter types and read their values,
    // advancing the slot index by each accessor's slot count
    std::vector<std::uint64_t> values;
    values.reserve(ptypes.size());

    int si = 0;
    for (const int typ : ptypes) {
        const auto& [reader, _, nslots] = access_for(typ);
        values.push_back(static_cast<std::uint64_t>(reader(si)));
        si += nslots;
    }
    return values;
}

void QlFunctionCall::write_params(const std::vector<std::pair<int, std::uint64_t>>& params) {
    int si = 0;
    for (const auto& [typ, value] : params) {
        const auto& [_, writer, nslots] = access_for(typ);
        writer(si, static_cast<std::int64_t>(value));
        si += nslots;
    }
}

std::vector<std::uint64_t> QlFunctionCall::read_ellipsis(const std::vector<int>& ptypes, std::size_t count) const {
    // fcall.py readEllipsis: a generator skipping the typed argument slots and
    // yielding native-width values from there; the C++ port takes the count
    std::vector<std::uint64_t> out;
    out.reserve(count);

    const auto& native = access_for(os::PARAM_INTN);
    int si = 0;
    for (const int typ : ptypes) {
        si += access_for(typ).nslots;
    }

    for (std::size_t i = 0; i < count; ++i) {
        out.push_back(static_cast<std::uint64_t>(native.reader(si)));
        si += native.nslots;
    }
    return out;
}

int QlFunctionCall::count_slots(const std::vector<int>& ptypes) const {
    int total = 0;
    for (const int typ : ptypes) {
        total += access_for(typ).nslots;
    }
    return total;
}

QlFunctionCall::CallResult QlFunctionCall::call(const CallHook& func,
                                                const std::vector<std::pair<std::string, int>>& proto,
                                                const Params& params, const OnEnterHook& hook_onenter,
                                                const OnExitHook& hook_onexit, bool passthru) {
    // fcall.py call: fire the on-enter hook (which may override the args and
    // the pc), call the function hook, fire the on-exit hook (which may
    // override the return value), set the return value, resolve the typed
    // arguments and unwind the frame
    CallResult out;

    const std::uint64_t pc = cc_->arch().regs().arch_pc();
    Params args = params;

    if (hook_onenter) {
        if (auto overrides = hook_onenter(pc, args)) {
            args = std::move(overrides->second);
        }
    }

    const auto retval = func(pc, args);
    out.retval = retval;

    if (hook_onexit) {
        if (auto override_ret = hook_onexit(pc, args, retval)) {
            out.retval = override_ret;
        }
    }

    if (out.retval.has_value()) {
        cc_->setReturnValue(*out.retval);
    }

    // resolve the typed arguments (fcall.py __get_typed_args): the types list
    // is extended to the params length for variadic functions
    out.params.reserve(args.size());
    for (std::size_t i = 0; i < args.size(); ++i) {
        const auto& [name, value] = args[i];
        if (i < proto.size()) {
            out.params.push_back(TypedArg{proto[i].second, name, value});
        } else {
            out.params.push_back(TypedArg{std::nullopt, name, value});
        }
    }

    // count the prototype slots and unwind the frame; note that the function
    // prototype sometimes does not reflect the actual number of arguments
    // passed (variadic functions never unwind their own frame, exactly for
    // that reason) — memory.py/fcall.py comments, verbatim
    std::vector<int> proto_types;
    proto_types.reserve(proto.size());
    for (const auto& [_, typ] : proto) {
        proto_types.push_back(typ);
    }

    const int nslots = count_slots(proto_types);
    out.retaddr = passthru ? -1 : static_cast<std::int64_t>(cc_->unwind(nslots));

    return out;
}

void QlFunctionCall::call_native(std::uint64_t addr, const std::vector<std::pair<int, std::uint64_t>>& args,
                                 std::optional<std::uint64_t> ret) {
    // fcall.py call_native: reserve the argument slots, set the return
    // address, write the arguments and point the pc at the callee
    std::vector<int> atypes;
    atypes.reserve(args.size());
    for (const auto& [atype, _] : args) {
        atypes.push_back(atype);
    }

    const int nslots = count_slots(atypes);
    cc_->reserve(nslots);

    if (ret.has_value()) {
        cc_->setReturnAddress(*ret);
    }

    write_params(args);

    cc_->arch().regs().set_arch_pc(addr);
}

// the post-emu_start frame unwind (the call_dll_entrypoint tail: the native
// frame pops its arg slots and the return address after emu_start returns)
void QlFunctionCall::unwind_native(int nslots) {
    static_cast<void>(cc_->unwind(nslots));
}

}  // namespace qiling
