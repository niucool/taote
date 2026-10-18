// Ported from qiling/os/qnx/message.py — the QNX resource-manager message
// handlers (the io_write + the sys_conf slices; the io_connect/io_read/
// io_lseek/stat and the mem families land with their fixtures).
#include "qiling/os/qnx/message.hpp"

#include "qiling/core.hpp"
#include "qiling/os/qnx/const.hpp"
#include "qiling/os/qnx/helpers.hpp"
#include "qiling/os/qnx/qnx.hpp"
#include "qiling/os/qnx/types.hpp"

#include <array>
#include <cstring>
#include <string_view>

namespace qiling {
namespace os {
namespace qnx {

namespace {

// message.py _IO_COMBINE_FLAG
constexpr std::uint16_t kIoCombineFlag = 0x8000;

// map_msgtype.py msgtype_table (lib/c/public/sys/iomsg.h): the dispatch
// entries (the type → the handler)
struct MsgTypeEntry {
    std::uint16_t type;
    MsgHandler handler;
};

const MsgTypeEntry kMsgTypeTable[] = {
    {0x000, ql_qnx_msg_sys_conf},  // sys_conf
    {0x102, ql_qnx_msg_io_write},  // io_write
};

}  // namespace

MsgHandler find_message_handler(std::uint16_t type) {
    for (const auto& entry : kMsgTypeTable) {
        if (entry.type == type) {
            return entry.handler;
        }
    }
    return nullptr;
}

// message.py ql_qnx_msg_sys_conf (lib/c/1a/confstr.c + lib/c/1/sysconf.c):
// the flat _sys_conf struct rides sparts=-24; the _CONF_NUM path answers the
// sysconf_consts value in the <IIIiq> reply; the _CONF_STR path answers the
// string through the reply iovs
std::optional<std::int64_t> ql_qnx_msg_sys_conf(Qiling& ql, std::uint64_t coid, std::uint64_t smsg,
                                                std::int32_t sparts, std::uint64_t rmsg, std::int32_t rparts) {
    (void)coid;

    // struct _sys_conf in services/system/public/sys/sysmsg.h:
    // (type, subtype, cmd, name, spare, value) = unpack("<HHiiiq", body)
    if (sparts != -24) {
        throw QlErrorBase("qnx sys_conf: the input size is wrong");
    }
    const auto body = get_message_body(ql, smsg, sparts);
    const auto type = static_cast<std::uint16_t>(body[0] | (body[1] << 8));
    const auto subtype = static_cast<std::uint16_t>(body[2] | (body[3] << 8));
    const auto cmd =
        static_cast<std::int32_t>(body[4] | (body[5] << 8) | (body[6] << 16) | (static_cast<std::uint32_t>(body[7]) << 24));
    const auto name =
        static_cast<std::int32_t>(body[8] | (body[9] << 8) | (body[10] << 16) | (static_cast<std::uint32_t>(body[11]) << 24));

    if (type != 0x000) {
        throw QlErrorBase("qnx sys_conf: the message is wrong");
    }
    // sysconf_subtypes: only _SYS_SUB_GET is implemented
    if (subtype != 0) {
        throw QlErrorNotImplemented("qnx sys_conf: the subtype is not implemented");
    }

    if (cmd == SYSCONF_CONDITION_NUM) {
        // sys_conf(_SYS_SUB_GET, _CONF_NUM, *) in lib/c/1/sysconf.c
        if (rparts != -24) {
            throw QlErrorBase("qnx sys_conf: the output size is wrong");
        }
        if (name != 11) {  // == _SC_PAGESIZE
            throw QlErrorNotImplemented("qnx sys_conf: the sys_conf name is not implemented");
        }
        // struct _sys_conf_reply: pack("<IIIiq", 0, 0, 0, 0, retval)
        std::array<std::uint8_t, 24> reply{};
        const auto value = static_cast<std::uint64_t>(PAGESIZE);
        for (int i = 0; i < 8; ++i) {
            reply[16 + i] = static_cast<std::uint8_t>((value >> (8 * i)) & 0xff);
        }
        ql.mem().write(rmsg, std::vector<std::uint8_t>(reply.begin(), reply.end()));
        return 0;
    }

    if (cmd == SYSCONF_CONDITION_STR) {
        // sys_conf(_SYS_SUB_GET, _CONF_STR, *) in lib/c/1a/confstr.c
        if (rparts != 2) {
            throw QlErrorBase("qnx sys_conf: the output size is wrong");
        }
        std::string_view retstr;
        if (name == 200) {  // == _CS_LIBPATH
            retstr = "/usr/lib";
        } else if (name == 203) {  // == _CS_TIMEZONE
            retstr = "UTC";
        } else {
            throw QlErrorNotImplemented("qnx sys_conf: the sys_conf name is not implemented");
        }
        // the first reply iov carries the <IIIiq> length cell (the NUL rides
        // the string literal, the upstream's retstr = "...\0")
        const auto iov0_base = ql.mem().read_ptr(rmsg, 4);
        std::array<std::uint8_t, 24> head{};
        const auto len = static_cast<std::int64_t>(retstr.size() + 1);
        for (int i = 0; i < 8; ++i) {
            head[16 + i] = static_cast<std::uint8_t>((static_cast<std::uint64_t>(len) >> (8 * i)) & 0xff);
        }
        ql.mem().write(iov0_base, std::vector<std::uint8_t>(head.begin(), head.end()));
        // the second reply iov carries the string
        const auto iov1_base = ql.mem().read_ptr(rmsg + 8, 4);
        ql.mem().write(iov1_base, retstr);
        ql.mem().write(iov1_base + retstr.size(), std::vector<std::uint8_t>{0x00});
        return 0;
    }

    throw QlErrorNotImplemented("qnx sys_conf: the message is not implemented");
}

// message.py ql_qnx_msg_io_write: the write delegation — the header rides
// iov[0] and the payload rides iov[1] (the smsg+8 dword); the combine and
// the xtype paths are not implemented (the upstream raise shape)
std::optional<std::int64_t> ql_qnx_msg_io_write(Qiling& ql, std::uint64_t coid, std::uint64_t smsg,
                                                std::int32_t sparts, std::uint64_t rmsg, std::int32_t rparts) {
    (void)rmsg;
    (void)rparts;

    // struct _io_write in lib/c/public/sys/iomsg.h:
    // (type, combine_len, nbytes, xtype, zero) = unpack("<HHiII", body)
    const auto body = get_message_body(ql, smsg, sparts);
    const auto type = static_cast<std::uint16_t>(body[0] | (body[1] << 8));
    const auto combine_len = static_cast<std::uint16_t>(body[2] | (body[3] << 8));
    const auto nbytes = static_cast<std::int32_t>(body[4] | (body[5] << 8) | (body[6] << 16) |
                                                  (static_cast<std::uint32_t>(body[7]) << 24));
    const auto xtype = static_cast<std::uint32_t>(body[8] | (body[9] << 8) | (body[10] << 16) |
                                                  (static_cast<std::uint32_t>(body[11]) << 24));

    if ((combine_len & kIoCombineFlag) != 0 || xtype != 0) {
        throw QlErrorNotImplemented("qnx io_write: IO combine and XTYPE support not implemented");
    }

    // the write's buffer pointer rides the second iov entry (the smsg+8
    // dword; the flat form shares the offset)
    auto& conn = static_cast<QlOsQnx&>(ql.os()).connections().at(static_cast<std::uint32_t>(coid));
    const auto buf = static_cast<std::uint64_t>(ql.mem().read_ptr(smsg + 8, 4));

    // the posix write delegation (message.py ql_syscall_write import)
    const auto* entry = posix::SyscallRegistry::instance().find("write");
    const std::vector<std::uint64_t> write_args{static_cast<std::uint64_t>(*conn.fd), buf,
                                                static_cast<std::uint64_t>(nbytes)};
    return entry->handler(ql, write_args);
}

}  // namespace qnx
}  // namespace os
}  // namespace qiling
