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
#include <filesystem>
#include <string>
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
    {0x000, ql_qnx_msg_sys_conf},      // sys_conf
    {0x100, ql_qnx_msg_io_connect},    // io_connect
    {0x101, ql_qnx_msg_io_read},       // io_read
    {0x102, ql_qnx_msg_io_write},      // io_write
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

// message.py ql_qnx_msg_io_read (lib/c/1/read.c): the flat _io_read rides
// sparts=-16; the nbytes must match -rparts and the posix read fills the
// reply buffer
std::optional<std::int64_t> ql_qnx_msg_io_read(Qiling& ql, std::uint64_t coid, std::uint64_t smsg,
                                               std::int32_t sparts, std::uint64_t rmsg, std::int32_t rparts) {
    const auto body = get_message_body(ql, smsg, sparts);

    // struct _io_read in lib/c/public/sys/iomsg.h:
    // (type_, combine_len, nbytes, xtype, zero) = unpack("<HHIII", body)
    const auto type = static_cast<std::uint16_t>(body[0] | (body[1] << 8));
    (void)type;
    const auto combine_len = static_cast<std::uint16_t>(body[2] | (body[3] << 8));
    const auto nbytes = static_cast<std::int32_t>(body[4] | (body[5] << 8) | (body[6] << 16) |
                                                  (static_cast<std::uint32_t>(body[7]) << 24));
    const auto xtype = static_cast<std::uint32_t>(body[8] | (body[9] << 8) | (body[10] << 16) |
                                                  (static_cast<std::uint32_t>(body[11]) << 24));

    if ((combine_len & kIoCombineFlag) != 0 || xtype != 0) {
        throw QlErrorNotImplemented("qnx io_read: IO combine and XTYPE support not implemented");
    }

    if (nbytes != -rparts) {
        throw QlErrorBase("qnx io_read: different sizes for io_read");
    }

    auto& conn = static_cast<QlOsQnx&>(ql.os()).connections().at(static_cast<std::uint32_t>(coid));
    const auto* read_entry = posix::SyscallRegistry::instance().find("read");
    const std::vector<std::uint64_t> read_args{static_cast<std::uint64_t>(*conn.fd), rmsg,
                                               static_cast<std::uint64_t>(nbytes)};
    return read_entry->handler(ql, read_args);
}

// message.py ql_qnx_msg_io_write: the write delegation — the header rides
// iov[0] and the payload rides iov[1] (the smsg+8 dword); the combine and
// the xtype paths are not implemented (the upstream raise shape)
// the table membership probe (the `x in table` python idiom over the
// name/flag tables)
template <typename Table>
bool table_contains(const Table& table, unsigned key) {
    for (const auto& entry : table) {
        if (entry.first == key) {
            return true;
        }
    }
    return false;
}

// message.py ql_qnx_msg_io_connect (_connect_ctrl.c::_connect_io): the
// OPEN path — the header rides iov[0] and the path rides iov[1]; the fd
// lands in the connection and the 20-byte link reply at the reply's first
// iov. The COMBINE subtypes raise not-implemented (the upstream walks the
// extra iovs for _IO_STAT/_IO_PATHCONF there).
std::optional<std::int64_t> ql_qnx_msg_io_connect(Qiling& ql, std::uint64_t coid, std::uint64_t smsg,
                                                  std::int32_t sparts, std::uint64_t rmsg, std::int32_t rparts) {
    (void)rparts;

    // first iov_t
    const auto iov0_base = ql.mem().read_ptr(smsg, 4);
    const auto iov0_len = ql.mem().read_ptr(smsg + 4, 4);
    if (iov0_len != 40) {
        throw QlErrorBase("qnx io_connect: wrong size for first first iov_t");
    }
    // struct _io_connect in lib/c/public/sys/iomsg.h:
    // unpack("<HHIHHIIIIHHHHBBH", iov0)
    const auto hdr = ql.mem().read(iov0_base, 40);
    const auto rd16 = [&hdr](std::size_t off) {
        return static_cast<std::uint16_t>(hdr[off] | (hdr[off + 1] << 8));
    };
    const auto rd32 = [&hdr](std::size_t off) {
        return static_cast<std::uint32_t>(hdr[off] | (hdr[off + 1] << 8) | (hdr[off + 2] << 16) |
                                          (static_cast<std::uint32_t>(hdr[off + 3]) << 24));
    };
    const auto type = rd16(0);
    const auto subtype = rd16(2);
    const auto file_type = rd32(4);
    const auto reply_max = rd16(8);
    const auto entry_max = rd16(10);
    const auto key = rd32(12);
    const auto handle = rd32(16);
    auto ioflag = rd32(20);
    const auto mode = rd32(24);
    const auto sflag = rd16(28);
    const auto access = rd16(30);
    const auto zero = rd16(32);
    const auto eflag = hdr[36];
    const auto extra_type = hdr[37];

    // the second iov_t carries the path
    const auto iov1_base = ql.mem().read_ptr(smsg + 8, 4);
    const auto iov1_len = ql.mem().read_ptr(smsg + 12, 4);
    auto path_bytes = ql.mem().read(iov1_base, iov1_len);
    while (!path_bytes.empty() && path_bytes.back() == 0x00) {
        path_bytes.pop_back();
    }
    const std::string path(path_bytes.begin(), path_bytes.end());
    const auto real_path = ql.os().path()->virtual_to_host_path(path);

    // the parameter checks (the upstream assert, verbatim)
    if (type != 0x100 || reply_max != 0xa18 || entry_max != 0x10 || key != 0 || handle != 0 || zero != 0 ||
        eflag != 0 || extra_type != 0) {
        throw QlErrorBase("qnx io_connect: the message is wrong");
    }
    if (!table_contains(io_connect_subtypes, subtype)) {
        throw QlErrorNotImplemented("qnx io_connect: the subtype is not implemented");
    }
    if (!table_contains(file_types, file_type)) {
        throw QlErrorNotImplemented("qnx io_connect: the file_type is not implemented");
    }
    if (!table_contains(file_sharing_modes, sflag)) {
        throw QlErrorNotImplemented("qnx io_connect: the sharing flag is not implemented");
    }
    if (access != 0 && !table_contains(file_access, access)) {
        throw QlErrorNotImplemented("qnx io_connect: the access is not implemented");
    }

    // convert _IO_FLAG_? to O_? (the upstream's ioflag -= 1, verbatim)
    ioflag -= 1;
    const auto real_mode = mode & ~static_cast<std::uint32_t>(S_IFMT);

    if (subtype == 0 || subtype == 1) {
        // _IO_CONNECT_COMBINE: the extra-iov walk for _IO_STAT/_IO_PATHCONF
        throw QlErrorNotImplemented("qnx io_connect: the COMBINE path is not implemented");
    }

    if (subtype == 2) {  // == _IO_CONNECT_OPEN
        const auto* open_entry = posix::SyscallRegistry::instance().find("open");
        const std::vector<std::uint64_t> open_args{static_cast<std::uint64_t>(iov1_base),
                                               static_cast<std::uint64_t>(ioflag),
                                               static_cast<std::uint64_t>(real_mode)};
        const auto fd = open_entry->handler(ql, open_args);
        auto& conn = static_cast<QlOsQnx&>(ql.os()).connections().at(static_cast<std::uint32_t>(coid));
        conn.fd = static_cast<int>(fd.value_or(-1));
    } else if (subtype == 5) {  // == _IO_CONNECT_MKNOD
        std::error_code ec;
        std::filesystem::create_directory(real_path, ec);
        if (ec) {
            throw QlErrorBase("qnx io_connect: the mknod mkdir failed");
        }
    } else {
        throw QlErrorNotImplemented("qnx io_connect: the subtype is not implemented");
    }

    // reply iov_t no. 1: the link reply (the eflag/umask from the host stat)
    const auto reply_iov_base = ql.mem().read_ptr(rmsg, 4);
    const auto reply_iov_len = ql.mem().read_ptr(rmsg + 4, 4);
    if (reply_iov_len != 20) {
        throw QlErrorBase("qnx io_connect: the reply iov_t 1 wrong size");
    }
    const auto host_path = std::filesystem::path(real_path);
    std::uint32_t umask = 0;
    if (std::filesystem::is_symlink(std::filesystem::symlink_status(host_path))) {
        umask = S_IFLNK;
    } else if (std::filesystem::is_directory(host_path)) {
        umask = S_IFDIR;
    } else if (std::filesystem::is_regular_file(host_path)) {
        umask = S_IFREG;
    }
    std::uint32_t reply_eflag = 0;
    if (std::filesystem::is_directory(host_path)) {
        reply_eflag = IO_CONNECT_EFLAG_DIR;
    } else if (path.size() >= 2 && path.compare(path.size() - 2, 2, "..") == 0) {
        reply_eflag = IO_CONNECT_EFLAG_DOTDOT;
    } else if (!path.empty() && path.back() == '.') {
        reply_eflag = IO_CONNECT_EFLAG_DOT;
    }
    // pack("<IIBBHIHH", 0, file_type, eflag, 0, 0, umask, 0, 0)
    std::array<std::uint8_t, 20> reply{};
    const auto put32 = [&reply](std::size_t off, std::uint32_t v) {
        for (int i = 0; i < 4; ++i) {
            reply[off + i] = static_cast<std::uint8_t>((v >> (8 * i)) & 0xff);
        }
    };
    const auto put16 = [&reply](std::size_t off, std::uint16_t v) {
        reply[off] = static_cast<std::uint8_t>(v & 0xff);
        reply[off + 1] = static_cast<std::uint8_t>((v >> 8) & 0xff);
    };
    put32(0, 0);
    put32(4, file_type);
    reply[8] = static_cast<std::uint8_t>(reply_eflag);
    reply[9] = 0;
    put16(10, 0);
    put32(12, umask);
    put16(16, 0);
    put16(18, 0);
    ql.mem().write(reply_iov_base, std::vector<std::uint8_t>(reply.begin(), reply.end()));
    return 0;
}

// message.py ql_qnx_msg_io_write: the write delegation
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
