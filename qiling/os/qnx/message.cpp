// Ported from qiling/os/qnx/message.py — the QNX resource-manager message
// handlers (the io_write + the sys_conf slices; the io_connect/io_read/
// io_lseek/stat and the mem families land with their fixtures).
#include "qiling/os/qnx/message.hpp"

#include "qiling/core.hpp"
#include "qiling/os/qnx/const.hpp"
#include "qiling/os/qnx/helpers.hpp"
#include "qiling/os/qnx/qnx.hpp"
#include "qiling/os/qnx/types.hpp"

#include "qiling/os/filestruct.hpp"
#include "qiling/loader/elf.hpp"

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
    {0x104, ql_qnx_msg_io_stat},       // io_stat
    {0x116, ql_qnx_msg_io_close},      // io_close
    {0x041, ql_qnx_msg_mem_ctrl},      // mem_ctrl
    {0x040, ql_qnx_msg_mem_map},       // mem_map
    {0x109, ql_qnx_msg_io_lseek},      // io_lseek
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

// mman.py syscall_mmap_impl (the qnx shape): the enclosing-page mapping with
// the unaligned base allowed (the QNX note, verbatim); the anonymous pages
// zero-fill and the file pages ride the fd's QlFile
std::optional<std::int64_t> syscall_mmap_impl(Qiling& ql, std::uint64_t addr, std::uint64_t length,
                                              std::uint64_t prot, std::uint64_t flags, std::int64_t fd,
                                              std::int64_t pgoffset) {
    const auto pagesize = ql.mem().pagesize();
    const auto mapping_size = ql.mem().align_up(length + (addr & (pagesize - 1)));

    // the mapping boundaries (the fixed base rides as-is; the QNX allows an
    // unaligned base — the enclosing pages get mapped)
    if ((flags & MMAP_MAP_FIXED) == 0) {
        const auto hint = std::max(addr, static_cast<loader::QlLoaderELF&>(ql.loader()).mmap_address());
        addr = ql.mem().find_free_space(mapping_size, hint);
    }
    const auto lbound = ql.mem().align(addr);
    const auto ubound = lbound + mapping_size;

    if ((flags & MMAP_MAP_FIXED) != 0) {
        ql.mem().unmap_between(lbound, ubound);
    }

    std::vector<std::uint8_t> data;
    if ((flags & MMAP_MAP_ANON) == 0) {
        auto* f = posix::fd_get(ql, fd).get();
        if (f == nullptr) {
            return -9;  // -EBADF
        }
        f->lseek(static_cast<std::uint64_t>(pgoffset), 0 /* SEEK_SET */);
        data = f->read(static_cast<std::size_t>(length));
    }

    // the map-then-protect shape (the write needs the write bit first)
    ql.mem().map(lbound, mapping_size, UC_PROT_ALL, "[mmap anonymous]");
    if (!data.empty()) {
        ql.mem().write(addr, data);
    }
    ql.mem().protect(lbound, mapping_size, static_cast<int>(prot));

    return static_cast<std::int64_t>(addr);
}

// message.py ql_qnx_msg_mem_ctrl (services/system/public/sys/memmsg.h): the
// flat struct read directly at smsg (24 bytes, NOT the get_message_body
// walk); the known subtype warns the not-implemented TODO and returns -1
// (the upstream TODO shape verbatim)
std::optional<std::int64_t> ql_qnx_msg_mem_ctrl(Qiling& ql, std::uint64_t coid, std::uint64_t smsg,
                                                std::int32_t sparts, std::uint64_t rmsg, std::int32_t rparts) {
    (void)coid;

    // struct _mem_ctrl in services/system/public/sys/memmsg.h:
    // (type, subtype, flags, addr, len) = unpack("<HHIQQ", read(smsg, 24))
    const auto raw = ql.mem().read(smsg, 24);
    const auto type = static_cast<std::uint16_t>(raw[0] | (raw[1] << 8));
    const auto subtype = static_cast<std::uint16_t>(raw[2] | (raw[3] << 8));

    if (sparts != -24 || rparts != 0) {
        throw QlErrorBase("qnx mem_ctrl: the input/output sizes are wrong");
    }
    if (type != 0x041) {
        throw QlErrorBase("qnx mem_ctrl: the mem_ctrl message is wrong");
    }
    if (!table_contains(mem_ctrl_subtypes, subtype)) {
        throw QlErrorNotImplemented("qnx mem_ctrl: the MEM_CTRL subtype is not implemented");
    }

    // the upstream TODO: warn + return -1
    return -1;
}

// message.py ql_qnx_msg_mem_map (services/system/public/sys/memmsg.h): the
// flat _mem_map (sparts=-56, rparts=-24); the qnx prot bits shift down eight
// to the posix spellings and the reply carries <len, addr, addr>
std::optional<std::int64_t> ql_qnx_msg_mem_map(Qiling& ql, std::uint64_t coid, std::uint64_t smsg,
                                               std::int32_t sparts, std::uint64_t rmsg, std::int32_t rparts) {
    (void)coid;

    // struct _mem_map in services/system/public/sys/memmsg.h:
    // (type, zero, reserved1, addr, len, prot, flags, fd, preload, align,
    //  offset) = unpack("<HHIQQIIiIQq", body)
    if (sparts != -56 || rparts != -24) {
        throw QlErrorBase("qnx mem_map: the input/output sizes are wrong");
    }
    const auto body = get_message_body(ql, smsg, sparts);
    const auto rd16 = [&body](std::size_t off) {
        return static_cast<std::uint16_t>(body[off] | (body[off + 1] << 8));
    };
    const auto rd32 = [&body](std::size_t off) {
        return static_cast<std::uint32_t>(body[off] | (body[off + 1] << 8) | (body[off + 2] << 16) |
                                          (static_cast<std::uint32_t>(body[off + 3]) << 24));
    };
    const auto rd64 = [&body](std::size_t off) {
        std::uint64_t v = 0;
        for (int i = 0; i < 8; ++i) {
            v |= static_cast<std::uint64_t>(body[off + i]) << (8 * i);
        }
        return v;
    };
    const auto type = rd16(0);
    const auto zero = rd16(2);
    const auto reserved1 = rd32(4);
    const auto addr = rd64(8);
    const auto len = rd64(16);
    auto prot = rd32(24);
    const auto flags = rd32(28);
    const auto fd = static_cast<std::int32_t>(rd32(32));
    const auto pgoffset = static_cast<std::int64_t>(rd64(52));

    if (type != 0x040 || zero != 0 || reserved1 != 0) {
        throw QlErrorBase("qnx mem_map: the message is wrong");
    }

    // the message fd names the connection when positive (the upstream shape)
    auto mmap_fd = static_cast<std::int64_t>(fd);
    if (fd > 0) {
        mmap_fd = *static_cast<QlOsQnx&>(ql.os()).connections().at(static_cast<std::uint32_t>(fd)).fd;
    }

    // map the qnx protection bits to the posix ones
    prot >>= 8;

    const auto ret = syscall_mmap_impl(ql, addr, len, prot, flags, mmap_fd, pgoffset);

    // struct _mem_map_reply: pack("<QQQ", len, ret, ret)
    const auto put64 = [rmsg, &ql](std::size_t off, std::uint64_t v) {
        std::array<std::uint8_t, 8> cell{};
        for (int i = 0; i < 8; ++i) {
            cell[i] = static_cast<std::uint8_t>((v >> (8 * i)) & 0xff);
        }
        ql.mem().write(rmsg + off, std::vector<std::uint8_t>(cell.begin(), cell.end()));
    };
    put64(0, len);
    put64(8, static_cast<std::uint64_t>(ret.value_or(0)));
    put64(16, static_cast<std::uint64_t>(ret.value_or(0)));
    return 0;
}

// message.py ql_qnx_msg_io_stat (lib/c/1/fstat.c): the flat _io_stat
// (sparts=-8, rparts=-72); the fd resolves through the connection and the
// host stat packs the QNXARMStat layout (the _pack_=4 18-cell layout,
// the hi cells zero) at rmsg
std::optional<std::int64_t> ql_qnx_msg_io_stat(Qiling& ql, std::uint64_t coid, std::uint64_t smsg,
                                               std::int32_t sparts, std::uint64_t rmsg, std::int32_t rparts) {
    // struct _io_stat in lib/c/public/sys/iomsg.h:
    // (type, combine_len, zero) = unpack("<HHI", smsg, 8)
    const auto hdr = ql.mem().read(smsg, 8);
    const auto type = static_cast<std::uint16_t>(hdr[0] | (hdr[1] << 8));
    const auto combine_len = static_cast<std::uint16_t>(hdr[2] | (hdr[3] << 8));
    const auto zero = static_cast<std::uint32_t>(hdr[4] | (hdr[5] << 8) | (hdr[6] << 16) |
                                                 (static_cast<std::uint32_t>(hdr[7]) << 24));

    if (sparts != -8 || rparts != -72) {
        throw QlErrorBase("qnx io_stat: the input/output sizes are wrong");
    }
    if (type != 0x104 || combine_len != 8 || zero != 0) {
        throw QlErrorBase("qnx io_stat: the message is wrong");
    }

    const auto fd = static_cast<std::int64_t>(
        *static_cast<QlOsQnx&>(ql.os()).connections().at(static_cast<std::uint32_t>(coid)).fd);
    auto* f = posix::fd_get(ql, fd).get();
    if (f == nullptr) {
        return -EBADF;
    }
    auto st = host_fstat_fd(f->fileno());

    // the QNXARMStat cells (stat.py, the _pack_=4 layout verbatim): ino,
    // ino_hi, size, size_hi, dev, rdev, uid, gid, mtime, atime, ctime, mode,
    // nlink, blksize, blocks, blksize, blocks, blocks_hi
    const auto put32 = [rmsg, &ql](std::size_t off, std::uint64_t v) {
        std::array<std::uint8_t, 4> cell{};
        for (int i = 0; i < 4; ++i) {
            cell[i] = static_cast<std::uint8_t>((v >> (8 * i)) & 0xff);
        }
        ql.mem().write(rmsg + off, std::vector<std::uint8_t>(cell.begin(), cell.end()));
    };
    put32(0, st.ino);
    put32(4, 0);  // st_ino_hi
    put32(8, st.size);
    put32(12, 0);  // st_size_hi
    put32(16, st.dev);
    put32(20, st.rdev);
    put32(24, st.uid);
    put32(28, st.gid);
    put32(32, static_cast<std::uint64_t>(st.mtime));
    put32(36, static_cast<std::uint64_t>(st.atime));
    put32(40, static_cast<std::uint64_t>(st.ctime));
    put32(44, st.mode);
    put32(48, st.nlink);
    put32(52, static_cast<std::uint64_t>(st.blksize));
    put32(56, static_cast<std::uint64_t>(st.blocks));
    put32(60, static_cast<std::uint64_t>(st.blksize));
    put32(64, static_cast<std::uint64_t>(st.blocks));
    put32(68, 0);  // st_blocks_hi

    return 0;
}

// message.py ql_qnx_msg_io_lseek (lib/c/1/lseek.c): the flat _io_lseek
// (sparts=-16, rparts=-8); the whence goes through the posix lseek and the
// 8-byte position lands at rmsg
std::optional<std::int64_t> ql_qnx_msg_io_lseek(Qiling& ql, std::uint64_t coid, std::uint64_t smsg,
                                                std::int32_t sparts, std::uint64_t rmsg, std::int32_t rparts) {
    // struct _io_lseek in lib/c/public/sys/iomsg.h:
    // (type, combine_len, whence, zero, offset) = unpack("<HHhHQ", smsg, 16)
    const auto hdr = ql.mem().read(smsg, 16);
    const auto rd16 = [&hdr](std::size_t off) {
        return static_cast<std::uint16_t>(hdr[off] | (hdr[off + 1] << 8));
    };
    const auto type = rd16(0);
    const auto combine_len = rd16(2);
    const auto whence = static_cast<std::int16_t>(rd16(4));
    const auto zero = rd16(6);
    std::uint64_t offset = 0;
    for (int i = 0; i < 8; ++i) {
        offset |= static_cast<std::uint64_t>(hdr[8 + i]) << (8 * i);
    }

    if (sparts != -16 || rparts != -8) {
        throw QlErrorBase("qnx io_lseek: the input/output sizes are wrong");
    }
    if (type != 0x109 || combine_len != 16 || zero != 0) {
        throw QlErrorBase("qnx io_lseek: the message is wrong");
    }
    if (!table_contains(lseek_whence, static_cast<unsigned>(whence))) {
        throw QlErrorNotImplemented("qnx io_lseek: unknown lseek direction");
    }

    auto& conn = static_cast<QlOsQnx&>(ql.os()).connections().at(static_cast<std::uint32_t>(coid));
    const auto* lseek_entry = posix::SyscallRegistry::instance().find("lseek");
    const std::vector<std::uint64_t> lseek_args{static_cast<std::uint64_t>(*conn.fd),
                                                static_cast<std::uint64_t>(offset),
                                                static_cast<std::uint64_t>(whence)};
    const auto regreturn = lseek_entry->handler(ql, lseek_args);

    // the 8-byte position at the reply
    ql.mem().write_ptr(rmsg, regreturn.value_or(0), 8);
    return 0;
}

// message.py ql_qnx_msg_io_write: the write delegation — the header rides
// iov[0] and the payload rides iov[1] (the smsg+8 dword); the combine and
// the xtype paths are not implemented (the upstream raise shape)
// message.py ql_qnx_msg_io_close (lib/c/1/close.c): the fd rides the
// connection, the conn's fd clears first (the upstream shape), and the
// posix close body does the rest; the fd-less conn rides the upstream's
// None-in-range fall-through to -EBADF
std::optional<std::int64_t> ql_qnx_msg_io_close(Qiling& ql, std::uint64_t coid, std::uint64_t smsg,
                                                std::int32_t sparts, std::uint64_t rmsg, std::int32_t rparts) {
    (void)smsg;
    (void)sparts;
    (void)rmsg;
    (void)rparts;

    auto& conn = static_cast<QlOsQnx&>(ql.os()).connections().at(static_cast<std::uint32_t>(coid));
    const auto fd = conn.fd;
    conn.fd = std::nullopt;
    if (!fd.has_value()) {
        return -EBADF;
    }
    return posix::do_close(ql, *fd);
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
