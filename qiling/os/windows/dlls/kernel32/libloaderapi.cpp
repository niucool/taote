// Ported from qiling/os/windows/dlls/kernel32/libloaderapi.py — the library
// loader family (the GetModuleHandle trio, the GetModuleFileName pair, the
// GetProcAddress with the ordinal/self-module branches, the LoadLibrary
// quartet, the resource pass bodies, and the FreeLibrary miscellany). The
// @winsdkapi decorators map onto register_libloaderapi_family(); the bodies
// ride the verbatim upstream walks over the loader surface. The family
// self-registers at static-init and can be re-seeded after ApiRegistry::
// clear() (the test isolation).
#include "qiling/core.hpp"
#include "qiling/loader/pe.hpp"
#include "qiling/os/utils.hpp"
#include "qiling/os/windows/api.hpp"
#include "qiling/os/windows/const.hpp"
#include "qiling/os/windows/fncc.hpp"
#include "qiling/os/windows/windows.hpp"

#include <string>

namespace qiling {
namespace os {
namespace win {

namespace {

// the w() accessor rides the fileapi.cpp definition (the family TUs share
// one TU via the dlls.cpp include chain)

loader::QlLoaderPE& pe_loader(Qiling& ql) {
    return static_cast<loader::QlLoaderPE&>(ql.loader());
}

// the shared _GetModuleHandle body (the utils.has_lib_ext walk)
std::optional<std::uint64_t> get_module_handle_body(Qiling& ql, const ResolvedParams& params) {
    // the upstream's `if lpModuleName == 0` walk: the NULL module name
    // arrives as the raw int (the zero guard in resolve_fcall_params); the
    // string-typed entries carry the decoded name — the cstring read at 0
    // would fault
    const auto& lp_param = get_param(params, "lpModuleName");
    bool null_name = false;
    if (const auto* v = std::get_if<std::uint64_t>(&lp_param.second)) {
        null_name = (*v == 0);
    }

    std::uint64_t ret = 0;
    if (null_name) {
        ret = pe_loader(ql).pe_image_address();
    } else {
        std::string module = api_get_string(ql, lp_param);
        // utils.py has_lib_ext: the dll/exe/sys/drv suffix check
        const auto dot = module.rfind('.');
        const std::string ext = dot == std::string::npos ? std::string() : module.substr(dot + 1);
        std::string lower = ext;
        for (auto& c : lower) {
            c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        }
        if (!(lower == "dll" || lower == "exe" || lower == "sys" || lower == "drv")) {
            module += ".dll";
        }

        const auto* image = pe_loader(ql).get_image_by_name(module, true);

        if (image != nullptr) {
            ret = image->base;
        } else {
            // f'Library "{module}" not imported' (the debug log)
            ret = 0;
        }
    }

    return ret;
}

// the shared __GetModuleFileName body
std::optional<std::uint64_t> get_module_file_name_body(Qiling& ql, const ResolvedParams& params, const bool wide) {
    const auto h_module = api_get_int(get_param(params, "hModule"));
    const auto lp_filename = api_get_int(get_param(params, "lpFilename"));
    const auto n_size = api_get_int(get_param(params, "nSize"));

    std::uint64_t module = h_module;
    if (module == 0) {
        if (!ql.code().empty()) {
            throw QlErrorNotImplemented("cannot retrieve module file name in shellcode mode");
        }

        module = pe_loader(ql).pe_image_address();
    }

    const loader::Image* image = nullptr;
    for (const auto& img : pe_loader(ql).images) {
        if (img.base == module) {
            image = &img;
            break;
        }
    }

    if (image == nullptr) {
        w(ql).set_last_error(ERROR_INVALID_HANDLE);
        return 0;
    }

    // encname = 'utf-16le' if wide else 'latin'
    const auto vpath = w(ql).path()->host_to_virtual_path(image->path);
    auto truncated = vpath.substr(0, static_cast<std::size_t>(n_size > 0 ? n_size - 1 : 0));
    truncated.push_back('\0');
    std::string encoded;
    if (wide) {
        for (const char c : truncated) {
            encoded.push_back(c);
            encoded.push_back('\0');
        }
    } else {
        encoded = truncated;
    }

    if (vpath.size() + 1 > static_cast<std::size_t>(n_size)) {
        w(ql).set_last_error(ERROR_INSUFFICIENT_BUFFER);
    }

    ql.mem().write(lp_filename, std::vector<std::uint8_t>(encoded.begin(), encoded.end()));

    return std::min(vpath.size(), static_cast<std::size_t>(n_size));
}

// the shared _LoadLibrary body
std::optional<std::uint64_t> load_library_body(Qiling& ql, const ResolvedParams& params) {
    const auto lp_lib_file_name = api_get_string(ql, get_param(params, "lpLibFileName"));

    // TODO: this searches only by basename; do we need to search by full
    // path as well?  (verbatim)
    if (const auto* dll = pe_loader(ql).get_image_by_name(lp_lib_file_name, true)) {
        return dll->base;
    }

    return pe_loader(ql).load_dll(lp_lib_file_name);
}

// the shared _LoadLibraryEx body
std::optional<std::uint64_t> load_library_ex_body(Qiling& ql, const ResolvedParams& params) {
    const auto lp_lib_file_name = api_get_string(ql, get_param(params, "lpLibFileName"));

    return pe_loader(ql).load_dll(lp_lib_file_name);
}

}  // namespace

void register_libloaderapi_family() {
    using namespace qiling::os::api;

    // HMODULE GetModuleHandleA(
    //   LPCSTR lpModuleName
    // );
    WinsdkApi("GetModuleHandleA", WinCc::Stdcall, {
        {"lpModuleName", LPCSTR_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        return get_module_handle_body(ql, params);
    };

    // HMODULE GetModuleHandleW(
    //   LPCWSTR lpModuleName
    // );
    WinsdkApi("GetModuleHandleW", WinCc::Stdcall, {
        {"lpModuleName", LPCWSTR_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        return get_module_handle_body(ql, params);
    };

    // BOOL GetModuleHandleExW(
    //   DWORD   dwFlags,
    //   LPCWSTR lpModuleName,
    //   HMODULE *phModule
    // );
    WinsdkApi("GetModuleHandleExW", WinCc::Stdcall, {
        {"dwFlags", DWORD_},
        {"lpModuleName", LPCWSTR_},
        {"phModule", LPVOID_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        const auto res = get_module_handle_body(ql, params);
        const auto dst = api_get_int(get_param(params, "phModule"));

        if (dst != 0 && res.has_value()) {
            ql.mem().write_ptr(dst, *res);
        }

        return res;
    };

    // DWORD GetModuleFileNameA(
    //   HMODULE hModule,
    //   LPSTR   lpFilename,
    //   DWORD   nSize
    // );
    WinsdkApi("GetModuleFileNameA", WinCc::Stdcall, {
        {"hModule", HANDLE_},
        {"lpFilename", LPVOID_},
        {"nSize", DWORD_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        return get_module_file_name_body(ql, params, false);
    };

    // DWORD GetModuleFileNameW(
    //   HMODULE hModule,
    //   LPSTR   lpFilename,
    //   DWORD   nSize
    // );
    WinsdkApi("GetModuleFileNameW", WinCc::Stdcall, {
        {"hModule", HANDLE_},
        {"lpFilename", LPVOID_},
        {"nSize", DWORD_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        return get_module_file_name_body(ql, params, true);
    };

    // FARPROC GetProcAddress(
    //   HMODULE hModule,
    //   LPCSTR  lpProcName
    // );
    WinsdkApi("GetProcAddress", WinCc::Stdcall, {
        {"hModule", HANDLE_},
        {"lpProcName", LPVOID_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        const auto h_module = api_get_int(get_param(params, "hModule"));
        const auto lp_proc_name = api_get_int(get_param(params, "lpProcName"));

        std::string procname;
        std::uint64_t ordinal = 0;
        bool by_name = false;

        // if lpProcName is a short integer, it is an ordinal. otherwise,
        // that is a function name.
        if (lp_proc_name > MAXUSHORT) {
            procname = QlOsUtils::read_cstring(ql, lp_proc_name);
            by_name = true;
        } else {
            ordinal = lp_proc_name;
        }

        // get dll name by handle (module base)
        std::optional<std::string> dll_name;
        for (const auto& image : pe_loader(ql).images) {
            if (image.base == h_module) {
                const std::filesystem::path p(image.path);
                std::string base = p.filename().string();
                for (auto& c : base) {
                    c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
                }
                dll_name = base;
                break;
            }
        }

        if (!dll_name.has_value()) {
            // f'Failed to import function "{lpProcName}" with handle {hModule:#x}'
            return 0;
        }

        // Handle case where module is self: the main image's export table
        const std::filesystem::path self_path(ql.path());
        std::string self_name = self_path.filename().string();
        for (auto& c : self_name) {
            c = static_cast<char>(std::tolower(static_cast<unsigned char>(c)));
        }

        if (dll_name == self_name) {
            if (by_name) {
                for (const auto& [ea, entry] : pe_loader(ql).export_symbols()) {
                    if (entry.name == procname) {
                        return ea;
                    }
                }
            } else {
                for (const auto& [ea, entry] : pe_loader(ql).export_symbols()) {
                    if (entry.ordinal == ordinal) {
                        return ea;
                    }
                }
            }

            return 0;
        }

        // in any other case, look through the import address table for that dll
        const auto* iat = pe_loader(ql).import_address_table_at(*dll_name);
        if (iat == nullptr) {
            return 0;
        }

        return by_name ? iat->lookup(procname) : iat->lookup(ordinal);
    };

    // HMODULE LoadLibraryA(
    //   LPCSTR lpLibFileName
    // );
    WinsdkApi("LoadLibraryA", WinCc::Stdcall, {
        {"lpLibFileName", LPCSTR_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        return load_library_body(ql, params);
    };

    // HMODULE LoadLibraryExA(
    //   LPCSTR lpLibFileName,
    //   HANDLE hFile,
    //   DWORD  dwFlags
    // );
    WinsdkApi("LoadLibraryExA", WinCc::Stdcall, {
        {"lpLibFileName", LPCSTR_},
        {"hFile", HANDLE_},
        {"dwFlags", DWORD_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        return load_library_ex_body(ql, params);
    };

    // HMODULE LoadLibraryW(
    //   LPCWSTR lpLibFileName
    // );
    WinsdkApi("LoadLibraryW", WinCc::Stdcall, {
        {"lpLibFileName", LPCWSTR_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        return load_library_body(ql, params);
    };

    // HMODULE LoadLibraryExW(
    //   LPCSTR lpLibFileName,
    //   HANDLE hFile,
    //   DWORD  dwFlags
    // );
    WinsdkApi("LoadLibraryExW", WinCc::Stdcall, {
        {"lpLibFileName", LPCWSTR_},
        {"hFile", HANDLE_},
        {"dwFlags", DWORD_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        return load_library_ex_body(ql, params);
    };

    // DWORD SizeofResource(
    //   HMODULE hModule,
    //   HRSRC   hResInfo
    // );
    WinsdkApi("SizeofResource", WinCc::Stdcall, {
        {"hModule", HANDLE_},
        {"hResInfo", HANDLE_},
    }) = [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        // Return size of resource
        // TODO set a valid value. More tests have to be made to find it.  (verbatim)
        return 0x8;
    };

    // HGLOBAL LoadResource(
    //   HMODULE hModule,
    //   HRSRC   hResInfo
    // );
    WinsdkApi("LoadResource", WinCc::Stdcall, {
        {"hModule", HANDLE_},
        {"hResInfo", HANDLE_},
    }) = [](Qiling&, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        return api_get_int(get_param(params, "hResInfo"));
    };

    // LPVOID LockResource(
    //   HGLOBAL hResData
    // );
    WinsdkApi("LockResource", WinCc::Stdcall, {
        {"hResData", HANDLE_},
    }) = [](Qiling&, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        return api_get_int(get_param(params, "hResData"));
    };

    // BOOL DisableThreadLibraryCalls(
    //  HMODULE hLibModule
    // );
    WinsdkApi("DisableThreadLibraryCalls", WinCc::Stdcall, {
        {"hLibModule", HANDLE_},
    }) = [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        return 1;
    };

    // BOOL FreeLibrary(
    //   HMODULE hLibModule
    // );
    WinsdkApi("FreeLibrary", WinCc::Stdcall, {
        {"hLibModule", HANDLE_},
    }) = [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        return 1;
    };

    // BOOL SetDefaultDllDirectories(
    //   DWORD DirectoryFlags
    // );
    WinsdkApi("SetDefaultDllDirectories", WinCc::Stdcall, {
        {"DirectoryFlags", DWORD_},
    }) = [](Qiling&, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        const auto value = api_get_int(get_param(params, "DirectoryFlags"));

        if (value == LOAD_LIBRARY_SEARCH_USER_DIRS) {
            // TODO we have to probably set an handler for this, since it can
            // be a not default value. And we have to change the default path
            // of load  (verbatim)
            throw QlErrorNotImplemented("API not implemented");
        }

        return 1;
    };
}

}  // namespace win
}  // namespace os
}  // namespace qiling

// the static-init registration (the python module-import side effect)
namespace {
const bool kLibloaderapiRegistered = [] {
    qiling::os::win::register_libloaderapi_family();
    return true;
}();
}  // namespace
