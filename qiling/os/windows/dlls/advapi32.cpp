// Ported from qiling/os/windows/dlls/advapi32.py — the registry family (the
// Reg* cycle over the RegistryManager + the profile REGISTRY keys). The
// @winsdkapi decorators map onto register_advapi32_family(); the bodies ride
// the verbatim upstream walks. The token/SID and the SC-manager families
// land in the following sub-slices. The family self-registers at static-init
// and can be re-seeded after ApiRegistry::clear() (the test isolation).
#include "qiling/core.hpp"
#include "qiling/os/windows/api.hpp"
#include "qiling/os/windows/const.hpp"
#include "qiling/os/windows/fncc.hpp"
#include "qiling/os/windows/registry.hpp"
#include "qiling/os/windows/structs.hpp"
#include "qiling/os/windows/windows.hpp"

#include <string>
#include <memory>

namespace qiling {
namespace os {
namespace win {

namespace {

// the w() accessor rides the fileapi.cpp definition (the family TUs share
// one TU via the dlls.cpp include chain)

// the verbatim __RegOpenKey body
std::optional<std::uint64_t> reg_open_key(Qiling& ql, const ResolvedParams& params) {
    const auto h_key = api_get_int(get_param(params, "hKey"));
    const auto lp_sub_key = api_get_string(ql, get_param(params, "lpSubKey"));
    const auto phk_result = api_get_int(get_param(params, "phkResult"));

    auto* handle = w(ql).handle_manager().get(h_key);

    if (handle == nullptr || handle->name.rfind("HKEY", 0) != 0) {
        return ERROR_FILE_NOT_FOUND;
    }

    if (!lp_sub_key.empty()) {
        const auto key = handle->name + "\\" + lp_sub_key;

        // Keys in the profile are saved as KEY\PARAM = VALUE, so i just want
        // to check that the key is the same  (verbatim)
        std::string key_casefold;
        for (const char c : key) {
            key_casefold.push_back(static_cast<char>(std::tolower(static_cast<unsigned char>(c))));
        }

        bool profile_hit = false;
        for (const auto& entry : ql.profile().option_keys("REGISTRY")) {
            if (entry == key_casefold) {
                profile_hit = true;
                break;
            }
        }

        if (profile_hit) {
            ql.log().debug("Using profile for key of  " + key);
            w(ql).registry_manager().access(key);
        } else {
            if (!w(ql).registry_manager().exists(key)) {
                ql.log().debug("Value key " + key + " not present");
                return ERROR_FILE_NOT_FOUND;
            }
        }

        // new handle
        Handle new_handle(std::nullopt, nullptr, key);
        w(ql).handle_manager().append(new_handle);
        handle = w(ql).handle_manager().get(new_handle.id);
    }

    if (phk_result != 0) {
        ql.mem().write_ptr(phk_result, handle->id);
    }

    return ERROR_SUCCESS;
}

// the handle->name accessor (the s_hKey rebinding walks)
std::string reg_key_name(Qiling& ql, std::uint64_t h_key) {
    auto* handle = w(ql).handle_manager().get(h_key);
    return handle != nullptr ? handle->name : std::string();
}

// the verbatim __RegQueryValue body (the wstring split rides the marshal)
std::optional<std::uint64_t> reg_query_value(Qiling& ql, const ResolvedParams& params, const bool wide) {
    const auto h_key = api_get_int(get_param(params, "hKey"));
    const auto lp_value_name = api_get_string(ql, get_param(params, "lpValueName"));
    const auto lp_type = api_get_int(get_param(params, "lpType"));
    const auto lp_data = api_get_int(get_param(params, "lpData"));
    const auto lpcb_data = api_get_int(get_param(params, "lpcbData"));

    auto ret = static_cast<std::uint64_t>(ERROR_SUCCESS);

    const auto s_hkey = reg_key_name(ql, h_key);

    // read reg_type  (verbatim: the RegNone when lpType is null)
    auto reg_type = lp_type == 0 ? static_cast<int>(qiling::os::RegType::RegNone)
                                 : static_cast<int>(ql.mem().read_ptr(lp_type, 4));

    // try reading the registry key value from profile first.
    // if the key is not specified in profile, proceed to registry manager
    // (verbatim comment)
    const auto keyname = s_hkey + "\\" + lp_value_name;
    auto value = ql.profile().get("REGISTRY", keyname);

    if (!value.has_value()) {
        int read_type = reg_type;
        auto read = w(ql).registry_manager().read(s_hkey, lp_value_name, read_type);
        reg_type = read.first.value_or(-1);
        if (read.second.has_value()) {
            const auto& rv = *read.second;
            if (const auto* s = std::get_if<std::string>(&rv)) {
                value = *s;
            } else if (const auto* b = std::get_if<std::vector<std::uint8_t>>(&rv)) {
                value = std::string(b->begin(), b->end());
            } else if (const auto* n = std::get_if<std::int64_t>(&rv)) {
                value = std::to_string(*n);
            }
        }
    } else {
        ql.log().debug("Value for " + keyname + " was read from profile");
        reg_type = static_cast<int>(qiling::os::RegType::RegSZ);
        // set that the registry has been accessed
        w(ql).registry_manager().access(s_hkey, lp_value_name, reg_type, value);
    }

    // error key
    if (reg_type < 0 || !value.has_value()) {
        ql.log().debug("Key value not found");
        return ERROR_FILE_NOT_FOUND;
    }

    // read how many bytes we are allowed to write into lpData, however
    // this arg is optional  (verbatim)
    std::uint64_t max_size = 0;
    if (lpcb_data != 0) {
        max_size = ql.mem().read_ptr(lpcb_data, 4);
    } else {
        // lpcbData may be null only if lpData is also null. if lpData is
        // allocated, but lpcbData is set to null, it means we have an out
        // buffer without knowing its size  (verbatim)
        if (lp_data != 0) {
            return ERROR_INVALID_PARAMETER;
        }
    }

    // set lpData
    os::RegValue reg_value = *value;
    const auto length = registry::RegistryManager::write_reg_value_into_mem(
        reg_type, lp_data, reg_value, max_size, wide, ql);

    // set lpcbData
    if (lpcb_data != 0) {
        ql.mem().write_ptr(lpcb_data, length, 4);
    }

    if (max_size < length) {
        ret = ERROR_MORE_DATA;
    }

    return ret;
}

// the verbatim __RegCreateKey body
std::optional<std::uint64_t> reg_create_key(Qiling& ql, const ResolvedParams& params) {
    const auto h_key = api_get_int(get_param(params, "hKey"));
    const auto lp_sub_key = api_get_string(ql, get_param(params, "lpSubKey"));
    const auto phk_result = api_get_int(get_param(params, "phkResult"));

    auto* handle = w(ql).handle_manager().get(h_key);

    if (handle == nullptr || handle->name.rfind("HKEY", 0) != 0) {
        return ERROR_FILE_NOT_FOUND;
    }

    if (!lp_sub_key.empty()) {
        const auto keyname = handle->name + "\\" + lp_sub_key;

        if (!w(ql).registry_manager().exists(keyname)) {
            w(ql).registry_manager().create(keyname);
        }

        auto* existing = w(ql).handle_manager().search_by_obj(const_cast<void*>(static_cast<const void*>(keyname.c_str())));

        // make sure we have a handle for this keyname  (verbatim)
        if (existing == nullptr) {
            Handle new_handle(std::nullopt, nullptr, keyname);
            w(ql).handle_manager().append(new_handle);
            existing = w(ql).handle_manager().get(new_handle.id);
        }
        handle = existing;
    }

    if (phk_result != 0) {
        ql.mem().write_ptr(phk_result, handle->id);
    }

    return ERROR_SUCCESS;
}

// the verbatim __RegSetValue body (the dwType expected REG_SZ)
std::optional<std::uint64_t> reg_set_value(Qiling& ql, const ResolvedParams& params, const bool wide) {
    const auto h_key = api_get_int(get_param(params, "hKey"));
    const auto lp_sub_key = api_get_string(ql, get_param(params, "lpSubKey"));
    const auto dw_type = static_cast<int>(api_get_int(get_param(params, "dwType")));
    const auto lp_data = api_get_int(get_param(params, "lpData"));
    const auto cb_data = api_get_int(get_param(params, "cbData"));

    const auto s_hkey = reg_key_name(ql, h_key);

    if (lp_data == 0) {
        return ERROR_INVALID_PARAMETER;
    }

    // dwType is expected to be REG_SZ and lpData to point to a
    // null-terminated string  (verbatim)
    w(ql).registry_manager().write(s_hkey, lp_sub_key, dw_type, lp_data, static_cast<std::uint64_t>(cb_data), wide);

    return ERROR_SUCCESS;
}

// the verbatim __RegSetValueEx body
std::optional<std::uint64_t> reg_set_value_ex(Qiling& ql, const ResolvedParams& params, const bool wide) {
    const auto h_key = api_get_int(get_param(params, "hKey"));
    const auto lp_value_name = api_get_string(ql, get_param(params, "lpValueName"));
    const auto dw_type = static_cast<int>(api_get_int(get_param(params, "dwType")));
    const auto lp_data = api_get_int(get_param(params, "lpData"));
    const auto cb_data = api_get_int(get_param(params, "cbData"));

    const auto s_hkey = reg_key_name(ql, h_key);

    if (lp_data == 0) {
        return ERROR_INVALID_PARAMETER;
    }

    w(ql).registry_manager().write(s_hkey, lp_value_name, dw_type, lp_data, static_cast<std::uint64_t>(cb_data), wide);

    return ERROR_SUCCESS;
}

// the verbatim __RegDeleteKey body
std::optional<std::uint64_t> reg_delete_key(Qiling& ql, const ResolvedParams& params) {
    const auto h_key = api_get_int(get_param(params, "hKey"));
    const auto lp_sub_key = api_get_string(ql, get_param(params, "lpSubKey"));

    const auto s_hkey = reg_key_name(ql, h_key);

    w(ql).registry_manager().delete_entry(s_hkey, lp_sub_key);

    return ERROR_SUCCESS;
}

// the verbatim __RegDeleteValue body
std::optional<std::uint64_t> reg_delete_value(Qiling& ql, const ResolvedParams& params) {
    const auto h_key = api_get_int(get_param(params, "hKey"));
    const auto lp_value_name = api_get_string(ql, get_param(params, "lpValueName"));

    const auto s_hkey = reg_key_name(ql, h_key);

    w(ql).registry_manager().delete_entry(s_hkey, lp_value_name);

    return ERROR_SUCCESS;
}

}  // namespace

// the token/SID + the SC-manager registration entry (the shared body lambdas
// live above; the verbatim python module surfaces both families through the
// single advapi32.py import)
void register_advapi32_token_sc_families();

void register_advapi32_family() {
    using namespace qiling::os::api;

    // LSTATUS RegOpenKeyExA( ... ) — the four RegOpenKey flavours share the
    // body (the W flavours ride the resolved wstring)
    WinsdkApi("RegOpenKeyExA", WinCc::Stdcall, {
        {"hKey", HKEY_},
        {"lpSubKey", LPCSTR_},
        {"ulOptions", DWORD_},
        {"samDesired", DWORD_},
        {"phkResult", PVOID_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        return reg_open_key(ql, params);
    };

    WinsdkApi("RegOpenKeyExW", WinCc::Stdcall, {
        {"hKey", HKEY_},
        {"lpSubKey", LPCWSTR_},
        {"ulOptions", DWORD_},
        {"samDesired", DWORD_},
        {"phkResult", PVOID_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        return reg_open_key(ql, params);
    };

    WinsdkApi("RegOpenKeyW", WinCc::Stdcall, {
        {"hKey", HKEY_},
        {"lpSubKey", LPCWSTR_},
        {"phkResult", PVOID_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        return reg_open_key(ql, params);
    };

    WinsdkApi("RegOpenKeyA", WinCc::Stdcall, {
        {"hKey", HKEY_},
        {"lpSubKey", LPCSTR_},
        {"phkResult", PVOID_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        return reg_open_key(ql, params);
    };

    // LSTATUS RegQueryValueExA( ... ) / RegQueryValueExW( ... )
    WinsdkApi("RegQueryValueExA", WinCc::Stdcall, {
        {"hKey", HKEY_},
        {"lpValueName", LPCSTR_},
        {"lpReserved", PVOID_},
        {"lpType", PVOID_},
        {"lpData", PVOID_},
        {"lpcbData", PVOID_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        return reg_query_value(ql, params, false);
    };

    WinsdkApi("RegQueryValueExW", WinCc::Stdcall, {
        {"hKey", HKEY_},
        {"lpValueName", LPCWSTR_},
        {"lpReserved", PVOID_},
        {"lpType", PVOID_},
        {"lpData", PVOID_},
        {"lpcbData", PVOID_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        return reg_query_value(ql, params, true);
    };

    // LSTATUS RegCloseKey( HKEY hKey );
    WinsdkApi("RegCloseKey", WinCc::Stdcall, {
        {"hKey", HKEY_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        const auto h_key = api_get_int(get_param(params, "hKey"));
        w(ql).handle_manager().delete_handle(h_key);

        return ERROR_SUCCESS;
    };

    // LSTATUS RegCreateKeyA( ... ) / RegCreateKeyW( ... )
    WinsdkApi("RegCreateKeyA", WinCc::Stdcall, {
        {"hKey", HKEY_},
        {"lpSubKey", LPCSTR_},
        {"phkResult", PVOID_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        return reg_create_key(ql, params);
    };

    WinsdkApi("RegCreateKeyW", WinCc::Stdcall, {
        {"hKey", HKEY_},
        {"lpSubKey", LPCWSTR_},
        {"phkResult", PVOID_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        return reg_create_key(ql, params);
    };

    // LSTATUS RegCreateKeyExW( ... ) — the verbatim fallback to the simple
    // body
    WinsdkApi("RegCreateKeyExW", WinCc::Stdcall, {
        {"hKey", HKEY_},
        {"lpSubKey", LPCWSTR_},
        {"Reserved", DWORD_},
        {"lpClass", LPWSTR_},
        {"dwOptions", DWORD_},
        {"samDesired", DWORD_},
        {"lpSecurityAttributes", PVOID_},
        {"phkResult", PVOID_},
        {"lpdwDisposition", PVOID_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        // fall back to the simple implementation  (verbatim)
        return reg_create_key(ql, params);
    };

    // LSTATUS RegSetValueA( ... ) / RegSetValueW( ... )
    WinsdkApi("RegSetValueA", WinCc::Stdcall, {
        {"hKey", HKEY_},
        {"lpSubKey", LPCSTR_},
        {"dwType", DWORD_},
        {"lpData", LPCSTR_},
        {"cbData", DWORD_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        return reg_set_value(ql, params, false);
    };

    WinsdkApi("RegSetValueW", WinCc::Stdcall, {
        {"hKey", HKEY_},
        {"lpSubKey", LPCWSTR_},
        {"dwType", DWORD_},
        {"lpData", LPCWSTR_},
        {"cbData", DWORD_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        // the verbatim wstring=False (the W flavour rides the narrow write)
        return reg_set_value(ql, params, false);
    };

    // LSTATUS RegSetValueExA( ... ) / RegSetValueExW( ... )
    WinsdkApi("RegSetValueExA", WinCc::Stdcall, {
        {"hKey", HKEY_},
        {"lpValueName", LPCSTR_},
        {"Reserved", DWORD_},
        {"dwType", DWORD_},
        {"lpData", PVOID_},
        {"cbData", DWORD_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        return reg_set_value_ex(ql, params, false);
    };

    WinsdkApi("RegSetValueExW", WinCc::Stdcall, {
        {"hKey", HKEY_},
        {"lpValueName", LPCWSTR_},
        {"Reserved", DWORD_},
        {"dwType", DWORD_},
        {"lpData", PVOID_},
        {"cbData", DWORD_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        return reg_set_value_ex(ql, params, true);
    };

    // LSTATUS RegDeleteKeyA( ... ) / RegDeleteKeyW( ... )
    WinsdkApi("RegDeleteKeyA", WinCc::Stdcall, {
        {"hKey", HKEY_},
        {"lpSubKey", LPCSTR_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        return reg_delete_key(ql, params);
    };

    WinsdkApi("RegDeleteKeyW", WinCc::Stdcall, {
        {"hKey", HKEY_},
        {"lpSubKey", LPCWSTR_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        return reg_delete_key(ql, params);
    };

    // LSTATUS RegDeleteValueA( ... ) / RegDeleteValueW( ... )
    WinsdkApi("RegDeleteValueA", WinCc::Stdcall, {
        {"hKey", HKEY_},
        {"lpValueName", LPCSTR_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        return reg_delete_value(ql, params);
    };

    WinsdkApi("RegDeleteValueW", WinCc::Stdcall, {
        {"hKey", HKEY_},
        {"lpValueName", LPCWSTR_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        return reg_delete_value(ql, params);
    };

    WinsdkApi("RegEnumValueA", WinCc::Stdcall, {
        {"hKey", HKEY_},
        {"dwIndex", DWORD_},
        {"lpValueName", LPSTR_},
        {"lpcchValueName", PVOID_},
        {"lpReserved", PVOID_},
        {"lpType", PVOID_},
        {"lpData", PVOID_},
        {"lpcbData", PVOID_},
    }) = [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        return ERROR_NO_MORE_ITEMS;
    };

    // the token/SID + the SC-manager handlers ride the same registration
    register_advapi32_token_sc_families();
}

// ---- sub-slice B: the token/SID and the SC-manager families (the shared
// body lambdas live here) ----

// the SID image builder (structs.py make_sid(auth_count): the Revision u8,
// the SubAuthorityCount u8, the IdentifierAuthority BaseStructEB Value u32
// big-endian + the 2-pad — the (5,) tuple fills the Value's first byte — and
// the SubAuthority[count] u32 LE)
std::string make_sid_image(const std::vector<std::uint32_t>& subauths) {
    std::string sid(8 + 4 * subauths.size(), '\0');
    sid[0] = '\x01';  // Revision
    sid[1] = static_cast<char>(subauths.size());
    // the IdentifierAuthority bytes: the {0,0,0,5,0,0} (the Value u32 BE of
    // 5 rides the last significant byte, the 2-byte pad follows)
    sid[5] = '\x05';
    for (std::size_t i = 0; i < subauths.size(); ++i) {
        const auto v = subauths[i];
        sid[8 + 4 * i + 0] = static_cast<char>(v & 0xff);
        sid[8 + 4 * i + 1] = static_cast<char>((v >> 8) & 0xff);
        sid[8 + 4 * i + 2] = static_cast<char>((v >> 16) & 0xff);
        sid[8 + 4 * i + 3] = static_cast<char>((v >> 24) & 0xff);
    }
    return sid;
}

// the verbatim singleton SID producers (the Administrators/Users/Guests/
// Power Users group SIDs)
std::string admin_sid_image()     { return make_sid_image({0x20, 0x220}); }  // S-1-5-32-544
std::string users_sid_image()     { return make_sid_image({0x20, 0x221}); }  // S-1-5-32-545
std::string guests_sid_image()    { return make_sid_image({0x20, 0x222}); }  // S-1-5-32-546
std::string powerusers_sid_image() { return make_sid_image({0x20, 0x223}); } // S-1-5-32-547

void register_advapi32_token_sc_families() {
    using namespace qiling::os::api;

    // BOOL GetTokenInformation( ... );
    WinsdkApi("GetTokenInformation", WinCc::Stdcall, {
        {"TokenHandle", HANDLE_},
        {"TokenInformationClass", DWORD_},
        {"TokenInformation", PVOID_},
        {"TokenInformationLength", DWORD_},
        {"ReturnLength", PVOID_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        const auto token_handle = api_get_int(get_param(params, "TokenHandle"));
        const auto token_information_class = api_get_int(get_param(params, "TokenInformationClass"));
        const auto token_information = api_get_int(get_param(params, "TokenInformation"));
        const auto token_information_length = api_get_int(get_param(params, "TokenInformationLength"));
        const auto return_length = api_get_int(get_param(params, "ReturnLength"));

        auto* handle = w(ql).handle_manager().get(token_handle);

        if (handle == nullptr) {
            w(ql).set_last_error(ERROR_INVALID_HANDLE);
            return 0;
        }

        const auto* token = static_cast<const Token*>(handle->obj);
        const auto& information_value = token->get(token_information_class);

        const auto return_size = information_value.size();
        ql.mem().write_ptr(return_length, return_size, 4);

        ql.log().debug("The target is checking for its permissions");

        if (return_size > static_cast<std::uint64_t>(token_information_length)) {
            w(ql).set_last_error(ERROR_INSUFFICIENT_BUFFER);
            return 0;
        }

        if (token_information != 0) {
            ql.mem().write(token_information, std::vector<std::uint8_t>(information_value.begin(), information_value.end()));
            return 1;
        } else {
            throw QlErrorNotImplemented("API not implemented");
        }
    };

    // PUCHAR GetSidSubAuthorityCount( PSID pSid );
    WinsdkApi("GetSidSubAuthorityCount", WinCc::Stdcall, {
        {"pSid", PVOID_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        const auto p_sid = api_get_int(get_param(params, "pSid"));

        // SID address is used as its handle id  (verbatim; the offsetof
        // SubAuthorityCount = 1)
        (void)w(ql).handle_manager().get(p_sid);
        return p_sid + 1;
    };

    // PDWORD GetSidSubAuthority( PSID pSid, DWORD nSubAuthority );
    WinsdkApi("GetSidSubAuthority", WinCc::Stdcall, {
        {"pSid", PVOID_},
        {"nSubAuthority", DWORD_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        const auto p_sid = api_get_int(get_param(params, "pSid"));
        const auto n_sub_authority = api_get_int(get_param(params, "nSubAuthority"));

        // SID address is used as its handle id  (verbatim; the offsetof
        // SubAuthority = 8)
        (void)w(ql).handle_manager().get(p_sid);
        return p_sid + 8 + (4 * static_cast<std::uint64_t>(n_sub_authority));
    };

    // BOOL AllocateAndInitializeSid( ... );
    WinsdkApi("AllocateAndInitializeSid", WinCc::Stdcall, {
        {"pIdentifierAuthority", PVOID_},
        {"nSubAuthorityCount", BYTE_},
        {"nSubAuthority0", DWORD_},
        {"nSubAuthority1", DWORD_},
        {"nSubAuthority2", DWORD_},
        {"nSubAuthority3", DWORD_},
        {"nSubAuthority4", DWORD_},
        {"nSubAuthority5", DWORD_},
        {"nSubAuthority6", DWORD_},
        {"nSubAuthority7", DWORD_},
        {"pSid", PVOID_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        const auto count = api_get_int(get_param(params, "nSubAuthorityCount"));
        std::vector<std::uint32_t> subauths;
        for (int i = 0; i < count && i < 8; ++i) {
            subauths.push_back(static_cast<std::uint32_t>(
                api_get_int(get_param(params, "nSubAuthority" + std::to_string(i)))));
        }

        const auto sid_image = make_sid_image(subauths);
        const auto sid_addr = w(ql).heap().alloc(sid_image.size());
        ql.mem().write(sid_addr, std::vector<std::uint8_t>(sid_image.begin(), sid_image.end()));

        // Handle(obj=sid_obj, id=sid_addr) — the port parks the packed SID
        // image on the handle's owned slot (the python struct object rides
        // the reference)
        auto parked = std::make_shared<std::string>(sid_image);
        Handle handle(static_cast<std::uint64_t>(sid_addr), parked.get());
        handle.owned = parked;
        w(ql).handle_manager().append(handle);

        const auto dest = api_get_int(get_param(params, "pSid"));
        ql.mem().write_ptr(dest, sid_addr);

        return 1;
    };

    // BOOL WINAPI CheckTokenMembership( ... );
    WinsdkApi("CheckTokenMembership", WinCc::Stdcall, {
        {"TokenHandle", HANDLE_},
        {"SidToCheck", PVOID_},
        {"IsMember", PVOID_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        const auto token_handle = api_get_int(get_param(params, "TokenHandle"));
        const auto sid_to_check = api_get_int(get_param(params, "SidToCheck"));

        auto* handle = w(ql).handle_manager().get(sid_to_check);
        const auto& sid = *static_cast<const std::string*>(handle->obj);
        bool is_member = false;

        // If TokenHandle is NULL, CheckTokenMembership uses the impersonation
        // token of the calling thread.  (verbatim)
        if (token_handle == 0) {
            // For now, treat power users as admins  (verbatim)
            if (sid == admin_sid_image() || sid == powerusers_sid_image()) {
                is_member = ql.profile().get("SYSTEM", "permission").value_or("") == "root";
            } else if (sid == users_sid_image()) {
                // FIXME: is this true for all tokens? probably not...  (verbatim)
                is_member = true;
            } else if (sid == guests_sid_image()) {
                is_member = false;
            } else {
                throw QlErrorNotImplemented("the SID does not match the default groups");
            }
        } else {
            throw QlErrorNotImplemented("API not implemented");
        }

        ql.mem().write_ptr(api_get_int(get_param(params, "IsMember")), is_member ? 1 : 0);

        return 1;
    };

    // PVOID FreeSid( PSID pSid );
    WinsdkApi("FreeSid", WinCc::Stdcall, {
        {"pSid", PVOID_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        // TODO: should also remove from ql.os.handle_manager ?  (verbatim)
        w(ql).heap().free(api_get_int(get_param(params, "pSid")));

        return 0;
    };

    // BOOL EqualSid( PSID pSid1, PSID pSid2 );
    WinsdkApi("EqualSid", WinCc::Stdcall, {
        {"pSid1", PVOID_},
        {"pSid2", PVOID_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        // TODO once i have understood better how SID are wrote in memory.
        // Fucking documentation  (verbatim comment; the body rides the 0)
        (void)w(ql).handle_manager().get(api_get_int(get_param(params, "pSid2")));
        return 0;
    };

    // SC_HANDLE OpenSCManagerA( ... );
    WinsdkApi("OpenSCManagerA", WinCc::Stdcall, {
        {"lpMachineName", LPCSTR_},
        {"lpDatabaseName", LPCSTR_},
        {"dwDesiredAccess", DWORD_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        const auto lp_machine_name = api_get_string(ql, get_param(params, "lpMachineName"));
        const auto lp_database_name = api_get_string(ql, get_param(params, "lpDatabaseName"));

        const auto sc_handle_name = "sc_" + lp_machine_name + "_" + lp_database_name;
        auto* new_handle = w(ql).handle_manager().search(sc_handle_name);

        if (new_handle == nullptr) {
            Handle handle(std::nullopt, nullptr, sc_handle_name);
            w(ql).handle_manager().append(handle);
            new_handle = w(ql).handle_manager().get(handle.id);
        }

        return new_handle->id;
    };

    // SC_HANDLE CreateServiceA( ... );
    WinsdkApi("CreateServiceA", WinCc::Stdcall, {
        {"hSCManager", PVOID_},
        {"lpServiceName", LPCSTR_},
        {"lpDisplayName", LPCSTR_},
        {"dwDesiredAccess", DWORD_},
        {"dwServiceType", DWORD_},
        {"dwStartType", DWORD_},
        {"dwErrorControl", DWORD_},
        {"lpBinaryPathName", LPCSTR_},
        {"lpLoadOrderGroup", LPCSTR_},
        {"lpdwTagId", PVOID_},
        {"lpDependencies", LPCSTR_},
        {"lpServiceStartName", LPCSTR_},
        {"lpPassword", LPCSTR_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        const auto h_scm_manager = api_get_int(get_param(params, "hSCManager"));
        const auto lp_service_name = api_get_string(ql, get_param(params, "lpServiceName"));
        const auto lp_binary_path_name = api_get_string(ql, get_param(params, "lpBinaryPathName"));

        w(ql).services()[lp_service_name] = lp_binary_path_name;
        Handle new_handle(std::nullopt, reinterpret_cast<void*>(static_cast<std::uintptr_t>(h_scm_manager)), lp_service_name);
        w(ql).handle_manager().append(new_handle);

        return new_handle.id;
    };

    // SC_HANDLE OpenServiceA( ... );
    WinsdkApi("OpenServiceA", WinCc::Stdcall, {
        {"hSCManager", PVOID_},
        {"lpServiceName", LPCSTR_},
        {"dwDesiredAccess", DWORD_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        const auto h_scm_manager = api_get_int(get_param(params, "hSCManager"));
        const auto lp_service_name = api_get_string(ql, get_param(params, "lpServiceName"));

        if (w(ql).services().count(lp_service_name) != 0) {
            Handle new_handle(std::nullopt, reinterpret_cast<void*>(static_cast<std::uintptr_t>(h_scm_manager)), lp_service_name);
            w(ql).handle_manager().append(new_handle);
            return new_handle.id;
        }

        return 0;
    };

    // BOOL CloseServiceHandle( SC_HANDLE hSCObject );
    WinsdkApi("CloseServiceHandle", WinCc::Stdcall, {
        {"hSCObject", PVOID_},
    }) = [](Qiling& ql, std::uint64_t, const ResolvedParams& params) -> std::optional<std::uint64_t> {
        const auto h_sco = api_get_int(get_param(params, "hSCObject"));
        w(ql).handle_manager().delete_handle(h_sco);

        return 1;
    };

    // BOOL StartServiceA( ... );
    WinsdkApi("StartServiceA", WinCc::Stdcall, {
        {"hService", PVOID_},
        {"dwNumServiceArgs", DWORD_},
        {"lpServiceArgVectors", PVOID_},
    }) = [](Qiling&, std::uint64_t, const ResolvedParams&) -> std::optional<std::uint64_t> {
        return 1;
    };
}

// the static-init registration (the python module-import side effect)
namespace {
const bool kAdvapi32Registered = [] {
    register_advapi32_family();
    register_advapi32_token_sc_families();
    return true;
}();
}  // namespace

}  // namespace win
}  // namespace os
}  // namespace qiling
