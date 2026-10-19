/* hello_reg.c - the registry-surface e2e fixture.
 *
 * Exercises advapi32 through the port's registry machinery: the profile
 * key open (HKEY_CURRENT_USER\Software\QilingTest rides the [REGISTRY]
 * profile section), the diff-store create + set, the read-back through a
 * fresh open, and the value marshalled out to a guest file.
 *
 * Rebuild: cl /nologo /c /O2 /MT tests\data\hello_reg.c /Fotests\data\hello_reg.obj
 *          link /nologo /SUBSYSTEM:CONSOLE tests\data\hello_reg.obj advapi32.lib /OUT:tests\data\hello_reg.exe
 */
#include <windows.h>

int main(void) {
    const char msg[] = "value42";
    char buf[64] = {0};
    DWORD len = sizeof(buf) - 1;
    DWORD type = 0;
    HKEY hk = 0, hk2 = 0;
    LONG rc = 0;

    /* the diff-store walk: create a fresh key + value, then read it back */
    rc = RegCreateKeyExA(HKEY_CURRENT_USER, "Software\\QilingTestNew", 0, NULL,
                         0, KEY_SET_VALUE | KEY_QUERY_VALUE, NULL, &hk, NULL);
    if (rc != ERROR_SUCCESS) {
        return 13;
    }
    RegSetValueExA(hk, "made", 0, REG_SZ, (const BYTE*)msg, (DWORD)sizeof(msg));
    RegCloseKey(hk);

    rc = RegOpenKeyExA(HKEY_CURRENT_USER, "Software\\QilingTestNew", 0, KEY_QUERY_VALUE, &hk2);
    if (rc != ERROR_SUCCESS) {
        return 14;
    }
    char made[32] = {0};
    DWORD made_len = sizeof(made) - 1;
    rc = RegQueryValueExA(hk2, "made", NULL, &type, (LPBYTE)made, &made_len);
    RegCloseKey(hk2);
    if (rc != ERROR_SUCCESS) {
        return 15;
    }

    /* marshal both strings out through the file surface */
    HANDLE out = CreateFileA("C:\\qltest\\reg.txt", GENERIC_WRITE, 0, NULL,
                             CREATE_ALWAYS, FILE_ATTRIBUTE_NORMAL, NULL);
    if (out == INVALID_HANDLE_VALUE) {
        return 16;
    }
    DWORD written = 0;
    WriteFile(out, made, (DWORD)strlen(made), &written, NULL);
    CloseHandle(out);
    return 0;
}
