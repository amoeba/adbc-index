# TODO

## ~~Windows DLL Symbol Extraction Issue~~ [RESOLVED]

**Problem:** The Windows test binary (`tiny.dll`) only exports 13 ADBC functions instead of the expected 14. The missing function is `AdbcDriverRelease`.

**Root Cause:** In the [tiniest-adbc-driver source code](https://github.com/amoeba/tiniest-adbc-driver/blob/main/src/tiny.c), `AdbcDriverRelease` was missing the `ADBC_EXPORT` macro in its function declaration. All other 13 functions had `ADBC_EXPORT`, which expands to `__declspec(dllexport)` on Windows when `ADBC_EXPORTING` is defined during compilation.

**Resolution:** Fixed in commit [e7acdf7](https://github.com/amoeba/tiniest-adbc-driver/commit/e7acdf7) by adding `ADBC_EXPORT` to the `AdbcDriverRelease` function declaration. The fix has been verified:
- Windows DLL now exports all 14 functions including `AdbcDriverRelease`
- Test artifacts updated with new binaries from CI build
- Tests updated to expect 14 symbols on all platforms
- All tests passing

---

## x86/x64 Stub Detection Not Working

**Problem:** Stub detection (disassembly pattern matching) doesn't work for Linux ELF and Windows PE binaries, only for macOS ARM64 Mach-O.

**Root cause:** The file offset calculations for x86/x64 binaries appear to be incorrect. For ELF, `st_value` is a virtual address that needs to be mapped to a file offset using section headers. For PE, the RVA-to-file-offset conversion may have issues.

**Investigation needed:**
1. Review ELF section header mapping for virtual address to file offset conversion
2. Verify PE RVA-to-file-offset logic handles all section types correctly
3. Add debug logging to see what bytes are actually being read from the binaries
4. Test with other ELF/PE binaries to see if the issue is specific to these test artifacts

**Impact:** Stub detection tests only validate macOS behavior. Linux and Windows platforms run stub analysis but don't get reliable results.

**Workaround:** Tests focus on macOS stub detection (`test_stub_detection_macos`) and only verify that analysis runs without errors on other platforms (`test_stub_detection_all_platforms`).
