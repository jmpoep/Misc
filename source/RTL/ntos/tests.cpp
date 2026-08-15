/************************************************************************************
*
*  (C) COPYRIGHT AUTHORS, 2015 - 2026
*
*  TITLE:       TESTS.CPP
*
*  VERSION:     1.250
*
*  DATE:        23 Jul 2026
*
*  NTOS / NTSUP RTL tests.
*
* THIS CODE AND INFORMATION IS PROVIDED "AS IS" WITHOUT WARRANTY OF
* ANY KIND, EITHER EXPRESSED OR IMPLIED, INCLUDING BUT NOT LIMITED
* TO THE IMPLIED WARRANTIES OF MERCHANTABILITY AND/OR FITNESS FOR A
* PARTICULAR PURPOSE.
*
************************************************************************************/

#include "global.h"
#include <intrin.h>
#include "rsrc/resource.h"

static ULONG g_FailCount = 0;
static BOOL g_Verbose = TRUE;

#define TEST_ASSERT(expr) do { if (!(expr)) { ++g_FailCount; if (g_Verbose) DbgPrint("ASSERT FAILED: %s (%s:%d)\n", #expr, __FUNCTION__, __LINE__); } } while (0)

BOOLEAN Sha256DigestEqual(
    _In_reads_(32) const UCHAR * Digest,
    _In_reads_(32) const UCHAR * Expected
)
{
    return (RtlCompareMemory(Digest, Expected, 32) == 32);
}

VOID Sha256_ABC(
    VOID
)
{
    static const UCHAR Expected[32] = {
        0xBA,0x78,0x16,0xBF,0x8F,0x01,0xCF,0xEA,
        0x41,0x41,0x40,0xDE,0x5D,0xAE,0x22,0x23,
        0xB0,0x03,0x61,0xA3,0x96,0x17,0x7A,0x9C,
        0xB4,0x10,0xFF,0x61,0xF2,0x00,0x15,0xAD
    };

    UCHAR digest[32];
    NTSUP_SHA256_CTX ctx;

    ntsupSha256Init(&ctx);
    ntsupSha256Update(&ctx, (const UCHAR*)"abc", 3);
    ntsupSha256Final(&ctx, digest);

    TEST_ASSERT(Sha256DigestEqual(digest, Expected));
}

VOID Sha256_Empty(
    VOID
)
{
    static const UCHAR Expected[32] = {
        0xE3,0xB0,0xC4,0x42,0x98,0xFC,0x1C,0x14,
        0x9A,0xFB,0xF4,0xC8,0x99,0x6F,0xB9,0x24,
        0x27,0xAE,0x41,0xE4,0x64,0x9B,0x93,0x4C,
        0xA4,0x95,0x99,0x1B,0x78,0x52,0xB8,0x55
    };

    NTSUP_SHA256_CTX ctx;
    UCHAR digest[32];

    ntsupSha256Init(&ctx);
    ntsupSha256Final(&ctx, digest);

    TEST_ASSERT(Sha256DigestEqual(digest, Expected));
}

static const UCHAR Expected[32] = {
    0x24,0x8D,0x6A,0x61,0xD2,0x06,0x38,0xB8,
    0xE5,0xC0,0x26,0x93,0x0C,0x3E,0x60,0x39,
    0xA3,0x3C,0xE4,0x59,0x64,0xFF,0x21,0x67,
    0xF6,0xEC,0xED,0xD4,0x19,0xDB,0x06,0xC1
};

static const CHAR FipsVector[] =
"abcdbcdecdefdefgefghfghighijhijk"
"ijkljklmklmnlmnomnopnopq";

VOID Sha256_FipsVector(
    VOID
)
{
    NTSUP_SHA256_CTX ctx;
    UCHAR digest[32];

    ntsupSha256Init(&ctx);

    ntsupSha256Update(
        &ctx,
        (const UCHAR*)FipsVector,
        sizeof(FipsVector) - 1);

    ntsupSha256Final(&ctx, digest);

    TEST_ASSERT(Sha256DigestEqual(digest, Expected));
}

VOID Sha256_SplitUpdates(
    VOID
)
{
    NTSUP_SHA256_CTX ctx1, ctx2;
    UCHAR d1[32];
    UCHAR d2[32];

    static const CHAR Text[] = "abcdefghijklmnopqrstuvwxyz";

    ntsupSha256Init(&ctx1);
    ntsupSha256Update(
        &ctx1,
        (const UCHAR*)Text,
        sizeof(Text) - 1);
    ntsupSha256Final(&ctx1, d1);

    ntsupSha256Init(&ctx2);

    ntsupSha256Update(&ctx2, (const UCHAR*)"abc", 3);
    ntsupSha256Update(&ctx2, (const UCHAR*)"defgh", 5);
    ntsupSha256Update(&ctx2, (const UCHAR*)"ijklmnop", 8);
    ntsupSha256Update(&ctx2, (const UCHAR*)"qrstuvwxyz", 10);

    ntsupSha256Final(&ctx2, d2);

    TEST_ASSERT(RtlCompareMemory(d1, d2, 32) == 32);
}

VOID Sha256_OneByteUpdates(
    VOID
)
{
    NTSUP_SHA256_CTX ctx1, ctx2;
    UCHAR d1[32];
    UCHAR d2[32];
    UCHAR buffer[512];
    ULONG i;

    for (i = 0; i < RTL_NUMBER_OF(buffer); i++)
        buffer[i] = (UCHAR)i;

    ntsupSha256Init(&ctx1);
    ntsupSha256Update(&ctx1, buffer, sizeof(buffer));
    ntsupSha256Final(&ctx1, d1);

    ntsupSha256Init(&ctx2);

    for (i = 0; i < RTL_NUMBER_OF(buffer); i++)
        ntsupSha256Update(&ctx2, &buffer[i], 1);

    ntsupSha256Final(&ctx2, d2);

    TEST_ASSERT(RtlCompareMemory(d1, d2, 32) == 32);
}

VOID Sha256_ZeroLengthUpdate(
    VOID
)
{
    static const UCHAR EmptyDigest[32] = {
        0xE3,0xB0,0xC4,0x42,0x98,0xFC,0x1C,0x14,
        0x9A,0xFB,0xF4,0xC8,0x99,0x6F,0xB9,0x24,
        0x27,0xAE,0x41,0xE4,0x64,0x9B,0x93,0x4C,
        0xA4,0x95,0x99,0x1B,0x78,0x52,0xB8,0x55
    };

    NTSUP_SHA256_CTX ctx;
    UCHAR digest[32];

    ntsupSha256Init(&ctx);

    ntsupSha256Update(&ctx, NULL, 0);

    ntsupSha256Final(&ctx, digest);

    TEST_ASSERT(RtlCompareMemory(
        digest,
        EmptyDigest,
        sizeof(digest)) == sizeof(digest));
}

VOID Sha256_BlockBoundaries(
    VOID
)
{
    static const SIZE_T Sizes[] = { 63, 64, 65, 127, 128, 129 };

    UCHAR buffer[129];
    SIZE_T i, j;

    for (i = 0; i < sizeof(buffer); i++)
        buffer[i] = (UCHAR)i;

    for (i = 0; i < RTL_NUMBER_OF(Sizes); i++) {

        UCHAR d1[32];
        UCHAR d2[32];
        NTSUP_SHA256_CTX c1, c2;

        ntsupSha256Init(&c1);
        ntsupSha256Update(&c1, buffer, Sizes[i]);
        ntsupSha256Final(&c1, d1);

        ntsupSha256Init(&c2);

        for (j = 0; j < Sizes[i]; j++)
            ntsupSha256Update(&c2, &buffer[j], 1);

        ntsupSha256Final(&c2, d2);

        TEST_ASSERT(
            RtlCompareMemory(d1, d2, 32) == 32);
    }
}

VOID Test_Sha256()
{
    g_FailCount = 0;

    Sha256_Empty();
    Sha256_ABC();
    Sha256_FipsVector();
    Sha256_SplitUpdates();
    Sha256_ZeroLengthUpdate();
    Sha256_BlockBoundaries();

    if (g_Verbose) {
        if (g_FailCount == 0)
            DbgPrint("[TEST] ntsupSha256 PASSED.\n");
        else
            DbgPrint("[TEST] ntsupSha256 %lu tests FAILED.\n", g_FailCount);
    }
}

PVOID CALLBACK TestAlloc(_In_ SIZE_T NumberOfBytes)
{
    return HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, NumberOfBytes);
}

BOOL CALLBACK TestFree(_In_ PVOID Memory)
{
    if (Memory) HeapFree(GetProcessHeap(), 0, Memory);
    return TRUE;
}

PVOID CALLBACK FailAlloc(_In_ SIZE_T NumberOfBytes)
{
    (void)NumberOfBytes;
    return NULL;
}

BOOL ReadFileContent(
    _In_ LPCWSTR FileName,
    _Out_ PBYTE* Buffer,
    _Out_ DWORD* Size
)
{
    HANDLE hFile;
    DWORD fileSize, bytesRead;
    PBYTE data;

    *Buffer = NULL;
    *Size = 0;

    hFile = CreateFile(FileName,
        GENERIC_READ,
        FILE_SHARE_READ,
        NULL,
        OPEN_EXISTING,
        FILE_ATTRIBUTE_NORMAL,
        NULL);

    if (hFile == INVALID_HANDLE_VALUE)
        return FALSE;

    fileSize = GetFileSize(hFile, NULL);
    if (fileSize == INVALID_FILE_SIZE) {
        CloseHandle(hFile);
        return FALSE;
    }

    data = (PBYTE)ntsupHeapAlloc(fileSize ? fileSize : 1);
    if (data == NULL) {
        CloseHandle(hFile);
        return FALSE;
    }

    bytesRead = 0;
    if (fileSize) {
        if (!ReadFile(hFile, data, fileSize, &bytesRead, NULL) || bytesRead != fileSize) {
            ntsupHeapFree(data);
            CloseHandle(hFile);
            return FALSE;
        }
    }

    CloseHandle(hFile);

    *Buffer = data;
    *Size = fileSize;
    return TRUE;
}

VOID WriteBufferToFile_WriteNewFile(VOID)
{
    WCHAR tempPath[MAX_PATH];
    WCHAR filePath[MAX_PATH];
    NTSTATUS resultStatus;
    SIZE_T written;
    BYTE const data1[] = { 1,2,3,4,5 };
    PBYTE fileData;
    DWORD fileSize;
    ULONG i;

    RtlSecureZeroMemory(tempPath, sizeof(tempPath));
    RtlSecureZeroMemory(filePath, sizeof(filePath));

    GetTempPath(MAX_PATH, tempPath);
    wsprintfW(filePath, L"%sntsup_test_%lu.bin", tempPath, GetTickCount());

    written = ntsupWriteBufferToFile(
        filePath,
        (PVOID)data1,
        sizeof(data1),
        TRUE,
        FALSE,
        &resultStatus);

    TEST_ASSERT(written == sizeof(data1));
    TEST_ASSERT(NT_SUCCESS(resultStatus));

    fileData = NULL;
    fileSize = 0;
    TEST_ASSERT(ReadFileContent(filePath, &fileData, &fileSize));
    if (fileData) {
        TEST_ASSERT(fileSize == sizeof(data1));
        for (i = 0; i < fileSize; i++)
            TEST_ASSERT(fileData[i] == data1[i]);
        ntsupHeapFree(fileData);
    }

    DeleteFile(filePath);
}

VOID WriteBufferToFile_AppendFile(VOID)
{
    WCHAR tempPath[MAX_PATH];
    WCHAR filePath[MAX_PATH];
    NTSTATUS resultStatus;
    SIZE_T written;
    BYTE const data1[] = { 0x10,0x11,0x12 };
    BYTE const data2[] = { 0xAA,0xBB };
    PBYTE fileData;
    DWORD fileSize;
    ULONG i;

    RtlSecureZeroMemory(tempPath, sizeof(tempPath));
    RtlSecureZeroMemory(filePath, sizeof(filePath));

    GetTempPath(MAX_PATH, tempPath);
    wsprintfW(filePath, L"%sntsup_test_append_%lu.bin", tempPath, GetTickCount());

    written = ntsupWriteBufferToFile(
        filePath,
        (PVOID)data1,
        sizeof(data1),
        TRUE,
        FALSE,
        &resultStatus);

    TEST_ASSERT(written == sizeof(data1));
    TEST_ASSERT(NT_SUCCESS(resultStatus));

    written = ntsupWriteBufferToFile(
        filePath,
        (PVOID)data2,
        sizeof(data2),
        TRUE,
        TRUE,
        &resultStatus);

    TEST_ASSERT(written == sizeof(data2));
    TEST_ASSERT(NT_SUCCESS(resultStatus));

    fileData = NULL;
    fileSize = 0;
    TEST_ASSERT(ReadFileContent(filePath, &fileData, &fileSize));
    if (fileData) {
        TEST_ASSERT(fileSize == sizeof(data1) + sizeof(data2));
        for (i = 0; i < sizeof(data1); i++)
            TEST_ASSERT(fileData[i] == data1[i]);
        for (i = 0; i < sizeof(data2); i++)
            TEST_ASSERT(fileData[sizeof(data1) + i] == data2[i]);
        ntsupHeapFree(fileData);
    }

    DeleteFile(filePath);
}

VOID WriteBufferToFile_InvalidPath(VOID)
{
    NTSTATUS resultStatus;
    SIZE_T written;
    BYTE dummy[4] = { 0 };

    written = ntsupWriteBufferToFile(
        L"",
        dummy,
        sizeof(dummy),
        FALSE,
        FALSE,
        &resultStatus);

    TEST_ASSERT(written == 0);
    TEST_ASSERT(!NT_SUCCESS(resultStatus));
}

VOID WriteBufferToFile_ZeroSizeWrite(VOID)
{
    WCHAR tempPath[MAX_PATH];
    WCHAR filePath[MAX_PATH];
    NTSTATUS resultStatus;
    SIZE_T written;
    PBYTE fileData;
    DWORD fileSize;

    RtlSecureZeroMemory(tempPath, sizeof(tempPath));
    RtlSecureZeroMemory(filePath, sizeof(filePath));

    GetTempPath(MAX_PATH, tempPath);
    wsprintfW(filePath, L"%sntsup_test_zero_%lu.bin", tempPath, GetTickCount());

    written = ntsupWriteBufferToFile(
        filePath,
        (PVOID)"",
        0,
        TRUE,
        FALSE,
        &resultStatus);

    TEST_ASSERT(written == 0);
    TEST_ASSERT(NT_SUCCESS(resultStatus) || written == 0); // Accept success with zero write

    fileData = NULL;
    fileSize = 0;
    if (ReadFileContent(filePath, &fileData, &fileSize)) {
        TEST_ASSERT(fileSize == 0);
        if (fileData) ntsupHeapFree(fileData);
    }

    DeleteFile(filePath);
}

VOID FindModuleNameByAddress_ValidModuleName(VOID)
{
    PRTL_PROCESS_MODULES modules;
    ULONG returnLength;
    PRTL_PROCESS_MODULE_INFORMATION modInfo;
    WCHAR nameBuffer[260];
    PVOID foundEntry;
    PVOID testAddress;
    ANSI_STRING ansiExpected;
    UNICODE_STRING usExpected;
    SIZE_T expectedLen;

    modules = (PRTL_PROCESS_MODULES)ntsupGetLoadedModulesList(&returnLength);
    TEST_ASSERT(modules != NULL);
    if (modules == NULL)
        return;

    if (modules->NumberOfModules == 0) {
        ntsupHeapFree(modules);
        TEST_ASSERT(FALSE);
        return;
    }

    modInfo = &modules->Modules[0];
    testAddress = (PBYTE)modInfo->ImageBase + (modInfo->ImageSize / 2);

    RtlSecureZeroMemory(nameBuffer, sizeof(nameBuffer));

    foundEntry = ntsupFindModuleNameByAddress(
        modules,
        testAddress,
        nameBuffer,
        _countof(nameBuffer));

    TEST_ASSERT(foundEntry != NULL);
    TEST_ASSERT(nameBuffer[0] != 0);

    if (foundEntry) {
        RtlInitString(&ansiExpected,
            (PCSZ)&modInfo->FullPathName[modInfo->OffsetToFileName]);
        usExpected.Buffer = NULL;
        usExpected.Length = usExpected.MaximumLength = 0;
        if (NT_SUCCESS(RtlAnsiStringToUnicodeString(&usExpected, &ansiExpected, TRUE))) {
            expectedLen = usExpected.Length / sizeof(WCHAR);
            TEST_ASSERT(ntsupStrLen(nameBuffer) <= expectedLen);
            TEST_ASSERT(ntsupStrCmp(nameBuffer, usExpected.Buffer) == 0);
            RtlFreeUnicodeString(&usExpected);
        }
    }

    ntsupHeapFree(modules);
}

VOID FindModuleNameByAddress_TruncatedBuffer(VOID)
{
    PRTL_PROCESS_MODULES modules;
    ULONG returnLength;
    PRTL_PROCESS_MODULE_INFORMATION modInfo;
    WCHAR tinyBuffer[4];
    PVOID testAddress;
    PVOID foundEntry;
    SIZE_T lenCaptured;

    modules = (PRTL_PROCESS_MODULES)ntsupGetLoadedModulesList(&returnLength);
    TEST_ASSERT(modules != NULL);
    if (modules == NULL)
        return;

    if (modules->NumberOfModules == 0) {
        ntsupHeapFree(modules);
        TEST_ASSERT(FALSE);
        return;
    }

    modInfo = &modules->Modules[0];
    testAddress = modInfo->ImageBase;

    RtlSecureZeroMemory(tinyBuffer, sizeof(tinyBuffer));

    foundEntry = ntsupFindModuleNameByAddress(
        modules,
        testAddress,
        tinyBuffer,
        _countof(tinyBuffer));

    TEST_ASSERT(foundEntry != NULL);
    lenCaptured = ntsupStrLen(tinyBuffer);
    TEST_ASSERT(lenCaptured <= (_countof(tinyBuffer) - 1));
    TEST_ASSERT(tinyBuffer[_countof(tinyBuffer) - 1] == 0);

    ntsupHeapFree(modules);
}

VOID FindModuleNameByAddress_InvalidAddress(VOID)
{
    PRTL_PROCESS_MODULES modules;
    ULONG returnLength;
    WCHAR buffer[32];
    PVOID foundEntry;

    modules = (PRTL_PROCESS_MODULES)ntsupGetLoadedModulesList(&returnLength);
    TEST_ASSERT(modules != NULL);
    if (modules == NULL)
        return;

    RtlSecureZeroMemory(buffer, sizeof(buffer));

    foundEntry = ntsupFindModuleNameByAddress(
        modules,
        ULongToPtr(0x1), // very low address, should not belong to system module range
        buffer,
        _countof(buffer));

    TEST_ASSERT(foundEntry == NULL);
    TEST_ASSERT(buffer[0] == 0);

    ntsupHeapFree(modules);
}

VOID FindModuleNameByAddress_InvalidBufferArgs(VOID)
{
    PRTL_PROCESS_MODULES modules;
    ULONG returnLength;
    PRTL_PROCESS_MODULE_INFORMATION modInfo;
    PVOID testAddress;
    PVOID foundEntry;
    WCHAR nameBuffer[8];

    modules = (PRTL_PROCESS_MODULES)ntsupGetLoadedModulesList(&returnLength);
    TEST_ASSERT(modules != NULL);
    if (modules == NULL)
        return;

    if (modules->NumberOfModules == 0) {
        ntsupHeapFree(modules);
        TEST_ASSERT(FALSE);
        return;
    }

    modInfo = &modules->Modules[0];
    testAddress = modInfo->ImageBase;

    foundEntry = ntsupFindModuleNameByAddress(
        modules,
        testAddress,
        NULL,
        0);
    TEST_ASSERT(foundEntry == NULL);

    RtlSecureZeroMemory(nameBuffer, sizeof(nameBuffer));
    foundEntry = ntsupFindModuleNameByAddress(
        modules,
        testAddress,
        nameBuffer,
        0);
    TEST_ASSERT(foundEntry == NULL);
    TEST_ASSERT(nameBuffer[0] == 0);

    ntsupHeapFree(modules);
}

VOID GetLoadedModulesListEx_BasicList(VOID)
{
    PRTL_PROCESS_MODULES modules;
    ULONG returnLength = 0;
    ULONG count, i;
    BOOLEAN haveNonZero = FALSE;

    modules = (PRTL_PROCESS_MODULES)ntsupGetLoadedModulesListEx(
        FALSE,
        &returnLength,
        (PNTSUPMEMALLOC)ntsupHeapAlloc,
        (PNTSUPMEMFREE)ntsupHeapFree);

    TEST_ASSERT(modules != NULL);
    if (modules == NULL)
        return;

    count = modules->NumberOfModules;
    TEST_ASSERT(count > 0);
    TEST_ASSERT(returnLength > 0);

    if (count > 0) {
        TEST_ASSERT(modules->Modules[0].ImageBase != NULL);
        TEST_ASSERT(modules->Modules[0].ImageSize > 0);
    }

    for (i = 0; i < count && i < 32; i++) {
        if (modules->Modules[i].FullPathName[0] != 0) {
            haveNonZero = TRUE;
            break;
        }
    }
    TEST_ASSERT(haveNonZero);

    ntsupHeapFree(modules);
}

VOID GetLoadedModulesListEx_ExtendedList(VOID)
{
    PRTL_PROCESS_MODULES modules;
    ULONG returnLength = 0;

    modules = (PRTL_PROCESS_MODULES)ntsupGetLoadedModulesListEx(
        TRUE,
        &returnLength,
        (PNTSUPMEMALLOC)ntsupHeapAlloc,
        (PNTSUPMEMFREE)ntsupHeapFree);

    if (modules == NULL) {
        if (g_Verbose) DbgPrint("Extended module list not available (SystemModuleInformationEx unsupported?) - skipping related assertions.\n");
        return;
    }

    TEST_ASSERT(returnLength > 0);
    TEST_ASSERT(modules->NumberOfModules > 0);
    TEST_ASSERT(modules->Modules[0].ImageBase != NULL);

    ntsupHeapFree(modules);
}

VOID GetLoadedModulesListEx_NullReturnLength(VOID)
{
    PRTL_PROCESS_MODULES modules;

    modules = (PRTL_PROCESS_MODULES)ntsupGetLoadedModulesListEx(
        FALSE,
        NULL,
        (PNTSUPMEMALLOC)ntsupHeapAlloc,
        (PNTSUPMEMFREE)ntsupHeapFree);

    TEST_ASSERT(modules != NULL);
    if (modules)
        ntsupHeapFree(modules);
}

VOID GetLoadedModulesListEx_AllocFailure(VOID)
{
    PVOID modules;
    ULONG returnLength = 0;

    modules = ntsupGetLoadedModulesListEx(
        FALSE,
        &returnLength,
        (PNTSUPMEMALLOC)FailAlloc,
        (PNTSUPMEMFREE)TestFree);

    TEST_ASSERT(modules == NULL);
    TEST_ASSERT(returnLength == 0);
}

VOID GetSystemInfoEx_SystemProcessInformation(VOID)
{
    PVOID buffer;
    ULONG retLen = 0;
    ULONG safeCheck = 0;
    ULONG bytesWalked = 0;

    buffer = ntsupGetSystemInfoEx(
        SystemProcessInformation,
        &retLen,
        (PNTSUPMEMALLOC)TestAlloc,
        (PNTSUPMEMFREE)TestFree);

    if (buffer == NULL) {
        if (g_Verbose) DbgPrint("SystemProcessInformation unsupported or allocation failed, skipping.\n");
        return;
    }

    TEST_ASSERT(retLen > 0);

    if (retLen > sizeof(SYSTEM_PROCESS_INFORMATION)) {

        PSYSTEM_PROCESS_INFORMATION spi = (PSYSTEM_PROCESS_INFORMATION)buffer;

        while (TRUE) {
            TEST_ASSERT(spi->NextEntryDelta % sizeof(ULONG) == 0);
            bytesWalked += spi->NextEntryDelta;
            safeCheck++;

            if (spi->NextEntryDelta == 0)
                break;

            if (safeCheck > 0x100000) {
                TEST_ASSERT(FALSE);
                break;
            }

            spi = (PSYSTEM_PROCESS_INFORMATION)((PUCHAR)spi + spi->NextEntryDelta);
        }
    }

    TestFree(buffer);
}

VOID GetSystemInfoEx_NullReturnLength(VOID)
{
    PVOID buffer;

    buffer = ntsupGetSystemInfoEx(
        SystemBasicInformation,
        NULL,
        (PNTSUPMEMALLOC)TestAlloc,
        (PNTSUPMEMFREE)TestFree);

    TEST_ASSERT(buffer == NULL);
    if (buffer)
        TestFree(buffer);
}

VOID GetSystemInfoEx_AllocFailure(VOID)
{
    PVOID buffer;
    ULONG retLen = 0;

    buffer = ntsupGetSystemInfoEx(
        SystemBasicInformation,
        &retLen,
        (PNTSUPMEMALLOC)FailAlloc,
        (PNTSUPMEMFREE)TestFree);

    TEST_ASSERT(buffer == NULL);
    TEST_ASSERT(retLen == 0);
}

VOID GetSystemInfoEx_InvalidClass(VOID)
{
    PVOID buffer;
    ULONG retLen = 0;

    buffer = ntsupGetSystemInfoEx(
        (SYSTEM_INFORMATION_CLASS)0xFFFFFFFF, //-V1016
        &retLen,
        (PNTSUPMEMALLOC)TestAlloc,
        (PNTSUPMEMFREE)TestFree);

    TEST_ASSERT(buffer == NULL);
    TEST_ASSERT(retLen == 0);
}

VOID HashImageSections_LoadedImage(VOID)
{
    HMODULE hMod;
    PIMAGE_NT_HEADERS nth;
    BYTE hash[NTSUPHASH_SHA256_SIZE];
    NTSTATUS status;
    SIZE_T imageSize;

    hMod = GetModuleHandle(NULL);
    TEST_ASSERT(hMod != NULL);
    if (hMod == NULL) return;

    nth = RtlImageNtHeader(hMod);
    TEST_ASSERT(nth != NULL);
    if (nth == NULL) return;

    imageSize = nth->OptionalHeader.SizeOfImage;
    RtlSecureZeroMemory(hash, sizeof(hash));

    status = ntsupHashImageSections(
        (PVOID)hMod,
        imageSize,
        hash,
        sizeof(hash),
        ImageTypeLoaded);

    TEST_ASSERT(NT_SUCCESS(status));
    if (NT_SUCCESS(status)) {
        SIZE_T i, zeroCount = 0;
        for (i = 0; i < sizeof(hash); i++)
            if (hash[i] == 0) zeroCount++;
        TEST_ASSERT(zeroCount != sizeof(hash));
    }
}

VOID HashImageSections_RawFileMapping(VOID)
{
    WCHAR path[MAX_PATH];
    HANDLE hFile, hMapping;
    LARGE_INTEGER fsz;
    PVOID mapBase;
    BYTE hash[NTSUPHASH_SHA256_SIZE];
    NTSTATUS status;

    RtlSecureZeroMemory(path, sizeof(path));
    if (!GetModuleFileName(NULL, path, MAX_PATH))
        return;

    hFile = CreateFile(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
    TEST_ASSERT(hFile != INVALID_HANDLE_VALUE);
    if (hFile == INVALID_HANDLE_VALUE) return;

    fsz.LowPart = GetFileSize(hFile, (LPDWORD)&fsz.HighPart);
    TEST_ASSERT(fsz.QuadPart > 0);

    hMapping = CreateFileMapping(hFile, NULL, PAGE_READONLY, 0, 0, NULL);
    TEST_ASSERT(hMapping != NULL);
    if (hMapping == NULL) {
        CloseHandle(hFile);
        return;
    }

    mapBase = MapViewOfFile(hMapping, FILE_MAP_READ, 0, 0, 0);
    TEST_ASSERT(mapBase != NULL);
    if (mapBase == NULL) {
        CloseHandle(hMapping);
        CloseHandle(hFile);
        return;
    }

    RtlSecureZeroMemory(hash, sizeof(hash));
    status = ntsupHashImageSections(
        mapBase,
        (SIZE_T)fsz.QuadPart,
        hash,
        sizeof(hash),
        ImageTypeRaw);

    TEST_ASSERT(NT_SUCCESS(status));

    UnmapViewOfFile(mapBase);
    CloseHandle(hMapping);
    CloseHandle(hFile);
}

VOID BuildMinimalImage(
    _Out_ PVOID* Buffer,
    _Out_ SIZE_T* BufferSize,
    _In_ BOOL ExecutableSection
)
{
    PBYTE base;
    IMAGE_DOS_HEADER* dos;
    IMAGE_NT_HEADERS64* nth;
    IMAGE_SECTION_HEADER* sh;
    SIZE_T bufSize;
    ULONG optSize;

    bufSize = 0x1000;
    *BufferSize = bufSize;
    base = (PBYTE)HeapAlloc(GetProcessHeap(), HEAP_ZERO_MEMORY, bufSize);
    *Buffer = base;
    if (base == NULL) return;

    dos = (IMAGE_DOS_HEADER*)base;
    dos->e_magic = IMAGE_DOS_SIGNATURE;
    dos->e_lfanew = 0x80;

    nth = (IMAGE_NT_HEADERS64*)(base + dos->e_lfanew);
    nth->Signature = IMAGE_NT_SIGNATURE;
    nth->FileHeader.Machine = IMAGE_FILE_MACHINE_AMD64;
    nth->FileHeader.NumberOfSections = 1;
    optSize = sizeof(IMAGE_OPTIONAL_HEADER64);
    nth->FileHeader.SizeOfOptionalHeader = (WORD)optSize;
    nth->OptionalHeader.Magic = IMAGE_NT_OPTIONAL_HDR64_MAGIC;
    nth->OptionalHeader.SectionAlignment = 0x200;
    nth->OptionalHeader.FileAlignment = 0x200;
    nth->OptionalHeader.SizeOfImage = (DWORD)bufSize;
    nth->OptionalHeader.SizeOfHeaders = 0x200;

    sh = (IMAGE_SECTION_HEADER*)((PBYTE)&nth->OptionalHeader + optSize);
    RtlCopyMemory(sh->Name, ".data", 5);
    sh->Misc.VirtualSize = 0x100;
    sh->VirtualAddress = 0x200;
    sh->SizeOfRawData = 0x200;
    sh->PointerToRawData = 0x200;
    sh->Characteristics =
        IMAGE_SCN_CNT_INITIALIZED_DATA |
        IMAGE_SCN_MEM_READ |
        (ExecutableSection ? (IMAGE_SCN_MEM_EXECUTE | IMAGE_SCN_CNT_CODE) : 0);
}

VOID HashImageSections_NoExecutableSections(VOID)
{
    PVOID image;
    SIZE_T imageSize;
    BYTE hash[NTSUPHASH_SHA256_SIZE];
    NTSTATUS status;

    image = NULL;
    imageSize = 0;
    BuildMinimalImage(&image, &imageSize, FALSE);
    TEST_ASSERT(image != NULL);
    if (image == NULL) return;

    RtlSecureZeroMemory(hash, sizeof(hash));
    status = ntsupHashImageSections(
        image,
        imageSize,
        hash,
        sizeof(hash),
        ImageTypeLoaded);

    TEST_ASSERT(status == STATUS_NOT_FOUND);

    HeapFree(GetProcessHeap(), 0, image);
}

VOID HashImageSections_ExecutableSectionPresent(VOID)
{
    PVOID image;
    SIZE_T imageSize;
    BYTE hash[NTSUPHASH_SHA256_SIZE];
    NTSTATUS status;

    image = NULL;
    imageSize = 0;
    BuildMinimalImage(&image, &imageSize, TRUE);
    TEST_ASSERT(image != NULL);
    if (image == NULL) return;

    RtlSecureZeroMemory(hash, sizeof(hash));
    status = ntsupHashImageSections(
        image,
        imageSize,
        hash,
        sizeof(hash),
        ImageTypeLoaded);

    TEST_ASSERT(NT_SUCCESS(status));

    HeapFree(GetProcessHeap(), 0, image);
}

VOID HashImageSections_InvalidParams(VOID)
{
    BYTE hash[NTSUPHASH_SHA256_SIZE];
    NTSTATUS status;
    PVOID image;
    SIZE_T imageSize;

    RtlSecureZeroMemory(hash, sizeof(hash));

    status = ntsupHashImageSections(NULL, 100, hash, sizeof(hash), ImageTypeLoaded);
    TEST_ASSERT(status == STATUS_INVALID_PARAMETER);

    status = ntsupHashImageSections(ULongToPtr(0x1), 0, hash, sizeof(hash), ImageTypeLoaded);
    TEST_ASSERT(status == STATUS_INVALID_PARAMETER);

    status = ntsupHashImageSections(ULongToPtr(0x1), 100, hash, 1, ImageTypeLoaded);
    TEST_ASSERT(status == STATUS_BUFFER_TOO_SMALL);

    image = NULL;
    imageSize = 0;
    BuildMinimalImage(&image, &imageSize, TRUE);
    if (image) {
        PIMAGE_NT_HEADERS nth = (PIMAGE_NT_HEADERS)RtlImageNtHeader(image);
        if (nth) {
            SIZE_T smaller = nth->OptionalHeader.SizeOfImage / 2;
            status = ntsupHashImageSections(
                image,
                smaller,
                hash,
                sizeof(hash),
                ImageTypeLoaded);
            TEST_ASSERT(status == STATUS_INVALID_IMAGE_FORMAT);
        }
        HeapFree(GetProcessHeap(), 0, image);
    }
}

VOID Test_WriteBufferToFile()
{
    g_FailCount = 0;
    WriteBufferToFile_WriteNewFile();
    WriteBufferToFile_AppendFile();
    WriteBufferToFile_InvalidPath();
    WriteBufferToFile_ZeroSizeWrite();

    if (g_Verbose) {
        if (g_FailCount == 0)
            DbgPrint("[TEST] ntsupWriteBufferToFile PASSED.\n");
        else
            DbgPrint("[TEST] ntsupWriteBufferToFile %lu tests FAILED.\n", g_FailCount);
    }
}

VOID Test_FindModuleNameByAddress()
{
    g_FailCount = 0;
    FindModuleNameByAddress_ValidModuleName();
    FindModuleNameByAddress_TruncatedBuffer();
    FindModuleNameByAddress_InvalidAddress();
    FindModuleNameByAddress_InvalidBufferArgs();

    if (g_Verbose) {
        if (g_FailCount == 0)
            DbgPrint("[TEST] ntsupFindModuleNameByAddress PASSED.\n");
        else
            DbgPrint("[TEST] ntsupFindModuleNameByAddress %lu tests FAILED.\n", g_FailCount);
    }
}

VOID Test_GetLoadedModulesListEx()
{
    g_FailCount = 0;

    GetLoadedModulesListEx_BasicList();
    GetLoadedModulesListEx_ExtendedList();
    GetLoadedModulesListEx_NullReturnLength();
    GetLoadedModulesListEx_AllocFailure();

    if (g_Verbose) {
        if (g_FailCount == 0)
            DbgPrint("[TEST] ntsupGetLoadedModulesListEx PASSED.\n");
        else
            DbgPrint("[TEST] ntsupGetLoadedModulesListEx %lu tests FAILED.\n", g_FailCount);
    }
}

VOID Test_GetSystemInfoEx()
{
    g_FailCount = 0;

    GetSystemInfoEx_SystemProcessInformation();
    GetSystemInfoEx_NullReturnLength();
    GetSystemInfoEx_AllocFailure();
    GetSystemInfoEx_InvalidClass();

    if (g_Verbose) {
        if (g_FailCount == 0)
            DbgPrint("[TEST] ntsupGetSystemInfoEx tests PASSED.\n");
        else
            DbgPrint("[TEST] ntsupGetSystemInfoEx %lu tests FAILED.\n", g_FailCount);
    }
}

VOID Test_HashImageSections()
{
    g_FailCount = 0;

    HashImageSections_LoadedImage();
    HashImageSections_RawFileMapping();
    HashImageSections_NoExecutableSections();
    HashImageSections_ExecutableSectionPresent();
    HashImageSections_InvalidParams();

    if (g_Verbose) {
        if (g_FailCount == 0)
            DbgPrint("[TEST] ntsupHashImageSections tests PASSED.\n");
        else
            DbgPrint("[TEST] ntsupHashImageSections%lu tests FAILED.\n", g_FailCount);
    }
}

VOID IsObjectExists_ValidObject(VOID)
{
    BOOLEAN result;

    //
    // Known object directory and object.
    //
    // \ObjectTypes exists in every Windows system.
    //
    result = ntsupIsObjectExists(
        L"\\",
        L"BaseNamedObjects");

    TEST_ASSERT(result == TRUE);
}

VOID IsObjectExists_InvalidObject(VOID)
{
    BOOLEAN result;

    result = ntsupIsObjectExists(
        L"\\",
        L"ThisObjectDoesNotExist");

    TEST_ASSERT(result == FALSE);
}

VOID IsObjectExists_InvalidDirectory(VOID)
{
    BOOLEAN result;

    result = ntsupIsObjectExists(
        L"\\ThisDirectoryDoesNotExist",
        L"Anything");

    TEST_ASSERT(result == FALSE);
}

VOID IsObjectExists_AdminObject(VOID)
{
    BOOLEAN result;

    result = ntsupIsObjectExists(
        L"\\ObjectTypes",
        L"Directory"
    );

    TEST_ASSERT(result == TRUE);
}

VOID IsObjectExists_NullObjectName(VOID)
{
    BOOLEAN result;

    //
    // Current implementation does not validate ObjectName.
    // This test documents expected safe behavior.
    //
    result = ntsupIsObjectExists(
        L"\\",
        NULL);

    TEST_ASSERT(result == FALSE);
}

VOID IsObjectExists_CaseInsensitiveObject(VOID)
{
    BOOLEAN result;

    result = ntsupIsObjectExists(
        L"\\",
        L"bAsENamEdObJECts");

    TEST_ASSERT(result == TRUE);
}

VOID IsObjectExists_CreatedObject(VOID)
{
    HANDLE handle;
    UNICODE_STRING usName;
    OBJECT_ATTRIBUTES oa;
    BOOLEAN result;

    RtlInitUnicodeString(
        &usName,
        L"\\BaseNamedObjects\\ntsupTestObject"
    );

    InitializeObjectAttributes(
        &oa,
        &usName,
        OBJ_CASE_INSENSITIVE,
        NULL,
        NULL
    );

    handle = NULL;

    //
    // Create a known object that we control.
    //
    NtCreateEvent(
        &handle,
        EVENT_ALL_ACCESS,
        &oa,
        NotificationEvent,
        FALSE
    );

    TEST_ASSERT(handle != NULL);

    result = ntsupIsObjectExists(
        L"\\BaseNamedObjects",
        L"ntsupTestObject"
    );

    TEST_ASSERT(result == TRUE);

    if (handle)
        NtClose(handle);
}

VOID Test_IsObjectExists()
{
    g_FailCount = 0;

    IsObjectExists_ValidObject();
    IsObjectExists_InvalidObject();
    IsObjectExists_InvalidDirectory();
    IsObjectExists_NullObjectName();
    IsObjectExists_CaseInsensitiveObject();
    IsObjectExists_CreatedObject();

    if (g_IsElevated)
        IsObjectExists_AdminObject();

    if (g_Verbose) {
        if (g_FailCount == 0)
            DbgPrint("[TEST] ntsupIsObjectExists PASSED.\n");
        else
            DbgPrint("[TEST] ntsupIsObjectExists %lu tests FAILED.\n", g_FailCount);
    }
}

VOID IsAddressValid_NullAddress(
    VOID
)
{
    BOOLEAN result;

    result = ntsupIsAddressValid(
        NULL,
        sizeof(ULONG));

    TEST_ASSERT(result == FALSE);
}

VOID IsAddressValid_InvalidSize(
    VOID
)
{
    PVOID buffer;
    BOOLEAN result;

    buffer = ntsupHeapAlloc(PAGE_SIZE);

    TEST_ASSERT(buffer != NULL);
    if (buffer == NULL)
        return;

    result = ntsupIsAddressValid(
        buffer,
        0);

    TEST_ASSERT(result == TRUE);

    ntsupHeapFree(buffer);
}

VOID IsAddressValid_ValidMemory(
    VOID
)
{
    PVOID buffer;
    BOOLEAN result;

    buffer = ntsupHeapAlloc(PAGE_SIZE);

    TEST_ASSERT(buffer != NULL);
    if (buffer == NULL)
        return;

    result = ntsupIsAddressValid(
        buffer,
        PAGE_SIZE);

    TEST_ASSERT(result == TRUE);

    ntsupHeapFree(buffer);
}

VOID IsAddressValid_FreedMemory(
    VOID
)
{
    PVOID memory = NULL;
    SIZE_T size = PAGE_SIZE;
    NTSTATUS status;
    BOOLEAN result;

    status = NtAllocateVirtualMemory(
        NtCurrentProcess(),
        &memory,
        0,
        &size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE);

    TEST_ASSERT(NT_SUCCESS(status));
    if (!NT_SUCCESS(status))
        return;

    NtFreeVirtualMemory(
        NtCurrentProcess(),
        &memory,
        &size,
        MEM_RELEASE);

    result = ntsupIsAddressValid(
        memory,
        sizeof(ULONG));

    TEST_ASSERT(result == FALSE);
}

VOID IsAddressValid_NoAccessMemory(
    VOID
)
{
    PVOID memory = NULL;
    SIZE_T size = PAGE_SIZE;
    NTSTATUS status;
    BOOLEAN result;
    ULONG oldProtect;

    status = NtAllocateVirtualMemory(
        NtCurrentProcess(),
        &memory,
        0,
        &size,
        MEM_COMMIT | MEM_RESERVE,
        PAGE_READWRITE);

    TEST_ASSERT(NT_SUCCESS(status));
    if (!NT_SUCCESS(status))
        return;

    status = NtProtectVirtualMemory(
        NtCurrentProcess(),
        &memory,
        &size,
        PAGE_NOACCESS,
        &oldProtect);

    TEST_ASSERT(NT_SUCCESS(status));

    if (NT_SUCCESS(status)) {

        result = ntsupIsAddressValid(
            memory,
            sizeof(ULONG));

        TEST_ASSERT(result == FALSE);
    }

    NtFreeVirtualMemory(
        NtCurrentProcess(),
        &memory,
        &size,
        MEM_RELEASE);
}

VOID Test_IsAddressValid()
{
    g_FailCount = 0;

    IsAddressValid_ValidMemory();
    IsAddressValid_NullAddress();
    IsAddressValid_InvalidSize();
    IsAddressValid_FreedMemory();
    IsAddressValid_NoAccessMemory();

    if (g_Verbose) {
        if (g_FailCount == 0)
            DbgPrint("[TEST] ntsupIsAddressValid PASSED.\n");
        else
            DbgPrint("[TEST] ntsupIsAddressValid %lu tests FAILED.\n", g_FailCount);
    }
}

VOID UserIsFullAdmin_CompareWithNative()
{
    BOOLEAN expected = FALSE;
    BOOLEAN actual;

    HANDLE hToken;
    NTSTATUS status;
    ULONG returnLength;
    PTOKEN_GROUPS tokenGroups;
    DWORD i, attributes;

    SID_IDENTIFIER_AUTHORITY ntAuthority = SECURITY_NT_AUTHORITY;
    PSID administratorsSid = NULL;

    hToken = ntsupGetCurrentProcessToken();

    TEST_ASSERT(hToken != NULL);
    if (hToken == NULL)
        return;

    status = NtQueryInformationToken(
        hToken,
        TokenGroups,
        NULL,
        0,
        &returnLength);

    TEST_ASSERT(status == STATUS_BUFFER_TOO_SMALL ||
        status == STATUS_BUFFER_OVERFLOW);

    tokenGroups = (PTOKEN_GROUPS)ntsupHeapAlloc(returnLength);

    TEST_ASSERT(tokenGroups != NULL);
    if (tokenGroups == NULL) {
        NtClose(hToken);
        return;
    }

    status = NtQueryInformationToken(
        hToken,
        TokenGroups,
        tokenGroups,
        returnLength,
        &returnLength);

    TEST_ASSERT(NT_SUCCESS(status));

    if (NT_SUCCESS(status)) {

        status = RtlAllocateAndInitializeSid(
            &ntAuthority,
            2,
            SECURITY_BUILTIN_DOMAIN_RID,
            DOMAIN_ALIAS_RID_ADMINS,
            0, 0, 0, 0, 0, 0,
            &administratorsSid);

        TEST_ASSERT(NT_SUCCESS(status));

        if (NT_SUCCESS(status)) {

            for (i = 0; i < tokenGroups->GroupCount; i++) {

                if (RtlEqualSid(
                    administratorsSid,
                    tokenGroups->Groups[i].Sid))
                {
                    attributes = tokenGroups->Groups[i].Attributes;

                    expected =
                        ((attributes & SE_GROUP_ENABLED) != 0) &&
                        ((attributes & SE_GROUP_USE_FOR_DENY_ONLY) == 0);

                    break;
                }
            }

            RtlFreeSid(administratorsSid);
        }
    }

    ntsupHeapFree(tokenGroups);

    NtClose(hToken);

    actual = ntsupUserIsFullAdmin();

    TEST_ASSERT(actual == expected);
}

VOID Test_UserIsFullAdmin()
{
    g_FailCount = 0;

    UserIsFullAdmin_CompareWithNative();

    if (g_Verbose) {
        if (g_FailCount == 0)
            DbgPrint("[TEST] ntsupUserIsFullAdmin PASSED.\n");
        else
            DbgPrint("[TEST] ntsupUserIsFullAdmin %lu tests FAILED.\n", g_FailCount);
    }
}

VOID DuplicateUnicodeString_Valid(
    VOID
)
{
    NTSTATUS status;
    UNICODE_STRING src, dst;

    RtlInitUnicodeString(&src, L"TestUnicodeString");

    dst.Buffer = (PWSTR)0x12345678;
    dst.Length = 1;
    dst.MaximumLength = 1;

    status = ntsupDuplicateUnicodeString(&src, &dst);

    TEST_ASSERT(NT_SUCCESS(status));
    TEST_ASSERT(dst.Buffer != NULL);
    TEST_ASSERT(dst.Buffer != src.Buffer);
    TEST_ASSERT(dst.Length == src.Length);
    TEST_ASSERT(dst.MaximumLength == src.MaximumLength);

    TEST_ASSERT(RtlCompareMemory(
        dst.Buffer,
        src.Buffer,
        src.Length) == src.Length);

    ntsupHeapFree(dst.Buffer);
}

VOID DuplicateUnicodeString_Empty(
    VOID
)
{
    NTSTATUS status;
    UNICODE_STRING src, dst;

    src.Buffer = NULL;
    src.Length = 0;
    src.MaximumLength = 0;

    dst.Buffer = (PWSTR)0x12345678;
    dst.Length = 1;
    dst.MaximumLength = 1;

    status = ntsupDuplicateUnicodeString(&src, &dst);

    TEST_ASSERT(NT_SUCCESS(status));
    TEST_ASSERT(dst.Buffer == NULL);
    TEST_ASSERT(dst.Length == 0);
    TEST_ASSERT(dst.MaximumLength == 0);
}

VOID DuplicateUnicodeString_NullParameters(
    VOID
)
{
    NTSTATUS status;
    UNICODE_STRING src, dst;

    RtlInitUnicodeString(&src, L"Test");

    status = ntsupDuplicateUnicodeString(
        NULL,
        &dst);

    TEST_ASSERT(status == STATUS_INVALID_PARAMETER);

    status = ntsupDuplicateUnicodeString(
        &src,
        NULL);

    TEST_ASSERT(status == STATUS_INVALID_PARAMETER);
}

VOID DuplicateUnicodeString_InvalidLength(
    VOID
)
{
    NTSTATUS status;
    UNICODE_STRING src, dst;
    WCHAR buffer[8];

    src.Buffer = buffer;
    src.Length = sizeof(buffer);
    src.MaximumLength = sizeof(buffer) - sizeof(WCHAR);

    status = ntsupDuplicateUnicodeString(
        &src,
        &dst);

    TEST_ASSERT(status == STATUS_INVALID_PARAMETER);
}

VOID DuplicateUnicodeString_InvalidEmpty(
    VOID
)
{
    NTSTATUS status;
    UNICODE_STRING src, dst;

    src.Buffer = (PWSTR)L"ABC";
    src.Length = 0;
    src.MaximumLength = 0;

    status = ntsupDuplicateUnicodeString(
        &src,
        &dst);

    TEST_ASSERT(status == STATUS_INVALID_PARAMETER);
}

VOID DuplicateUnicodeString_NullBuffer(
    VOID
)
{
    NTSTATUS status;
    UNICODE_STRING src, dst;

    src.Buffer = NULL;
    src.Length = sizeof(WCHAR);
    src.MaximumLength = sizeof(WCHAR);

    status = ntsupDuplicateUnicodeString(
        &src,
        &dst);

    TEST_ASSERT(status == STATUS_INVALID_PARAMETER);
}

VOID DuplicateAnsiString_Valid(
    VOID
)
{
    NTSTATUS status;
    ANSI_STRING src, dst;

    RtlInitString(&src, (PCSZ)"TestAnsiString");

    dst.Buffer = (PCHAR)0x12345678;
    dst.Length = 1;
    dst.MaximumLength = 1;

    status = ntsupDuplicateAnsiString(&src, &dst);

    TEST_ASSERT(NT_SUCCESS(status));
    TEST_ASSERT(dst.Buffer != NULL);
    TEST_ASSERT(dst.Buffer != src.Buffer);
    TEST_ASSERT(dst.Length == src.Length);
    TEST_ASSERT(dst.MaximumLength == src.MaximumLength);

    TEST_ASSERT(RtlCompareMemory(
        dst.Buffer,
        src.Buffer,
        src.Length) == src.Length);

    ntsupHeapFree(dst.Buffer);
}

VOID DuplicateAnsiString_Empty(
    VOID
)
{
    NTSTATUS status;
    ANSI_STRING src, dst;

    src.Buffer = NULL;
    src.Length = 0;
    src.MaximumLength = 0;

    dst.Buffer = (PCHAR)0x12345678;
    dst.Length = 1;
    dst.MaximumLength = 1;

    status = ntsupDuplicateAnsiString(&src, &dst);

    TEST_ASSERT(NT_SUCCESS(status));
    TEST_ASSERT(dst.Buffer == NULL);
    TEST_ASSERT(dst.Length == 0);
    TEST_ASSERT(dst.MaximumLength == 0);
}

VOID DuplicateAnsiString_NullParameters(
    VOID
)
{
    NTSTATUS status;
    ANSI_STRING src, dst;

    RtlInitString(&src, (PCSZ)"Test");

    status = ntsupDuplicateAnsiString(
        NULL,
        &dst);

    TEST_ASSERT(status == STATUS_INVALID_PARAMETER);

    status = ntsupDuplicateAnsiString(
        &src,
        NULL);

    TEST_ASSERT(status == STATUS_INVALID_PARAMETER);
}

VOID DuplicateAnsiString_InvalidLength(
    VOID
)
{
    NTSTATUS status;
    ANSI_STRING src, dst;
    CHAR buffer[8];

    src.Buffer = buffer;
    src.Length = sizeof(buffer);
    src.MaximumLength = sizeof(buffer) - sizeof(CHAR);

    status = ntsupDuplicateAnsiString(
        &src,
        &dst);

    TEST_ASSERT(status == STATUS_INVALID_PARAMETER);
}

VOID DuplicateAnsiString_InvalidEmpty(
    VOID
)
{
    NTSTATUS status;
    ANSI_STRING src, dst;

    src.Buffer = (PCHAR)"ABC";
    src.Length = 0;
    src.MaximumLength = 0;

    status = ntsupDuplicateAnsiString(
        &src,
        &dst);

    TEST_ASSERT(status == STATUS_INVALID_PARAMETER);
}

VOID DuplicateAnsiString_NullBuffer(
    VOID
)
{
    NTSTATUS status;
    ANSI_STRING src, dst;

    src.Buffer = NULL;
    src.Length = sizeof(CHAR);
    src.MaximumLength = sizeof(CHAR);

    status = ntsupDuplicateAnsiString(
        &src,
        &dst);

    TEST_ASSERT(status == STATUS_INVALID_PARAMETER);
}

VOID Test_DuplicateUnicodeString()
{
    g_FailCount = 0;

    DuplicateUnicodeString_Valid();
    DuplicateUnicodeString_Empty();
    DuplicateUnicodeString_NullParameters();
    DuplicateUnicodeString_InvalidLength();
    DuplicateUnicodeString_InvalidEmpty();
    DuplicateUnicodeString_NullBuffer();

    if (g_Verbose) {
        if (g_FailCount == 0)
            DbgPrint("[TEST] ntsupDuplicateUnicodeString PASSED.\n");
        else
            DbgPrint("[TEST] ntsupDuplicateUnicodeString %lu tests FAILED.\n", g_FailCount);
    }
}

VOID Test_DuplicateAnsiString()
{
    g_FailCount = 0;

    DuplicateAnsiString_Valid();
    DuplicateAnsiString_Empty();
    DuplicateAnsiString_NullParameters();
    DuplicateAnsiString_InvalidLength();
    DuplicateAnsiString_InvalidEmpty();
    DuplicateAnsiString_NullBuffer();

    if (g_Verbose) {
        if (g_FailCount == 0)
            DbgPrint("[TEST] ntsupDuplicateAnsiString PASSED.\n");
        else
            DbgPrint("[TEST] ntsupDuplicateAnsiString %lu tests FAILED.\n", g_FailCount);
    }
}

PVOID NTAPI TestAllocFail(
    _In_ SIZE_T Size
)
{
    UNREFERENCED_PARAMETER(Size);

    return NULL;
}

VOID QueryProcessCommandLine_AllocationFailure(
    VOID
)
{
    NTSTATUS status;
    UNICODE_STRING commandLine;

    status = ntsupQueryProcessCommandLine(
        NtCurrentProcess(),
        &commandLine,
        TestAllocFail,
        ntsupHeapFree);

    TEST_ASSERT(status == STATUS_INSUFFICIENT_RESOURCES);
    TEST_ASSERT(commandLine.Buffer == NULL);
}

VOID QueryProcessCommandLine_CurrentProcess(
    VOID
)
{
    NTSTATUS status;
    UNICODE_STRING commandLine;

    commandLine.Buffer = (PWSTR)0x12345678;
    commandLine.Length = 1;
    commandLine.MaximumLength = 1;

    status = ntsupQueryProcessCommandLine(
        NtCurrentProcess(),
        &commandLine,
        ntsupHeapAlloc,
        ntsupHeapFree);

    TEST_ASSERT(NT_SUCCESS(status));

    if (NT_SUCCESS(status)) {

        TEST_ASSERT(commandLine.Buffer != NULL);
        TEST_ASSERT(commandLine.Length != 0);
        TEST_ASSERT(commandLine.MaximumLength >= commandLine.Length);
        TEST_ASSERT(commandLine.Buffer[commandLine.Length / sizeof(WCHAR)] == 0);

        ntsupHeapFree(commandLine.Buffer);
    }
}

VOID QueryProcessCommandLine_InvalidHandle(
    VOID
)
{
    NTSTATUS status;
    UNICODE_STRING commandLine;

    status = ntsupQueryProcessCommandLine(
        (HANDLE)0x1234,
        &commandLine,
        ntsupHeapAlloc,
        ntsupHeapFree);

    TEST_ASSERT(!NT_SUCCESS(status));
    TEST_ASSERT(commandLine.Buffer == NULL);
}

VOID QueryProcessCommandLine_NullParameters(
    VOID
)
{
    NTSTATUS status;
    UNICODE_STRING commandLine;

    status = ntsupQueryProcessCommandLine(
        NtCurrentProcess(),
        NULL,
        ntsupHeapAlloc,
        ntsupHeapFree);

    TEST_ASSERT(status == STATUS_INVALID_PARAMETER);

    status = ntsupQueryProcessCommandLine(
        NtCurrentProcess(),
        &commandLine,
        NULL,
        ntsupHeapFree);

    TEST_ASSERT(status == STATUS_INVALID_PARAMETER);

    status = ntsupQueryProcessCommandLine(
        NtCurrentProcess(),
        &commandLine,
        ntsupHeapAlloc,
        NULL);

    TEST_ASSERT(status == STATUS_INVALID_PARAMETER);
}

VOID Test_QueryProcessCommandLine()
{
    g_FailCount = 0;

    QueryProcessCommandLine_CurrentProcess();
    QueryProcessCommandLine_InvalidHandle();
    QueryProcessCommandLine_NullParameters();
    QueryProcessCommandLine_AllocationFailure();

    if (g_Verbose) {
        if (g_FailCount == 0)
            DbgPrint("[TEST] ntsupQueryProcessCommandLine PASSED.\n");
        else
            DbgPrint("[TEST] ntsupQueryProcessCommandLine %lu tests FAILED.\n", g_FailCount);
    }
}

VOID QueryResourceData_Valid(
    VOID
)
{
    ULONG dataSize = 0;
    PBYTE data;

    data = ntsupQueryResourceData(
        IDR_TEST_RCDATA,
        NtCurrentPeb()->ImageBaseAddress,
        &dataSize);

    TEST_ASSERT(data != NULL);
    TEST_ASSERT(dataSize != 0);

    if (data && dataSize >= sizeof("NativeTest") - 1) {

        TEST_ASSERT(RtlCompareMemory(
            data,
            "NativeTest",
            sizeof("NativeTest") - 1) ==
            sizeof("NativeTest") - 1);
    }
}

VOID QueryResourceData_InvalidId(
    VOID
)
{
    ULONG dataSize = 1234;
    PBYTE data;

    data = ntsupQueryResourceData(
        0x7fffffff,
        NtCurrentPeb()->ImageBaseAddress,
        &dataSize);

    TEST_ASSERT(data == NULL);
    TEST_ASSERT(dataSize == 0);
}

VOID QueryResourceData_NullModule(
    VOID
)
{
    ULONG dataSize = 1234;
    PBYTE data;

    data = ntsupQueryResourceData(
        IDR_TEST_RCDATA,
        NULL,
        &dataSize);

    TEST_ASSERT(data == NULL);
    TEST_ASSERT(dataSize == 0);
}

VOID QueryResourceData_NullSize(
    VOID
)
{
    PBYTE data;

    data = ntsupQueryResourceData(
        IDR_TEST_RCDATA,
        NtCurrentPeb()->ImageBaseAddress,
        NULL);

    TEST_ASSERT(data != NULL);
}

VOID Test_QueryResourceData()
{
    g_FailCount = 0;

    QueryResourceData_Valid();
    QueryResourceData_InvalidId();
    QueryResourceData_NullModule();
    QueryResourceData_NullSize();

    if (g_Verbose) {
        if (g_FailCount == 0)
            DbgPrint("[TEST] ntsupQueryResourceData PASSED.\n");
        else
            DbgPrint("[TEST] ntsupQueryResourceData %lu tests FAILED.\n", g_FailCount);
    }
}

VOID ResolveSymbolicLink_Valid(
    VOID
)
{
    BOOLEAN result;
    WCHAR buffer[260];
    UNICODE_STRING linkName;

    RtlSecureZeroMemory(buffer, sizeof(buffer));

    RtlInitUnicodeString(
        &linkName,
        L"\\??\\C:"
    );

    result = ntsupResolveSymbolicLink(
        NULL,
        &linkName,
        buffer,
        sizeof(buffer));

    TEST_ASSERT(result == TRUE);

    if (result) {
        TEST_ASSERT(buffer[0] != UNICODE_NULL);
    }
}

VOID ResolveSymbolicLink_InvalidLink(
    VOID
)
{
    BOOLEAN result;
    WCHAR buffer[260];
    UNICODE_STRING linkName;

    RtlSecureZeroMemory(buffer, sizeof(buffer));

    RtlInitUnicodeString(
        &linkName,
        L"\\??\\ThisLinkDoesNotExist"
    );

    result = ntsupResolveSymbolicLink(
        NULL,
        &linkName,
        buffer,
        sizeof(buffer));

    TEST_ASSERT(result == FALSE);
}

VOID ResolveSymbolicLink_InvalidBuffer(
    VOID
)
{
    BOOLEAN result;
    UNICODE_STRING linkName;

    RtlInitUnicodeString(
        &linkName,
        L"\\??\\C:"
    );

    result = ntsupResolveSymbolicLink(
        NULL,
        &linkName,
        NULL,
        sizeof(WCHAR));

    TEST_ASSERT(result == FALSE);
}

VOID ResolveSymbolicLink_ZeroBuffer(
    VOID
)
{
    BOOLEAN result;
    WCHAR buffer[16];
    UNICODE_STRING linkName;

    RtlSecureZeroMemory(buffer, sizeof(buffer));

    RtlInitUnicodeString(
        &linkName,
        L"\\??\\C:"
    );

    result = ntsupResolveSymbolicLink(
        NULL,
        &linkName,
        buffer,
        0);

    TEST_ASSERT(result == FALSE);
}

VOID ResolveSymbolicLink_SmallBuffer(
    VOID
)
{
    BOOLEAN result;
    WCHAR buffer[2];
    UNICODE_STRING linkName;

    RtlSecureZeroMemory(
        buffer,
        sizeof(buffer));

    RtlInitUnicodeString(
        &linkName,
        L"\\??\\C:"
    );

    result = ntsupResolveSymbolicLink(
        NULL,
        &linkName,
        buffer,
        sizeof(buffer));

    //
    // The buffer is intentionally too small for the target path.
    // NtQuerySymbolicLinkObject should fail with STATUS_BUFFER_TOO_SMALL.
    //
    TEST_ASSERT(result == FALSE);
    TEST_ASSERT(RtlGetLastWin32Error() == ERROR_INSUFFICIENT_BUFFER);
}

VOID Test_ResolveSymbolicLink()
{
    g_FailCount = 0;

    ResolveSymbolicLink_Valid();
    ResolveSymbolicLink_InvalidLink();
    ResolveSymbolicLink_InvalidBuffer();
    ResolveSymbolicLink_ZeroBuffer();
    ResolveSymbolicLink_SmallBuffer();

    if (g_Verbose) {
        if (g_FailCount == 0)
            DbgPrint("[TEST] ntsupResolveSymbolicLink PASSED.\n");
        else
            DbgPrint("[TEST] ntsupResolveSymbolicLink %lu tests FAILED.\n", g_FailCount);
    }
}

VOID LookupImageSectionByName_Valid(
    VOID
)
{
    PVOID section;
    ULONG sectionSize;
    PVOID imageBase;

    imageBase = NtCurrentPeb()->ImageBaseAddress;

    section = ntsupLookupImageSectionByName(
        (PSTR)".text",
        5,
        imageBase,
        &sectionSize);

    TEST_ASSERT(section != NULL);
    TEST_ASSERT(sectionSize != 0);

    if (section)
    {
        TEST_ASSERT(
            (ULONG_PTR)section >= (ULONG_PTR)imageBase);
    }
}

VOID LookupImageSectionByName_InvalidSection(
    VOID
)
{
    PVOID section;
    ULONG sectionSize;

    sectionSize = 0x1234;

    section = ntsupLookupImageSectionByName(
        (PSTR)".pe386",
        13,
        NtCurrentPeb()->ImageBaseAddress,
        &sectionSize);

    TEST_ASSERT(section == NULL);
    TEST_ASSERT(sectionSize == 0);
}

VOID LookupImageSectionByName_InvalidImage(
    VOID
)
{
    PVOID section;
    ULONG sectionSize;

    section = ntsupLookupImageSectionByName(
        (PSTR)".text",
        5,
        (PVOID)0x1234,
        &sectionSize);

    TEST_ASSERT(section == NULL);
    TEST_ASSERT(sectionSize == 0);
}

VOID LookupImageSectionByName_NullSize(
    VOID
)
{
    PVOID section;

    section = ntsupLookupImageSectionByName(
        (PSTR)".text",
        5,
        NtCurrentPeb()->ImageBaseAddress,
        NULL);

    TEST_ASSERT(section != NULL);
}

VOID LookupImageSectionByName_TruncatedName(
    VOID
)
{
    PVOID section;
    ULONG sectionSize;

    section = ntsupLookupImageSectionByName(
        (PSTR)".te",
        3,
        NtCurrentPeb()->ImageBaseAddress,
        &sectionSize);

    TEST_ASSERT(section != NULL);
}

VOID Test_LookupImageSectionByName()
{
    g_FailCount = 0;

    LookupImageSectionByName_Valid();
    LookupImageSectionByName_InvalidSection();
    LookupImageSectionByName_InvalidImage();
    LookupImageSectionByName_NullSize();
    LookupImageSectionByName_TruncatedName();

    if (g_Verbose) {
        if (g_FailCount == 0)
            DbgPrint("[TEST] ntsupLookupImageSectionByName PASSED.\n");
        else
            DbgPrint("[TEST] ntsupLookupImageSectionByName %lu tests FAILED.\n", g_FailCount);
    }
}

VOID QueryEnvironmentVariableOffset_Valid(
    VOID
)
{
    UNICODE_STRING value;
    LPWSTR result;
    WCHAR expectedPrefix[] = L"PATH=";

    RtlInitUnicodeString(
        &value,
        expectedPrefix);

    result = ntsupQueryEnvironmentVariableOffset(
        &value);

    TEST_ASSERT(result != NULL);

    if (result) {
        TEST_ASSERT(*result != UNICODE_NULL);
    }
}

VOID QueryEnvironmentVariableOffset_NotFound(
    VOID
)
{
    UNICODE_STRING value;
    LPWSTR result;

    RtlInitUnicodeString(
        &value,
        L"THIS_VARIABLE_DOES_NOT_EXIST=");

    result = ntsupQueryEnvironmentVariableOffset(
        &value);

    TEST_ASSERT(result == NULL);
}

VOID QueryEnvironmentVariableOffset_EmptyValue(
    VOID
)
{
    UNICODE_STRING value;
    LPWSTR result;

    ntsupSetEnvironmentVariable(
        L"NTSUP_EMPTY_TEST",
        L"");

    RtlInitUnicodeString(
        &value,
        L"NTSUP_EMPTY_TEST=");

    result = ntsupQueryEnvironmentVariableOffset(
        &value);

    TEST_ASSERT(result != NULL);

    if (result) {
        TEST_ASSERT(*result == UNICODE_NULL);
    }

    ntsupSetEnvironmentVariable(
        L"NTSUP_EMPTY_TEST",
        NULL);
}

VOID QueryEnvironmentVariableOffset_NullValue(
    VOID
)
{
    LPWSTR result;

    result = ntsupQueryEnvironmentVariableOffset(
        NULL);

    TEST_ASSERT(result == NULL);
}

VOID Test_QueryEnvironmentVariableOffset()
{
    g_FailCount = 0;

    QueryEnvironmentVariableOffset_Valid();
    QueryEnvironmentVariableOffset_NotFound();
    QueryEnvironmentVariableOffset_EmptyValue();
    QueryEnvironmentVariableOffset_NullValue();

    if (g_Verbose) {
        if (g_FailCount == 0)
            DbgPrint("[TEST] ntsupQueryEnvironmentVariableOffset PASSED.\n");
        else
            DbgPrint("[TEST] ntsupQueryEnvironmentVariableOffset %lu tests FAILED.\n", g_FailCount);
    }
}

VOID Tests_RunAll()
{
    Test_Sha256();
    Test_IsAddressValid();
    Test_LookupImageSectionByName();
    Test_QueryProcessCommandLine();
    Test_QueryResourceData();
    Test_ResolveSymbolicLink();
    Test_WriteBufferToFile();
    Test_FindModuleNameByAddress();
    Test_GetLoadedModulesListEx();
    Test_GetSystemInfoEx();
    Test_HashImageSections();
    Test_IsObjectExists();
    Test_UserIsFullAdmin();
    Test_DuplicateUnicodeString();
    Test_DuplicateAnsiString();
    Test_QueryEnvironmentVariableOffset();
}
