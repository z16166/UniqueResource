#pragma once

#include <windows.h>

#include <WinTrust.h>
#include <mscat.h>
#include <wincrypt.h>

// RegOpenKeyEx()/RegCreateKeyEx()/RegCloseKey()
struct RegKeyHandleTrait
{
    static constexpr HKEY default_value = nullptr;
    static void Cleanup(HKEY h) noexcept
    {
        RegCloseKey(h);
    }
};
using RegKeyHandle = UniqueResource<RegKeyHandleTrait, HKEY>;

// LoadLibrary()/FreeLibrary()
struct DllHandleTrait
{
    static constexpr HMODULE default_value = nullptr;
    static void Cleanup(HMODULE h) noexcept
    {
        FreeLibrary(h);
    }
};
using DllHandle = UniqueResource<DllHandleTrait, HMODULE>;

// CreateToolhelp32Snapshot()/CloseHandle()
struct ToolhelpSnapHandleTrait
{
    static constexpr HANDLE default_value = INVALID_HANDLE_VALUE;
    static void Cleanup(HANDLE h) noexcept
    {
        CloseHandle(h);
    }
};
using ToolhelpSnapHandle = UniqueResource<ToolhelpSnapHandleTrait, HANDLE>;

// OpenProcess()/CloseHandle()
struct ProcessHandleTrait
{
    static constexpr HANDLE default_value = nullptr;
    static void Cleanup(HANDLE h) noexcept
    {
        CloseHandle(h);
    }
};
using ProcessHandle = UniqueResource<ProcessHandleTrait, HANDLE>;

// OpenProcessToken()/OpenThreadToken()/CloseHandle()
struct TokenHandleTrait
{
    static constexpr HANDLE default_value = nullptr;
    static void Cleanup(HANDLE h) noexcept
    {
        CloseHandle(h);
    }
};
using TokenHandle = UniqueResource<TokenHandleTrait, HANDLE>;

// CreateFile()/CloseHandle()
struct FileHandleTrait
{
    static constexpr HANDLE default_value = INVALID_HANDLE_VALUE;
    static void Cleanup(HANDLE h) noexcept
    {
        CloseHandle(h);
    }
};
using FileHandle = UniqueResource<FileHandleTrait, HANDLE>;

// CreateFileMapping()/CloseHandle()
struct FileMappingHandleTrait
{
    static constexpr HANDLE default_value = nullptr;
    static void Cleanup(HANDLE h) noexcept
    {
        CloseHandle(h);
    }
};
using FileMappingHandle = UniqueResource<FileMappingHandleTrait, HANDLE>;

// CertOpenStore()/CertCloseStore()
struct CertStoreHandleTrait
{
    static constexpr HCERTSTORE default_value = nullptr;
    static void Cleanup(HCERTSTORE h) noexcept
    {
        CertCloseStore(h, 0);
    }
};
using CertStoreHandle = UniqueResource<CertStoreHandleTrait, HCERTSTORE>;

// CertFindCertificateInStore()/CertFreeCertificateContext()
struct CertContextHandleTrait
{
    static constexpr PCCERT_CONTEXT default_value = nullptr;
    static void Cleanup(PCCERT_CONTEXT ctx) noexcept
    {
        CertFreeCertificateContext(ctx);
    }
};
using CertContextHandle = UniqueResource<CertContextHandleTrait, PCCERT_CONTEXT>;

// CertGetCertificateChain()/CertFreeCertificateChain()
struct CertChainHandleTrait
{
    static constexpr PCCERT_CHAIN_CONTEXT default_value = nullptr;
    static void Cleanup(PCCERT_CHAIN_CONTEXT ctx) noexcept
    {
        CertFreeCertificateChain(ctx);
    }
};
using CertChainHandle = UniqueResource<CertChainHandleTrait, PCCERT_CHAIN_CONTEXT>;

// CryptMsgOpenToDecode()/CryptMsgClose()
struct CryptMsgHandleTrait
{
    static constexpr HCRYPTMSG default_value = nullptr;
    static void Cleanup(HCRYPTMSG h) noexcept
    {
        CryptMsgClose(h);
    }
};
using CryptMsgHandle = UniqueResource<CryptMsgHandleTrait, HCRYPTMSG>;

// CryptCATAdminAcquireContext()/CryptCATAdminReleaseContext()
struct CatalogHandleTrait
{
    static constexpr HCATADMIN default_value = nullptr;
    static void Cleanup(HCATADMIN h) noexcept
    {
        CryptCATAdminReleaseContext(h, 0);
    }
};
using CatalogHandle = UniqueResource<CatalogHandleTrait, HCATADMIN>;

// OpenSCManager()/OpenService()/CloseServiceHandle()
struct ServiceHandleTrait
{
    static constexpr SC_HANDLE default_value = nullptr;
    static void Cleanup(SC_HANDLE h) noexcept
    {
        CloseServiceHandle(h);
    }
};
using ServiceHandle = UniqueResource<ServiceHandleTrait, SC_HANDLE>;

// FindFirstFile()/FindClose()
struct FindHandleTrait
{
    static constexpr HANDLE default_value = INVALID_HANDLE_VALUE;
    static void Cleanup(HANDLE h) noexcept
    {
        FindClose(h);
    }
};
using FindHandle = UniqueResource<FindHandleTrait, HANDLE>;
