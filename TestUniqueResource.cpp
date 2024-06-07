#define _CRT_SECURE_NO_WARNINGS

#include <assert.h>
#include <iostream>
#include <new>
#include <vector>

#include "./UniqueResource.h"

#include "./StdioTraits.h"

#ifdef _WIN32
#include "./Win32Traits.h"
#endif

#define OPENSSL_DEMO 1

#ifdef OPENSSL_DEMO
#define OPENSSL_NO_DEPRECATED
#define OPENSSL_NO_DEPRECATED_3_0
#include "./OpensslTraits.h"
#endif

void StdDemo()
{
    StdFileHandle f = MakeUniqueResource<StdFileHandle>(fopen(R"(c:\windows\system32\drivers\etc\hosts)", "rt"));
    assert((bool)f);
    if (!f)
        return;

    fseek((FILE *)f, 0, SEEK_END);
    const auto fileSize = ftell(f.Get());

    // better use MakeUniqueResource<T>() to get exception-safety.
    ByteArray buffer{new (std::nothrow) unsigned char[fileSize]};
    assert((bool)buffer);
    if (!buffer)
        return;

    fseek(f.Get(), 0, SEEK_SET);
    fread(buffer.Get(), fileSize, 1, f.Get());
}

void Win32Demo()
{
#ifdef _WIN32
    {
        DllHandle ntdll = MakeUniqueResource<DllHandle>(LoadLibrary(L"ntdll.dll"));
        assert((bool)ntdll);
        if (!ntdll)
            return;

        typedef LONG(WINAPI * fnRtlGetVersion)(PRTL_OSVERSIONINFOW lpVersionInformation);
        fnRtlGetVersion pRtlGetVersion = (fnRtlGetVersion)GetProcAddress(ntdll.Get(), "RtlGetVersion");
        assert(!pRtlGetVersion);
    }

    {
        WIN32_FIND_DATA findData;
        FindHandle findHandle = MakeUniqueResource<FindHandle>(FindFirstFile(LR"(c:\program files\*)", &findData));
        assert((bool)findHandle);
        if (!findHandle)
            return;

        do
        {
            std::wcout << findData.cFileName << std::endl;
        } while (FindNextFile(findHandle.Get(), &findData));
    }

    {
        RegKeyHandle key;

        if (ERROR_SUCCESS == RegOpenKeyExA(HKEY_LOCAL_MACHINE, R"(SYSTEM\CurrentControlSet\Control\SafeBoot\Network)",
                                           0, KEY_READ, &key))
        {
            char szName[MAX_PATH]{};

            for (DWORD dwIndex = 0; RegEnumKeyA(key.Get(), dwIndex, szName, _countof(szName) - 1) == ERROR_SUCCESS;
                 ++dwIndex)
            {
                RegKeyHandle subKey;
                if (RegOpenKeyExA(key.Get(), szName, 0, KEY_READ, &subKey) != ERROR_SUCCESS)
                    continue;
            }
        }
    }
#endif
}

#ifdef OPENSSL_DEMO

static constexpr size_t SM4_BLOCK_LEN = 16;

#define CHECK(x)                                                                                                       \
    {                                                                                                                  \
        static_assert(std::is_same<decltype(x), bool>::value);                                                         \
                                                                                                                       \
        if (!(x))                                                                                                      \
            return false;                                                                                              \
    }

template <class T> inline bool SafeResizeVector(std::vector<T> &v, size_t newSize)
{
    try
    {
        v.resize(newSize);
    }
    catch (const std::bad_alloc &e)
    {
        return false;
    }

    return true;
}

static constexpr uint8_t sm4Key[SM4_BLOCK_LEN] = {0x04, 0x50, 0x28, 0xe7, 0xe4, 0x97, 0x41, 0x06,
                                                  0xb8, 0x94, 0xb4, 0xae, 0xa1, 0xa3, 0x31, 0x67};

static constexpr uint8_t iv[SM4_BLOCK_LEN] = {0xb2, 0x8a, 0x50, 0x85, 0xdb, 0xc4, 0x44, 0x9e,
                                              0xb9, 0x34, 0xcc, 0x53, 0x85, 0x1b, 0x39, 0x43};

bool EncryptData(const std::vector<uint8_t> &in, std::vector<uint8_t> &out)
{
    EvpCipherCtx ctx;
    *(&ctx) = EVP_CIPHER_CTX_new();
    CHECK(!ctx.IsDefaultValue());

    // extra space for padding
    size_t capacity = in.size() + SM4_BLOCK_LEN * 2;
    CHECK(SafeResizeVector(out, capacity));

    CHECK(EVP_EncryptInit_ex(ctx.Get(), EVP_sm4_ecb(), nullptr, sm4Key, iv) > 0);
    int outlen = (int)capacity;
    CHECK(EVP_EncryptUpdate(ctx.Get(), &out[0], &outlen, &in[0], (int)in.size()) > 0);
    int outlen2 = (int)capacity - outlen;
    CHECK(EVP_EncryptFinal_ex(ctx.Get(), &out[outlen], &outlen2) > 0);

    assert(outlen + outlen2 <= (int)out.size());
    out.resize(outlen + outlen2);
    return true;
}

bool DecryptData(const std::vector<uint8_t> &in, std::vector<uint8_t> &out)
{
    EvpCipherCtx ctx;
    *(&ctx) = EVP_CIPHER_CTX_new();
    CHECK(!ctx.IsDefaultValue());

    CHECK(EVP_DecryptInit_ex(ctx.Get(), EVP_sm4_ecb(), nullptr, sm4Key, iv) > 0);

    const size_t bufferSize = in.size();
    CHECK(SafeResizeVector(out, bufferSize));

    int outlen = (int)bufferSize;
    CHECK(EVP_DecryptUpdate(ctx.Get(), &out[0], &outlen, in.data(), (int)in.size()) == 1);

    int outlen2 = (int)bufferSize - outlen;
    CHECK(EVP_DecryptFinal_ex(ctx.Get(), &out[outlen], &outlen2) == 1);
    const auto plaintextSize = outlen + outlen2;
    out.resize(plaintextSize);

    return true;
}

void OpensslDemo()
{
    std::vector<uint8_t> in{0x11, 0x22, 0x33, 0x44};

    std::vector<uint8_t> out;
    assert(EncryptData(in, out));

    std::vector<uint8_t> out2;
    assert(DecryptData(out, out2));

    assert(in.size() == out2.size());
    assert(!memcmp(in.data(), out2.data(), in.size()));
}

#endif

int main()
{
    StdDemo();
    Win32Demo();

#ifdef OPENSSL_DEMO
    OpensslDemo();
#endif

    return 0;
}