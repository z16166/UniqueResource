#pragma once

#include <stdio.h>

// for new[]/delete[].
// mainly for "new (std::nothrow) E[number]", or "new E[number]".
// if "number" is controlled by malicious users, we have 2 ways to prevent our program from crash:
//     1. use "new E[number]", and catch std::bad_alloc.
//     2. use "new (std::nothrow) E[number]" and check the returned pointer against nullptr.
template <class T> struct ArrayTrait
{
    typedef typename std::remove_extent<T>::type E;
    static constexpr E *default_value = nullptr;
    static void Cleanup(E *p) noexcept
    {
        static_assert(std::is_array<T>::value, "please specify array type");
        delete[] p;
    }
};
using ByteArray = UniqueResource<ArrayTrait<unsigned char[]>, unsigned char *>;
using CharArray = UniqueResource<ArrayTrait<char[]>, char *>;
using WcharArray = UniqueResource<ArrayTrait<wchar_t[]>, wchar_t *>;

// for fopen()/fclose(), C-style file I/O.
struct StdFileHandleTrait
{
    static constexpr FILE *default_value = nullptr;
    static void Cleanup(FILE *f) noexcept
    {
        fclose(f);
    }
};
using StdFileHandle = UniqueResource<StdFileHandleTrait, FILE *>;
