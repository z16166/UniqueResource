#pragma once

#include <openssl/bio.h>
#include <openssl/ec.h>
#include <openssl/evp.h>
#include <openssl/types.h>

// BIO_new_file()/BIO_free()
struct BioTrait
{
    static constexpr BIO *default_value = nullptr;
    static void Cleanup(BIO *h) noexcept
    {
        BIO_free(h);
    }
};
using BioHandle = UniqueResource<BioTrait, BIO *>;

//  EVP_CIPHER_CTX_new()/EVP_CIPHER_CTX_free()
struct EvpCipherCtxTrait
{
    static constexpr EVP_CIPHER_CTX *default_value = nullptr;
    static void Cleanup(EVP_CIPHER_CTX *ctx) noexcept
    {
        EVP_CIPHER_CTX_free(ctx);
    }
};
using EvpCipherCtx = UniqueResource<EvpCipherCtxTrait, EVP_CIPHER_CTX *>;

// EVP_PKEY_new()/EVP_PKEY_free()
struct EvpPkeyTrait
{
    static constexpr EVP_PKEY *default_value = nullptr;
    static void Cleanup(EVP_PKEY *pkey) noexcept
    {
        EVP_PKEY_free(pkey);
    }
};
using EvpPkey = UniqueResource<EvpPkeyTrait, EVP_PKEY *>;

// EVP_MD_CTX_new()/EVP_MD_CTX_free()
struct EvpMdCtxTrait
{
    static constexpr EVP_MD_CTX *default_value = nullptr;
    static void Cleanup(EVP_MD_CTX *ctx) noexcept
    {
        EVP_MD_CTX_free(ctx);
    }
};
using EvpMdCtx = UniqueResource<EvpMdCtxTrait, EVP_MD_CTX *>;

// EVP_PKEY_CTX_new()/EVP_PKEY_CTX_free()
struct EvpPkeyCtxTrait
{
    static constexpr EVP_PKEY_CTX *default_value = nullptr;
    static void Cleanup(EVP_PKEY_CTX *ctx) noexcept
    {
        EVP_PKEY_CTX_free(ctx);
    }
};
using EvpPkeyCtx = UniqueResource<EvpPkeyCtxTrait, EVP_PKEY_CTX *>;

// EC_KEY_new_by_curve_name()/EC_KEY_free()
// struct EcKeyTrait {
//    static constexpr EC_KEY* default_value = nullptr;
//    static void Cleanup(EC_KEY* key) noexcept { EC_KEY_free(key); }
//};
// using EcKey = UniqueResource<EcKeyTrait, EC_KEY*>;

// EC_GROUP_new_by_curve_name()/EC_GROUP_free()
struct EcGroupTrait
{
    static constexpr EC_GROUP *default_value = nullptr;
    static void Cleanup(EC_GROUP *g) noexcept
    {
        EC_GROUP_free(g);
    }
};
using EcGroup = UniqueResource<EcGroupTrait, EC_GROUP *>;
