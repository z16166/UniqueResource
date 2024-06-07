#pragma once

#include <type_traits>

template <typename ResourceTrait, typename ResourceType> class UniqueResource
{
  public:
    typedef ResourceType ValueType;

    UniqueResource() noexcept : resource_{DefaultValue()}
    {
    }

    explicit UniqueResource(ResourceType resource) noexcept : resource_{resource}
    {
    }

    UniqueResource(const UniqueResource &) = delete;

    UniqueResource &operator=(const UniqueResource &) = delete;

    UniqueResource(UniqueResource &&other) noexcept : resource_{other.resource_}
    {
        assert(this != std::addressof(other));
        other.resource_ = DefaultValue();
    }

    UniqueResource &operator=(UniqueResource &&other) noexcept
    {
        assert(this != std::addressof(other));

        Cleanup();
        resource_ = other.resource_;
        other.resource_ = DefaultValue();
        return *this;
    }

    ~UniqueResource() noexcept
    {
        Cleanup();
    }

    ResourceType *operator&() noexcept
    {
        Cleanup();
        return &resource_;
    }

    ResourceType Get() const noexcept
    {
        return resource_;
    }

    bool IsDefaultValue() const noexcept
    {
        return resource_ == DefaultValue();
    }

    void Release() noexcept
    {
        Cleanup();
        resource_ = DefaultValue();
    }

    explicit operator bool() const noexcept
    {
        return resource_ != DefaultValue();
    }
    bool operator!() const noexcept
    {
        return resource_ == DefaultValue();
    }

  private:
    void Cleanup() noexcept
    {
        if (resource_ != DefaultValue())
            ResourceTrait::Cleanup(resource_);
    }

    static constexpr ResourceType DefaultValue() noexcept
    {
        return ResourceTrait::default_value;
    }

    ResourceType resource_;
};

// just like std::make_unique<T>(), for exception-safety.
template <typename T> T MakeUniqueResource(typename T::ValueType value)
{
    return T{value};
}
