#pragma once

#include <atomic>
#include <cstdint>

namespace engine::plugin {

/// Base interface for all plugin objects with reference counting.
/// 
/// All objects that cross the plugin boundary must inherit from this.
/// This ensures proper lifetime management regardless of which module
/// (host or plugin) allocated the object.
///
/// Rules:
/// - When you receive an IObject*, you don't own it unless documented
/// - If you need to keep a reference, call retain()
/// - When done with a retained reference, call release()
/// - Objects are deleted when refcount reaches zero
struct IObject {
    virtual ~IObject() = default;

    /// Increment the reference count
    virtual void retain() = 0;

    /// Decrement the reference count. Object is deleted when count reaches 0.
    virtual void release() = 0;

    /// Get current reference count (for debugging only)
    virtual std::int32_t ref_count() const = 0;
};

/// Base implementation of IObject with atomic reference counting.
/// 
/// Plugin authors should inherit from this when creating objects
/// that need to be passed to the host.
class ObjectBase : public IObject {
public:
    ObjectBase() : ref_count_(1) {}
    virtual ~ObjectBase() = default;

    void retain() override {
        ref_count_.fetch_add(1, std::memory_order_relaxed);
    }

    void release() override {
        if (ref_count_.fetch_sub(1, std::memory_order_acq_rel) == 1) {
            delete this;
        }
    }

    std::int32_t ref_count() const override {
        return ref_count_.load(std::memory_order_relaxed);
    }

protected:
    std::atomic<std::int32_t> ref_count_;
};

/// Smart pointer for IObject that automatically manages retain/release.
/// Similar to std::shared_ptr but works across plugin boundaries.
template <typename T>
class Ref {
public:
    Ref() : ptr_(nullptr) {}
    
    explicit Ref(T* ptr, bool add_ref = true) : ptr_(ptr) {
        if (ptr_ && add_ref) {
            ptr_->retain();
        }
    }

    Ref(const Ref& other) : ptr_(other.ptr_) {
        if (ptr_) {
            ptr_->retain();
        }
    }

    Ref(Ref&& other) noexcept : ptr_(other.ptr_) {
        other.ptr_ = nullptr;
    }

    ~Ref() {
        if (ptr_) {
            ptr_->release();
        }
    }

    Ref& operator=(const Ref& other) {
        if (this != &other) {
            if (ptr_) {
                ptr_->release();
            }
            ptr_ = other.ptr_;
            if (ptr_) {
                ptr_->retain();
            }
        }
        return *this;
    }

    Ref& operator=(Ref&& other) noexcept {
        if (this != &other) {
            if (ptr_) {
                ptr_->release();
            }
            ptr_ = other.ptr_;
            other.ptr_ = nullptr;
        }
        return *this;
    }

    T* get() const { return ptr_; }
    T* operator->() const { return ptr_; }
    T& operator*() const { return *ptr_; }
    explicit operator bool() const { return ptr_ != nullptr; }

    /// Release ownership without decrementing refcount
    T* detach() {
        T* tmp = ptr_;
        ptr_ = nullptr;
        return tmp;
    }

    /// Reset to a new pointer
    void reset(T* ptr = nullptr, bool add_ref = true) {
        if (ptr_) {
            ptr_->release();
        }
        ptr_ = ptr;
        if (ptr_ && add_ref) {
            ptr_->retain();
        }
    }

private:
    T* ptr_;
};

/// Create a Ref from a raw pointer without adding a reference.
/// Use when the pointer already has a reference counted for you.
template <typename T>
Ref<T> adopt_ref(T* ptr) {
    return Ref<T>(ptr, false);
}

/// Create a Ref from a raw pointer, adding a reference.
template <typename T>
Ref<T> make_ref(T* ptr) {
    return Ref<T>(ptr, true);
}

}  // namespace engine::plugin
