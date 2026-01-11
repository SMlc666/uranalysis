#pragma once

#include <string>

namespace client {

template<typename TState>
class WidgetBase {
public:
    explicit WidgetBase(const char* id) : id_(id) {}
    virtual ~WidgetBase() = default;
    
    virtual void render(TState& state) = 0;
    
protected:
    const char* id() const { return id_; }
    std::string make_id(const char* suffix) const {
        return std::string(suffix) + "##" + id_;
    }
    
private:
    const char* id_;
};

// Specialization for void state (stateless or internal state)
template<>
class WidgetBase<void> {
public:
    explicit WidgetBase(const char* id) : id_(id) {}
    virtual ~WidgetBase() = default;
    
    // No pure virtual render for void, subclasses define their own render methods
    
protected:
    const char* id() const { return id_; }
    std::string make_id(const char* suffix) const {
        return std::string(suffix) + "##" + id_;
    }
    
private:
    const char* id_;
};

}  // namespace client