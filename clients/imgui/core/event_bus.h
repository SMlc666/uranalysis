#pragma once

#include <any>
#include <functional>
#include <typeindex>
#include <unordered_map>
#include <vector>
#include <memory>

namespace client {

class EventBus {
public:
    using SubscriptionId = std::uint64_t;
    using Handler = std::function<void(const std::any&)>;

    template<typename TEvent>
    SubscriptionId subscribe(std::function<void(const TEvent&)> handler) {
        auto type = std::type_index(typeid(TEvent));
        auto wrapped_handler = [handler](const std::any& event) {
            handler(std::any_cast<const TEvent&>(event));
        };
        
        SubscriptionId id = next_id_++;
        handlers_[type].emplace_back(id, wrapped_handler);
        return id;
    }

    template<typename TEvent>
    void unsubscribe(SubscriptionId id) {
        auto type = std::type_index(typeid(TEvent));
        auto it = handlers_.find(type);
        if (it != handlers_.end()) {
            auto& list = it->second;
            for (auto list_it = list.begin(); list_it != list.end(); ++list_it) {
                if (list_it->first == id) {
                    list.erase(list_it);
                    return;
                }
            }
        }
    }

    template<typename TEvent>
    void publish(const TEvent& event) {
        auto type = std::type_index(typeid(TEvent));
        auto it = handlers_.find(type);
        if (it != handlers_.end()) {
            std::any any_event = event;
            for (const auto& [id, handler] : it->second) {
                handler(any_event);
            }
        }
    }

    template<typename TEvent>
    class ScopedSubscription {
    public:
        ScopedSubscription(EventBus& bus, std::function<void(const TEvent&)> handler)
            : bus_(bus), id_(bus.subscribe<TEvent>(handler)) {}
        
        ~ScopedSubscription() {
            bus_.unsubscribe<TEvent>(id_);
        }

        // Prevent copying
        ScopedSubscription(const ScopedSubscription&) = delete;
        ScopedSubscription& operator=(const ScopedSubscription&) = delete;

        // Allow moving
        ScopedSubscription(ScopedSubscription&& other) noexcept
            : bus_(other.bus_), id_(other.id_) {
            other.id_ = 0; // Invalid ID
        }

    private:
        EventBus& bus_;
        SubscriptionId id_;
    };

private:
    std::unordered_map<std::type_index, std::vector<std::pair<SubscriptionId, Handler>>> handlers_;
    SubscriptionId next_id_ = 1;
};

}  // namespace client