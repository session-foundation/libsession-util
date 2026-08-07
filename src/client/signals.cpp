#include <session/client/signals.hpp>

namespace session::client {

Subscription& Subscription::operator=(Subscription&& other) noexcept {
    if (this != &other) {
        reset();
        _registry = std::move(other._registry);
        _id = other._id;
        other._registry.reset();
        other._id = 0;
    }
    return *this;
}

void Subscription::reset() {
    if (_id != 0) {
        if (auto reg = _registry.lock())
            reg->handlers.erase(_id);
        _id = 0;
    }
    _registry.reset();
}

}  // namespace session::client
