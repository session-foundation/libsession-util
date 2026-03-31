#pragma once

#include <stdexcept>
#include <string>

extern "C" {
#include <arpa/inet.h>
#include <netdb.h>
}

namespace session::test {

// Resolves a hostname to an IP address string via getaddrinfo.  This is needed because libquic
// does not perform DNS resolution.
inline std::string resolve_host(const std::string& host) {
    struct addrinfo hints {};
    hints.ai_family = AF_UNSPEC;
    hints.ai_socktype = SOCK_DGRAM;

    struct addrinfo* res = nullptr;
    if (int rc = getaddrinfo(host.c_str(), nullptr, &hints, &res); rc != 0 || !res)
        throw std::runtime_error{
                "Failed to resolve '" + host + "': " +
                (rc ? gai_strerror(rc) : "no results")};

    char buf[INET6_ADDRSTRLEN]{};
    if (res->ai_family == AF_INET6)
        inet_ntop(
                AF_INET6,
                &reinterpret_cast<sockaddr_in6*>(res->ai_addr)->sin6_addr,
                buf,
                sizeof(buf));
    else
        inet_ntop(
                AF_INET,
                &reinterpret_cast<sockaddr_in*>(res->ai_addr)->sin_addr,
                buf,
                sizeof(buf));

    freeaddrinfo(res);
    return buf;
}

}  // namespace session::test
