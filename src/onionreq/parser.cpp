#include "session/onionreq/parser.hpp"

#include <oxenc/endian.h>
#include <sodium/core.h>

#include <nlohmann/json.hpp>
#include <stdexcept>

namespace session::onionreq {

OnionReqParser::OnionReqParser(uspan x25519_pk, uspan x25519_sk, uspan req, size_t max_size) :
        keys{x25519_pubkey::from_bytes(x25519_pk), x25519_seckey::from_bytes(x25519_sk)},
        enc{keys.second, keys.first} {
    if (sodium_init() == -1)
        throw std::runtime_error{"Failed to initialize libsodium!"};
    if (req.size() < sizeof(uint32_t))
        throw std::invalid_argument{"onion request data too small"};
    if (req.size() > max_size)
        throw std::invalid_argument{"onion request data too big"};
    auto size = oxenc::load_little_to_host<uint32_t>(req.data());
    req = req.subspan(sizeof(size));

    if (req.size() < size)
        throw std::invalid_argument{"encrypted onion request data segment too small"};
    auto ciphertext = req.subspan(0, size);
    req = req.subspan(size);
    auto metadata = nlohmann::json::parse(req);

    if (auto encit = metadata.find("enc_type"); encit != metadata.end())
        enc_type = parse_enc_type(encit->get<std::string_view>());
    // else leave it at the backwards-compat AES-GCM default

    if (auto itr = metadata.find("ephemeral_key"); itr != metadata.end())
        remote_pk = parse_x25519_pubkey(itr->get<std::string>());
    else
        throw std::invalid_argument{"metadata does not have 'ephemeral_key' entry"};

    payload_ = enc.decrypt(enc_type, span_to_vec<unsigned char>(ciphertext), remote_pk);
}

std::vector<unsigned char> OnionReqParser::encrypt_reply(uspan reply) const {
    return enc.encrypt(enc_type, span_to_vec<unsigned char>(reply), remote_pk);
}

}  // namespace session::onionreq
