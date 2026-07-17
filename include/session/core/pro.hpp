#pragma once

#include <chrono>
#include <cstdint>
#include <span>

#include "component.hpp"

namespace session::pro_backend {
struct ProRevocationItem;
}
namespace session::core {

class Core;

class Pro final : detail::CoreComponent {
  public:
    /// API: core/Pro::pro_proof_is_revoked
    ///
    /// Check if the proof identified by its `revocation_tag` is revoked as of the given
    /// timestamp from the list of proofs stored in the database.
    ///
    /// Outputs:
    /// - `bool` -- True if the proof was revoked, false otherwise.
    bool proof_is_revoked(
            std::span<const std::byte, 32> revocation_tag,
            std::chrono::sys_time<std::chrono::milliseconds> unix_ts);

    /// API: core/Pro::pro_update_revocations
    ///
    /// Update the list of pro revocations.  If the `revocations_ticket` matches the current ticket,
    /// this is a no-op.
    ///
    /// Inputs:
    /// - `revocations_ticket` -- Ticket that describes the version of the revocations. This value
    ///   comes alongside the revocation list when queried.  This ticket changes whenever the
    ///   revocation list is updated and is used to identify when an actual update is needed.
    /// - `revocations` -- New list of Session Pro revocations.
    void update_revocations(
            uint32_t ticket, std::span<const pro_backend::ProRevocationItem> revocations);

  private:
    friend class Core;

    explicit Pro(Core& core) : detail::CoreComponent{core} {}

    // Stores the version of the revocation list that we last updated.  Used as an optimization to
    // short-circuit updates that are the same as the previous update.
    std::optional<uint32_t> revocations_ticket_;
};

}  // namespace session::core
