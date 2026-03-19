#pragma once

#include <session/pro_backend.h>

#include <chrono>
#include <session/session_protocol.hpp>
#include <session/types.hpp>
#include <span>
#include <string>

/// Helper functions to construct payloads to communicate with the Session Pro Backend. The data
/// structures here are largely bindings to the endpoints exposed on the Session Pro Backend:
///
///   https://github.com/Doy-lee/session-pro-backend/blob/06e82c9d5b5a0a881d12d0182358219a4081acf5/server.py#L2
///
/// The high level summary of the functionality in this file. Clients can:
///
/// 1. Build a request with `AddProPaymentRequest::build_to_json` from a Session Pro payment and
///    submit it to the backend to register the specified Ed25519 keys for Session Pro.
///
///    Server responds JSON to be parsed with `AddProPaymentOrGenerateProProofResponse::parse`.
///    Clients should validate the response and update their `UserProfile` by constructing a
///    `ProConfig` with the `proof` from the response and filling in the relevant rotating private
///    key that the proof was authorised for.
///
///    The server will only respond successfully if it can also independently verify the purchase
///    otherwise an error is returned and can be read from the `ResponseHeader` after parsing the
///    raw response.
///
/// 2. Attach the `ProProof` constructed from (1) into their messages. Libsession has helper
///    functions to embed the proof into their messages via the helper functions in the Session
///    Protocol header file. This is done by assigning the `ProProof` into the
///    `Content.proMessage.proof` protobuf structure. Additionally the caller will use
///    `pro_features_for_utf8/16` to determine the correct flags to assign the `features` to
///    `Content.proMessage.flags` in the protobuf structure.
///
///    Lastly the high-level libsession encoding functions accept the rotating private key to which
///    the protobuf encoded plaintext content will be signed and the payload augmented as necessary
///    to enable pro features for that message.
///
/// 3. Periodically poll the global revocation list which overrides the validity of current
///    circulating proofs. This is done by constructing the request via
///    `GetProRevocationsRequest::to_json` and sending it to the backend.
///
///    Server responds JSON to be parsed with `GetProRevocationResponse::parse` which contains the
///    list that clients should cache. Any incoming messages with a Pro proof that is in the list of
///    revoked proofs will not be entitled to Pro features.
///
/// 4. Query the status (and optionally payment history) of a user's Session Pro Master Ed25519 key
///    has registered by building a `GetProDetailsRequest::build_to_json` query and submitting it.
///
///    Server responds JSON to be parsed with `GetProDetailsResponse::parse` which they can use to
///    populate their client's payment history.
///
/// 5. Get a list of per-payment provider URLs, such as links to the support page for refunds and
///    subscription via the `PAYMENT_PROVIDER_METADATA` global variable defined in the C header.
///
/// See the unit tests for examples of using the APIs mentioned.

namespace session::pro_backend {

/// TODO: Assign the Session Pro backend public key for verifying proofs to allow users of the
/// library to have the pubkey available for verifying proofs.
constexpr array_uc32 PUBKEY = {0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                               0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00,
                               0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00, 0x00};
static_assert(sizeof(PUBKEY) == array_uc32{}.size());

enum struct AddProPaymentResponseStatus {
    /// Payment was claimed and the pro proof was successfully generated
    Success = SESSION_PRO_BACKEND_ADD_PRO_PAYMENT_RESPONSE_STATUS_SUCCESS,

    /// Backend encountered an error when attempting to claim the payment
    Error = SESSION_PRO_BACKEND_ADD_PRO_PAYMENT_RESPONSE_STATUS_ERROR,

    /// Request JSON failed to be parsed correctly, payload was malformed or missing values
    ParseError = SESSION_PRO_BACKEND_ADD_PRO_PAYMENT_RESPONSE_STATUS_PARSE_ERROR,

    /// Payment is already claimed
    AlreadyRedeemed = SESSION_PRO_BACKEND_ADD_PRO_PAYMENT_RESPONSE_STATUS_ALREADY_REDEEMED,

    /// Payment transaction attempted to claim a payment that the backend does not have. Either the
    /// payment doesn't exist or the backend has not witnessed the payment from the provider yet.
    UnknownPayment = SESSION_PRO_BACKEND_ADD_PRO_PAYMENT_RESPONSE_STATUS_UNKNOWN_PAYMENT,
};

struct ResponseHeader {
    /// Status code for the response, maps to a specific enum for some requests otherwise it uses 0
    /// for success, other values indicate errors. For the following responses, the status code maps
    /// to
    ///
    ///  | Request            | Enum
    ///  | AddProPayment      | AddProPaymentResponseStatus
    ///  | Everything else ...| SESSION_PRO_BACKEND_STATUS_SUCCESS or
    ///                         SESSION_PRO_BACKEND_STATUS_ERROR
    std::uint32_t status;

    /// List of parsing or processing errors. Empty if there are no parsing errors, if there are
    /// errors, the parse may be partially complete, always check the errors before proceeding.
    std::vector<std::string> errors;
};

struct MasterRotatingSignatures {
    array_uc64 master_sig;
    array_uc64 rotating_sig;
};

struct AddProPaymentUserTransaction {
    SESSION_PRO_BACKEND_PAYMENT_PROVIDER provider;

    /// The payment ID to claim which is different per platform.
    ///
    ///   Google Play Store => purchase token
    ///   iOS App Store     => transaction ID (note, not the original transaction id)
    std::string payment_id;

    /// Only for Google Play Store, set this to the purchase's order ID. Ignored for other payment
    /// providers
    std::string order_id;
};

/// Register a new Session Pro proof to the backend. The payment is registered under the
/// `master_pkey` and authorises the `rotating_pkey` to use the proof. In practice this means that
/// the caller will receive a Session Pro Proof that can be attached to messages that have to be
/// signed by the `rotating_pkey` for other clients to entitle that message to Pro privileges.
///
/// The attached signatures must sign over the contents of the request which can be generated by the
/// helper function `build_sigs`.
struct AddProPaymentRequest {
    /// Request version. The latest accepted version is 0
    std::uint8_t version;

    /// 32-byte Ed25519 Session Pro master public key derived from the Session account seed to
    /// register a Session Pro payment under.
    array_uc32 master_pkey;

    /// 32-byte Ed25519 Session Pro rotating public key to authorise to use the generated Session
    /// Pro proof
    array_uc32 rotating_pkey;

    /// Transaction containing the payment details to register on the Session Pro backend
    AddProPaymentUserTransaction payment_tx;

    /// 64-byte signature proving knowledge of the master key's secret component
    array_uc64 master_sig;

    /// 64-byte signature proving knowledge of the rotating key's secret component
    array_uc64 rotating_sig;

    /// API: pro/AddProPaymentRequest::to_json
    ///
    /// Serializes the request to a JSON string.
    ///
    /// Outputs:
    /// - `std::string` - JSON representation of the request.
    std::string to_json() const;

    /// API: pro/AddProPaymentRequest::build_sigs
    ///
    /// Builds the master and rotating signatures using the provided private keys and payment token
    /// hash. Throws if the keys (32-byte or 64-byte libsodium format) are incorrectly sized.
    /// Using 64-byte libsodium keys is more efficient.
    ///
    /// Inputs:
    /// - `request_version` -- Version of the request to build a hash for
    /// - `master_privkey` -- 64-byte libsodium style or 32 byte Ed25519 master private key
    /// - `rotating_privkey` -- 64-byte libsodium style or 32 byte Ed25519 rotating private key
    /// - `payment_tx_provider` -- Provider that the payment to register is coming from
    /// - `payment_tx_payment_id` -- ID that is associated with the payment from the payment
    ///   provider. See `AddProPaymentUserTransaction`
    ///   this is the transaction ID).
    /// - `payment_tx_order_id` -- Order ID that is associated with the payment see
    ///   `AddProPaymentUserTransaction`
    ///
    /// Outputs:
    /// - `MasterRotatingSignatures` - Struct containing the 64-byte master and rotating signatures.
    static MasterRotatingSignatures build_sigs(
            std::uint8_t request_version,
            std::span<const uint8_t> master_privkey,
            std::span<const uint8_t> rotating_privkey,
            SESSION_PRO_BACKEND_PAYMENT_PROVIDER payment_tx_provider,
            std::span<const uint8_t> payment_tx_payment_id,
            std::span<const uint8_t> payment_tx_order_id);

    /// API: pro/AddProPaymentRequest::build_to_json
    ///
    /// Builds a AddProPaymentRequest and serialize it to JSON. This function is the same as filling
    /// the struct fields and calling `to_json`.
    ///
    /// Inputs:
    /// - `request_version` -- Version of the request to build a hash for
    /// - `master_privkey` -- 64-byte libsodium style or 32 byte Ed25519 master private key
    /// - `rotating_privkey` -- 64-byte libsodium style or 32 byte Ed25519 rotating private key
    /// - `payment_tx_provider` -- Provider that the payment to register is coming from
    /// - `payment_tx_payment_id` -- ID that is associated with the payment from the payment
    ///   provider. See `AddProPaymentUserTransaction`
    ///   this is the transaction ID).
    /// - `payment_tx_order_id` -- Order ID that is associated with the payment see
    ///   `AddProPaymentUserTransaction`
    ///
    /// Outputs:
    /// - `std::string` -- Request serialised to JSON
    static std::string build_to_json(
            std::uint8_t request_version,
            std::span<const uint8_t> master_privkey,
            std::span<const uint8_t> rotating_privkey,
            SESSION_PRO_BACKEND_PAYMENT_PROVIDER payment_tx_provider,
            std::span<const uint8_t> payment_tx_payment_id,
            std::span<const uint8_t> payment_tx_order_id);
};

/// The generated proof from the Session Pro backend that has been parsed from JSON. This structure
/// is the raw parse result that can then be converted into the config::ProProof or equivalent
/// structure.
struct AddProPaymentOrGenerateProProofResponse : public ResponseHeader {
    ProProof proof;

    /// API: pro/AddProPaymentOrGenerateProProofResponse::parse
    ///
    /// Parses a JSON string into the response struct.
    ///
    /// Inputs:
    /// - `json` -- JSON string to parse.
    ///
    /// Outputs:
    /// - The response struct with `status` set to an error state on failure. Errors are stored in
    ///   `errors`
    static AddProPaymentOrGenerateProProofResponse parse(std::string_view json);
};

/// Request a new Session Pro proof from the backend. The specified `master_pkey` must have
/// previously already registered a payment to the backend that is still active and hence entitled
/// to Session Pro features. This endpoint can then be used to pair a new Ed25519 key to be
/// authorised to use a the Session Pro proof.
struct GenerateProProofRequest {
    /// Request version. The latest accepted version is 0
    std::uint8_t version;

    /// 32-byte Ed25519 Session Pro master public key to generate a Session Pro proof from. This key
    /// must have had a prior, and still active payment registered under it for a new proof to be
    /// generated successfully.
    array_uc32 master_pkey;

    /// 32-byte Ed25519 Session Pro rotating public key authorized to use the generated proof
    array_uc32 rotating_pkey;

    /// Unix timestamp of the request
    sys_ms unix_ts;

    /// 64-byte signature proving knowledge of the master key's secret component
    array_uc64 master_sig;

    /// 64-byte signature proving knowledge of the rotating key's secret component
    array_uc64 rotating_sig;

    /// API: pro/GenerateProProofRequest::build_sigs
    ///
    /// Builds master and rotating signatures using the provided private keys and timestamp.
    /// Throws if the keys (32-byte or 64-byte libsodium format) are incorrectly sized.
    /// Using 64-byte libsodium keys is more efficient.
    ///
    /// Inputs:
    /// - `request_version` -- Version of the request to build a hash for
    /// - `master_privkey` -- 64-byte libsodium style or 32 byte Ed25519 master private key
    /// - `rotating_privkey` -- 64-byte libsodium style or 32 byte Ed25519 rotating private key
    /// - `unix_ts` -- Unix timestamp for the request.
    ///
    /// Outputs:
    /// - `MasterRotatingSignatures` - Struct containing the 64-byte master and rotating signatures.
    static MasterRotatingSignatures build_sigs(
            std::uint8_t request_version,
            std::span<const uint8_t> master_privkey,
            std::span<const uint8_t> rotating_privkey,
            sys_ms unix_ts);

    /// API: pro/GenerateProProofRequest::build_to_json
    ///
    /// Builds a GenerateProProofRequest and serialize it to JSON. This function is the same as
    /// filling the struct fields and calling `to_json`.
    ///
    /// Inputs:
    /// - `request_version` -- Version of the request to build a request for
    /// - `master_privkey` -- 64-byte libsodium style or 32 byte Ed25519 master private key
    /// - `rotating_privkey` -- 64-byte libsodium style or 32 byte Ed25519 rotating private key
    /// - `unix_ts` -- Unix timestamp for the request.
    ///
    /// Outputs:
    /// - `std::string` -- Request serialised to JSON
    static std::string build_to_json(
            std::uint8_t request_version,
            std::span<const uint8_t> master_privkey,
            std::span<const uint8_t> rotating_privkey,
            sys_ms unix_ts);

    /// API: pro/GenerateProProofRequest::to_json
    ///
    /// Serializes the request to a JSON string.
    ///
    /// Outputs:
    /// - `std::string` - JSON representation of the request.
    std::string to_json() const;
};

/// Retrieve the current list of revocations for currently active Session Pro proofs (because of
/// refunds for example). The caller should maintain this list until the revocation has expiry and
/// periodically retrieve this list from the backend every hour.
struct GetProRevocationsRequest {
    /// Request version. The latest accepted version is 0
    std::uint8_t version;

    /// 4-byte monotonic integer for the caller's revocation list iteration. Set to 0 if unknown;
    /// otherwise, use the latest known `ticket` from a prior `GetProRevocationResponse` to allow
    /// the Session Pro Backend to omit the revocation list if it has not changed.
    std::uint32_t ticket;

    /// API: pro/GenerateProProofRequest::to_json
    ///
    /// Serializes the request to a JSON string.
    ///
    /// Outputs:
    /// - `std::string` - JSON representation of the request.
    std::string to_json() const;
};

struct ProRevocationItem {
    /// 32-byte hash of the generation index, identifying a proof
    array_uc32 gen_index_hash;

    /// Unix timestamp when the proof expires
    sys_ms expiry_unix_ts;
};

struct GetProRevocationsResponse : public ResponseHeader {
    /// 4-byte monotonic integer for the latest revocation list iteration.
    /// Update the caller's ticket to this value for subsequent requests.
    std::uint32_t ticket;

    /// List of revoked Session Pro proofs
    std::vector<ProRevocationItem> items;

    /// API: pro/GetProRevocationsResponse::parse
    ///
    /// Parses a JSON string into the response struct.
    ///
    /// Inputs:
    /// - `json` -- JSON string to parse.
    ///
    /// Outputs:
    /// - The response struct with `status` set to an error state on failure. Errors are stored in
    ///   `errors`
    static GetProRevocationsResponse parse(std::string_view json);
};

struct GetProDetailsRequest {
    /// Request version for the API
    std::uint8_t version;

    /// 32-byte Ed25519 master public key to retrieve payments for
    array_uc32 master_pkey;

    /// 64-byte signature proving knowledge of the master public key's secret component
    array_uc64 master_sig;

    /// Unix timestamp of the request
    sys_ms unix_ts;

    /// Max amount of historical payments to request from the backend
    uint32_t count;

    /// API: pro/AddProPaymentRequest::build_sigs
    ///
    /// Builds the master and rotating signatures using the provided private keys and payment token
    /// hash. Throws if the keys (32-byte or 64-byte libsodium format) or 32-byte payment token hash
    /// are passed with an incorrect size. Using 64-byte libsodium keys is more efficient.
    ///
    /// Inputs:
    /// - `request_version` -- Version of the request to build a hash for
    /// - `master_privkey` -- 64-byte libsodium style or 32 byte Ed25519 master private key
    /// - `unix_ts` -- Unix timestamp for the request.
    /// - `count` -- Amount of historical payments to request
    ///
    /// Outputs:
    /// - `array_uc64` - the 64-byte signature
    static array_uc64 build_sig(
            uint8_t version,
            std::span<const uint8_t> master_privkey,
            sys_ms unix_ts,
            uint32_t count);

    /// API: pro/GetProDetailsRequest::build_to_json
    ///
    /// Builds a GetProDetailsRequest and serialize it to JSON. This function is the same as filling
    /// the struct fields and calling `to_json`.
    ///
    /// Inputs:
    /// - `version` -- Version of the request to build a request from
    /// - `master_privkey` -- 64-byte libsodium style or 32 byte Ed25519 master private key
    /// - `unix_ts` -- Unix timestamp for the request.
    /// - `count` -- Amount of historical payments to request
    ///
    /// Outputs:
    /// - `std::string` -- Request serialised to JSON
    static std::string build_to_json(
            std::uint8_t version,
            std::span<const uint8_t> master_privkey,
            sys_ms unix_ts,
            uint32_t count);

    /// API: pro/GenerateProProofRequest::to_json
    ///
    /// Serializes the request to a JSON string.
    ///
    /// Outputs:
    /// - `std::string` - JSON representation of the request.
    std::string to_json() const;
};

struct ProPaymentItem {
    /// Describes the current status of the consumption of the payment for Session Pro entitlement
    /// The status should be used to determine which timestamps should be used.
    ///
    /// For example, a payment can be in a redeemed state whilst also have a refunded timestamp set
    /// if the payment was refunded and then the refund was reversed. We preserve all timestamps for
    /// book-keeping purposes.
    SESSION_PRO_BACKEND_PAYMENT_STATUS status;

    /// Session Pro product/plan item that was purchased
    SESSION_PRO_BACKEND_PLAN plan;

    /// Store front that this particular payment came from
    SESSION_PRO_BACKEND_PAYMENT_PROVIDER payment_provider;

    /// Strings associated with platform's payment provider from
    /// `SESSION_PRO_BACKEND_PAYMENT_PROVIDER_METADATA`, provided for convenience. This pointer is
    /// always pointing to valid memory.
    const session_pro_backend_payment_provider_metadata* payment_provider_metadata =
            SESSION_PRO_BACKEND_PAYMENT_PROVIDER_METADATA;

    /// Flag indicating whether or not this payment will automatically bill itself at the end of the
    /// billing cycle.
    bool auto_renewing;

    /// Unix timestamp of when the payment was witnessed by the Pro Backend. Always set
    sys_ms unredeemed_unix_ts;

    /// Unix timestamp of when the payment was redeemed. 0 if not activated
    sys_ms redeemed_unix_ts;

    /// Unix timestamp of when the payment was expiry. 0 if not activated
    sys_ms expiry_unix_ts;

    /// Duration of the grace period, e.g. when the payment provider will start to attempt to renew
    /// the Session Pro subscription. During the period between
    /// [expiry_unix_ts, expiry_unix_ts + grace_period_duration_ms] the user continues to have
    /// entitlement to Session Pro. This value is only applicable if `auto_renewing` is `true`.
    std::chrono::milliseconds grace_period_duration_ms;

    /// Unix deadline timestamp of when the user is able to refund the subscription via the payment
    /// provider. Thereafter the user must initiate a refund manually via Session support.
    sys_ms platform_refund_expiry_unix_ts;

    /// Unix timestamp of when the payment was revoked or refunded. 0 if not applicable.
    sys_ms revoked_unix_ts;

    /// UNIX timestamp at which a refund request was requested for this payment. This is set to 0
    /// if no refund has been requested for this payment yet.
    sys_ms refund_requested_unix_ts;

    /// When payment provider is set to Google Play Store, this is the platform-specific purchase
    /// token. This information should be considered as confidential and stored appropriately.
    std::string google_payment_token;

    /// When payment provider is set to Google Play Store, this is the platform-specific order
    /// id. This information should be considered as confidential and stored appropriately.
    std::string google_order_id;

    /// When payment provider is set to iOS App Store, this is the platform-specific original
    /// transaction ID. This information should be considered as confidential and stored
    /// appropriately.
    std::string apple_original_tx_id;

    /// When payment provider is set to iOS App Store, this is the platform-specific transaction ID
    /// This information should be considered as confidential and stored appropriately.
    std::string apple_tx_id;

    /// When payment provider is set to iOS App Store, this is the platform-specific web line order
    /// ID. This information should be considered as confidential and stored appropriately.
    std::string apple_web_line_order_id;

    /// When payment provider is set to Rangeproof, this is the platform-specific order ID.
    /// This information should be considered as confidential and stored appropriately.
    std::string rangeproof_order_id;
};

struct GetProDetailsResponse : public ResponseHeader {
    /// List of payment items for the master public key
    std::vector<ProPaymentItem> items;

    /// Current Session Pro entitlement status for the master public key
    SESSION_PRO_BACKEND_USER_PRO_STATUS user_status;

    /// Error code that indicates that the Session Pro Backend encountered an error book-keeping
    /// Session Pro entitlement for the user. If this value is not `SUCCESS` implementing clients
    /// can optionally prompt the user that they should contact support for investigation.
    SESSION_PRO_BACKEND_GET_PRO_DETAILS_ERROR_REPORT error_report;

    /// Flag to indicate if the user will automatically renew their subscription.
    bool auto_renewing;

    /// Deadline UNIX timestamp that a user is entitled to Session Pro Proofs. The user is allowed
    /// to request a Session Pro Proof from the Pro Backend up until this timestamp. Thereafter
    /// the user is no longer entitled to Session Pro. This deadline includes the grace period if
    /// applicable.
    ///
    /// The grace period is enabled when `auto_renewing` is `true` and is the extra period after a
    /// user's subscription has elapsed that the payment provider allocates to continue entitlement
    /// to Session Pro whilst attempting to execute the billing of a Session Pro subscription.
    ///
    /// This allows a user to maintain entitlement to Session Pro across billing cycles by giving
    /// some leeway as to the time required for the payment provider to successfully bill the user.
    /// This expiry timestamp is hence calculated as:
    ///
    ///   expiry_unix_ts_ms = (subscription_expiry_unix_ts + grace_period_duration_ms)
    ///
    /// E.g. The subscription expiry timestamp can be calculated by subtracting
    /// `grace_period_duration_ms` to determine if the user is currently in a grace period. Some
    /// platforms do not support a grace period so this value can be 0.
    ///
    /// Finally, a reminder that the grace period is not activated or included in this deadline
    /// timestamp if they have configured subscription `auto_renewing` to be off.
    ///
    /// This timestamp may be in the past if the user no longer has active payments. Overtime the
    /// Pro Backend may prune user history and so after long lapses of activity, a user's
    /// subscription history may be deleted.
    sys_ms expiry_unix_ts;

    /// Duration that a user is entitled to for their grace period. This value is to be ignored if
    /// `auto_renewing` is false. It can be used to calculate the subscription expiry timestamp by
    /// subtracting `expiry_unix_ts_ms` from this value.
    std::chrono::milliseconds grace_period_duration;

    /// UNIX timestamp at which a refund request was requested by this user. This timestamp comes
    /// from the latest payment that the backend has deemed to be active for the user (e.g. the
    /// payment associated with the `expiry_unix_ts_ms`). This value is 0 if no refund has been
    /// requested on the active payment.
    sys_ms refund_requested_unix_ts;

    /// Total number of payments known by the backend for the user. This may be greater than the
    /// length of items if the request, requested less than the number of payments the user has.
    uint32_t payments_total;

    /// API: pro/GetProDetailsResponse::parse
    ///
    /// Parses a JSON string into the response struct.
    ///
    /// Inputs:
    /// - `json` -- JSON string to parse.
    ///
    /// Outputs:
    /// - The response struct with `status` set to an error state on failure. Errors are stored in
    ///   `errors`
    static GetProDetailsResponse parse(std::string_view json);
};

struct SetPaymentRefundRequestedRequest {
    /// Request version for the API
    std::uint8_t version;

    /// 32-byte Ed25519 master public key to retrieve payments for
    array_uc32 master_pkey;

    /// 64-byte signature proving knowledge of the master public key's secret component
    array_uc64 master_sig;

    /// Unix timestamp of the current time
    sys_ms unix_ts;

    /// Unix timestamp to set as the timestamp that a refund was requested on this payment.
    sys_ms refund_requested_unix_ts;

    /// Payment details to set the refund request on
    AddProPaymentUserTransaction payment_tx;

    /// API: pro/SetPaymentRefundRequested::build_sigs
    ///
    /// Builds the signature that must be included in the request to authenticate and permit
    /// updating the refund requested status of a payment. Throws if the keys (32-byte or
    /// 64-byte libsodium format) are incorrectly sized. Using 64-byte libsodium keys is more
    /// efficient.
    ///
    /// Inputs:
    /// - `request_version` -- Version of the request to build a hash for
    /// - `master_privkey` -- 64-byte libsodium style or 32 byte Ed25519 master private key
    /// - `unix_ts` -- Unix timestamp for the request.
    /// - `refund_requested_unix_ts` -- Unix timestamp to set as the timestamp that a refund was
    ///   requested on this payment
    /// - `payment_tx_provider` -- Provider that the payment to set a refund request on is coming
    ///   from
    /// - `payment_tx_payment_id` -- ID that is associated with the payment from the payment
    ///   provider. See `AddProPaymentUserTransaction`
    ///   this is the transaction ID).
    /// - `payment_tx_order_id` -- Order ID that is associated with the payment see
    ///   `AddProPaymentUserTransaction`
    ///
    /// Outputs:
    /// - `array_uc64` - the 64-byte signature
    static array_uc64 build_sig(
            uint8_t version,
            std::span<const uint8_t> master_privkey,
            sys_ms unix_ts,
            sys_ms refund_requested_unix_ts,
            SESSION_PRO_BACKEND_PAYMENT_PROVIDER payment_tx_provider,
            std::span<const uint8_t> payment_tx_payment_id,
            std::span<const uint8_t> payment_tx_order_id);

    /// API: pro/SetPaymentRefundRequested::build_to_json
    ///
    /// Builds a SetPaymentRefundRequested and serialize it to JSON. This function is the same as
    /// filling the struct fields and calling `to_json`.
    ///
    /// Inputs:
    /// - `version` -- Version of the request to build a request from
    /// - `master_privkey` -- 64-byte libsodium style or 32 byte Ed25519 master private key
    /// - `unix_ts` -- Unix timestamp for the request.
    /// - `refund_requested_unix_ts` -- Unix timestamp to set as the timestamp that a refund was
    ///   requested on this payment
    /// - `payment_tx_provider` -- Provider that the payment to set a refund request on is coming
    ///   from
    /// - `payment_tx_payment_id` -- ID that is associated with the payment from the payment
    ///   provider. See `AddProPaymentUserTransaction`
    ///   this is the transaction ID).
    /// - `payment_tx_order_id` -- Order ID that is associated with the payment see
    ///   `AddProPaymentUserTransaction`
    ///
    /// Outputs:
    /// - `std::string` -- Request serialised to JSON
    static std::string build_to_json(
            std::uint8_t version,
            std::span<const uint8_t> master_privkey,
            sys_ms unix_ts,
            sys_ms refund_requested_unix_ts,
            SESSION_PRO_BACKEND_PAYMENT_PROVIDER payment_tx_provider,
            std::span<const uint8_t> payment_tx_payment_id,
            std::span<const uint8_t> payment_tx_order_id);

    /// API: pro/SetPaymentRefundRequested::to_json
    ///
    /// Serializes the request to a JSON string.
    ///
    /// Outputs:
    /// - `std::string` - JSON representation of the request.
    std::string to_json() const;
};

struct SetPaymentRefundRequestedResponse : public ResponseHeader {
    /// Version from the request
    std::uint8_t version;

    /// True if a payment was found matching the given payment information and that the refund
    /// request unix timestamp was set
    bool updated;

    /// API: pro/SetPaymentRefundRequestedResponse::parse
    ///
    /// Parses a JSON string into the response struct.
    ///
    /// Inputs:
    /// - `json` -- JSON string to parse.
    ///
    /// Outputs:
    /// - The response struct with `status` set to an error state on failure. Errors are stored in
    ///   `errors`
    static SetPaymentRefundRequestedResponse parse(std::string_view json);
};
}  // namespace session::pro_backend
