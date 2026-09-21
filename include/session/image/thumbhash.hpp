#pragma once

#include <array>
#include <cstdint>
#include <optional>
#include <span>
#include <vector>

namespace session::image::thumbhash {

/// The largest input dimension `encode` accepts.  ThumbHash's own limit: the output is at most a
/// 7x7 DCT, so a larger input costs time without adding information.
inline constexpr uint32_t max_input_dimension = 100;

/// The largest hash `encode` can produce (7x7 luminance + 3x3 P + 3x3 Q + 5x5 alpha).
inline constexpr size_t max_hash_size = 25;

/// A decoded placeholder: RGBA8, row-major, *not* alpha-premultiplied.
struct image {
    uint32_t width = 0;
    uint32_t height = 0;
    std::vector<std::byte> rgba;
};

/// API: image/thumbhash/encode
///
/// Encodes a small RGBA image into a ThumbHash: a ~20-25 byte placeholder that a receiving client
/// can render as a blurred preview before the real attachment arrives.
///
/// The caller is responsible for scaling the source image down; `width` and `height` must each be
/// between 1 and `max_input_dimension`.  Note that the scaler matters for reproducibility: two
/// clients that downscale the same photo differently will produce different hashes.  See the note
/// on cross-platform reproducibility in the implementation.
///
/// Inputs:
/// - `rgba` -- the pixels, row-major, 4 bytes per pixel, *not* alpha-premultiplied.  Must be
///   exactly `width * height * 4` bytes.
/// - `width`, `height` -- the image dimensions, each in [1, `max_input_dimension`].
///
/// Outputs:
/// - the hash, between 5 and `max_hash_size` bytes.
///
/// Throws `std::invalid_argument` if the dimensions are out of range or `rgba` is the wrong size.
std::vector<std::byte> encode(std::span<const std::byte> rgba, uint32_t width, uint32_t height);

/// API: image/thumbhash/decode
///
/// Decodes a ThumbHash to RGBA pixels at the requested resolution.  This is the function clients
/// should use: pass the attachment's real dimensions, scaled down small.
///
/// The output shape is entirely yours to choose -- the DCT basis is continuous, so any grid is
/// valid and this simply samples it at the points you ask for.  A hash carries no usable record
/// of the source's shape (see `component_aspect_ratio`), so the aspect ratio must come from the
/// attachment metadata, not from here.
///
/// Keep the resolution small and let the UI scale the result.  The hash holds at most 7 cycles
/// across the image, so a 32px decode captures essentially everything: upscaling it 10x with any
/// linear filter differs from a full-size decode by an RMSE of under 1, which is imperceptible,
/// and decode cost grows with the *output* pixel count (0.085ms at 32x24, 4.6ms at 240x180).  Do
/// not scale it with nearest-neighbour filtering, which will look blocky.
///
/// Inputs:
/// - `hash` -- the bytes produced by `encode`.
/// - `width`, `height` -- the output dimensions, each at least 1.
///
/// Outputs:
/// - the decoded RGBA8 image.
///
/// Throws `std::invalid_argument` if the hash is malformed or the dimensions are zero.
image decode(std::span<const std::byte> hash, uint32_t width, uint32_t height);

/// API: image/thumbhash/expected_size
///
/// The exact number of bytes a well-formed hash starting with these bytes must occupy, or nullopt
/// if the leading bytes are not a usable header.
///
/// A hash's length is not merely bounded, it is fully determined: the alpha flag and the 3-bit
/// component count fix how many coefficient nibbles follow.  Only six lengths are reachable at
/// all -- 17, 19, 21, 23 or 24 bytes without alpha, and 23 or 25 with it.  Reads the header only:
/// no DCT, no allocation.
///
/// Note that `decode` is more permissive than this, requiring only that enough bytes are present.
/// Use `valid` at a trust boundary, where "exactly well-formed" is what you mean.
std::optional<size_t> expected_size(std::span<const std::byte> hash);

/// API: image/thumbhash/valid
///
/// Whether `hash` is structurally well-formed: a usable header, and exactly the length that
/// header implies.
///
/// This is what a receive path should test before storing a value a remote peer supplied.  It is
/// strictly stronger than a length cap, which a blob of the right size but arbitrary content
/// would pass, and it costs a handful of bit extractions.
bool valid(std::span<const std::byte> hash);

/// API: image/thumbhash/average_rgba
///
/// Returns the average colour of the original image as RGBA8 (not alpha-premultiplied), read
/// straight out of the hash's DC terms.  Much cheaper than decoding, and enough for a flat-colour
/// placeholder.
///
/// Throws `std::invalid_argument` if the hash is malformed.
std::array<std::byte, 4> average_rgba(std::span<const std::byte> hash);

// ─── Diagnostics and last resorts ────────────────────────────────────────────
//
// The two functions below exist for inspecting a hash and for the case where one turns up with no
// accompanying metadata at all.  Neither belongs on a normal display path.

/// API: image/thumbhash/component_aspect_ratio
///
/// Returns the ratio of the hash's DCT component counts.  This is NOT the image's aspect ratio
/// and must never be used to lay one out.
///
/// A ThumbHash does not record the source's shape.  It records how many luminance AC coefficients
/// are present, because a decoder cannot parse the hash without knowing where the chroma terms
/// begin.  The encoder picks that count roughly in proportion to the source, so a wide image gets
/// more horizontal detail than vertical, and dividing the two out gives something that correlates
/// with the shape.  Upstream exposes it as `thumbHashToApproximateAspectRatio`; this is the same
/// value under a name that does not invite misuse.
///
/// It is quantised to a handful of values, because one side is always pinned at the per-channel
/// maximum.  The complete set of results is 7/n for n in 1..7 and their reciprocals without alpha
/// (13 values: 1/7 ... 1 ... 7), or 5/n for n in 1..5 and reciprocals with it (9 values).  It also
/// saturates, so every image wider than 7:1 reports exactly 7.0: a 1000x100 banner reads as 7.0
/// rather than 10.0, and a 1x100 sliver is wrong by a factor of fourteen.
///
/// Throws `std::invalid_argument` if the hash is malformed.
double component_aspect_ratio(std::span<const std::byte> hash);

/// API: image/thumbhash/decode_unsized
///
/// Decodes a hash when its dimensions are genuinely unknown, guessing the output shape from
/// `component_aspect_ratio` with `size` pixels on the longer edge.
///
/// The guess is as coarse as that function is -- it can be wrong by more than a factor of ten --
/// so a placeholder sized from the result will visibly jump when the real image loads.  Use
/// `decode` with the attachment's real dimensions instead; reach for this only when there are
/// none, such as when inspecting a hash in isolation.
///
/// Throws `std::invalid_argument` if the hash is malformed or `size` is zero.
image decode_unsized(std::span<const std::byte> hash, uint32_t size = 32);

}  // namespace session::image::thumbhash
