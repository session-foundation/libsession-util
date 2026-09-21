#include <oxenc/hex.h>

#include <catch2/catch_approx.hpp>
#include <catch2/catch_test_macros.hpp>
#include <cmath>
#include <set>
#include <vector>

#include "../src/image/det_trig.hpp"
#include "session/image/thumbhash.hpp"

using namespace session::image;
using namespace std::literals;

namespace {

// A synthetic image with enough structure in every channel that all the DCT terms are exercised:
// a diagonal luminance ramp, opposing red/blue gradients, and a green blob.
std::vector<std::byte> test_image(int w, int h, bool alpha) {
    std::vector<std::byte> px(size_t(w) * h * 4);
    for (int y = 0; y < h; y++)
        for (int x = 0; x < w; x++) {
            double fx = double(x) / std::max(1, w - 1), fy = double(y) / std::max(1, h - 1);
            double blob = std::exp(-8 * ((fx - 0.3) * (fx - 0.3) + (fy - 0.7) * (fy - 0.7)));
            auto set = [&](int c, double v) {
                px[(size_t(y) * w + x) * 4 + c] =
                        std::byte(uint8_t(std::clamp(v, 0.0, 1.0) * 255 + 0.5));
            };
            set(0, 0.9 * fx + 0.05);
            set(1, blob);
            set(2, 0.9 * (1 - fy) + 0.05);
            // A soft circular cutout, so the alpha DCT has something to encode.
            set(3, alpha ? std::clamp(1.6 - 3.0 * std::hypot(fx - 0.5, fy - 0.5), 0.0, 1.0) : 1.0);
        }
    return px;
}

}  // namespace

// det_trig replaces std::cos with a hand-written Taylor series, so the coefficient table is a
// transcription that nothing else would catch if it were wrong: a bad term still produces smooth,
// plausible-looking output, just with the wrong values baked into every hash.  Check it against
// libm over exactly the arguments the DCT uses.  The tolerance is far looser than the ~4e-15 the
// two genuinely differ by (libm is handed a thrice-rounded angle) and far tighter than any
// consequential typo, which would show up at 1e-5 or worse.
TEST_CASE("det_trig cosine agrees with libm", "[image][thumbhash][det_trig]") {
    using session::image::detail::cos_dct;
    using session::image::detail::cos_pi;

    double worst = 0;
    for (int n = 1; n <= 100; n++)
        for (int k = 0; k <= 6; k++)
            for (int i = 0; i < n; i++)
                worst = std::max(
                        worst, std::abs(cos_dct(k, i, n) - std::cos(M_PI / n * k * (i + 0.5))));
    CHECK(worst < 1e-13);

    // Exact values the reduction must land on, covering every branch: each octant, the sign flip
    // past pi/2, and wrap-around of the integer reduction.
    CHECK(cos_pi(0, 7) == 1.0);
    CHECK(cos_pi(7, 7) == -1.0);
    CHECK(cos_pi(14, 7) == 1.0);                              // 2pi
    CHECK(cos_pi(-7, 7) == -1.0);                             // negative numerator
    CHECK(cos_pi(700, 7) == 1.0);                             // many periods
    CHECK(cos_pi(1, 2) == Catch::Approx(0.0).margin(1e-16));  // pi/2
    CHECK(cos_pi(1, 3) == Catch::Approx(0.5));                // pi/3
    CHECK(cos_pi(2, 3) == Catch::Approx(-0.5));               // 2pi/3
    CHECK(cos_pi(1, 4) == Catch::Approx(std::sqrt(0.5)));     // pi/4, the branch boundary
    CHECK(cos_pi(3, 4) == Catch::Approx(-std::sqrt(0.5)));
    CHECK(cos_pi(1, 6) == Catch::Approx(std::sqrt(3.0) / 2));  // pi/6, cos branch
    CHECK(cos_pi(5, 6) == Catch::Approx(-std::sqrt(3.0) / 2));
}

TEST_CASE("thumbhash round-trip", "[image][thumbhash]") {
    for (auto alpha : {false, true}) {
        for (auto [w, h] : {std::pair{32, 32}, {64, 48}, {48, 64}, {100, 100}, {7, 3}, {1, 1}}) {
            auto px = test_image(w, h, alpha);
            auto hash = thumbhash::encode(px, w, h);

            CHECK(hash.size() >= 5);
            CHECK(hash.size() <= thumbhash::max_hash_size);
            // Alpha is only carried when some pixel is actually translucent.
            CHECK(((std::to_integer<uint8_t>(hash[2]) & 0x80) != 0) == alpha);

            auto img = thumbhash::decode_unsized(hash, 32);
            CHECK(img.rgba.size() == size_t(img.width) * img.height * 4);
            CHECK(img.width >= 1);
            CHECK(img.height >= 1);
            CHECK(std::max(img.width, img.height) == 32);

            auto exact = thumbhash::decode(hash, 20, 10);
            CHECK(exact.width == 20);
            CHECK(exact.height == 10);
            CHECK(exact.rgba.size() == 20 * 10 * 4);
        }
    }
}

namespace {

// Per-channel mean of a decoded image.
std::array<double, 4> channel_means(const thumbhash::image& im) {
    std::array<double, 4> sum{};
    size_t n = size_t(im.width) * im.height;
    for (size_t i = 0; i < n; i++)
        for (int c = 0; c < 4; c++)
            sum[c] += std::to_integer<uint8_t>(im.rgba[i * 4 + c]);
    for (auto& v : sum)
        v /= double(n);
    return sum;
}

}  // namespace

TEST_CASE("thumbhash decode is resolution independent", "[image][thumbhash]") {
    auto hash = thumbhash::encode(test_image(64, 48, false), 64, 48);

    // The DCT basis is continuous, so decoding at different resolutions samples the same
    // underlying surface: the overall colour should not shift with the output grid.
    auto coarse = channel_means(thumbhash::decode(hash, 16, 12));
    auto fine = channel_means(thumbhash::decode(hash, 160, 120));
    for (int c = 0; c < 4; c++)
        CHECK(std::abs(coarse[c] - fine[c]) < 2.0);
}

TEST_CASE("thumbhash average colour matches the decoded mean", "[image][thumbhash]") {
    for (auto alpha : {false, true}) {
        auto hash = thumbhash::encode(test_image(40, 40, alpha), 40, 40);
        auto avg = thumbhash::average_rgba(hash);
        // average_rgba reads the DC terms, which are the mean of the image; the AC terms very
        // nearly integrate away over the whole grid, so the decoded mean should land close by.
        // Clamping and the 1.25x chroma boost keep it from being exact.
        auto mean = channel_means(thumbhash::decode(hash, 32, 32));
        for (int c = 0; c < 4; c++)
            CHECK(std::abs(double(std::to_integer<uint8_t>(avg[c])) - mean[c]) <= 24.0);
    }
}

TEST_CASE("thumbhash aspect ratio", "[image][thumbhash]") {
    auto wide = thumbhash::encode(test_image(96, 32, false), 96, 32);
    auto tall = thumbhash::encode(test_image(32, 96, false), 32, 96);
    auto square = thumbhash::encode(test_image(48, 48, false), 48, 48);
    CHECK(thumbhash::component_aspect_ratio(wide) > 1.5);
    CHECK(thumbhash::component_aspect_ratio(tall) < 0.67);
    CHECK(thumbhash::component_aspect_ratio(square) == 1.0);

    // decode_unsized() should follow the component ratio.
    auto w = thumbhash::decode_unsized(wide, 32);
    CHECK(w.width == 32);
    CHECK(w.height < 32);
}

// component_aspect_ratio() reports the DCT component counts, not the image's shape, so it can only
// ever return 7/n for n in 1..7 (or 5/n with alpha) and saturates beyond that.  Pinned here so the
// limitation stays visible rather than being discovered in a client: a 1000x637 photo scaled to
// 100x64 by the sender comes back as 7/4, and anything wider than 7:1 comes back as exactly 7.
TEST_CASE("thumbhash component ratio is not an aspect ratio", "[image][thumbhash]") {
    struct {
        int w, h;
        double expected;
    } const cases[] = {
            {100, 64, 7.0 / 4},  // a 1000x637 source: true 1.570
            {100, 56, 7.0 / 4},  // 1920x1080: true 1.778
            {100, 75, 7.0 / 5},  // 4032x3024: true 1.333
            {100, 25, 7.0 / 2},  // 2000x500: true 4.0
            {100, 100, 1.0},     //
            {64, 100, 4.0 / 7},  // portrait
            {100, 10, 7.0},      // 1000x100 banner: true 10.0, saturated
            {100, 1, 7.0},       // 100:1, still 7.0
    };
    for (const auto& c : cases) {
        auto hash = thumbhash::encode(test_image(c.w, c.h, false), c.w, c.h);
        INFO(c.w << "x" << c.h);
        CHECK(thumbhash::component_aspect_ratio(hash) == Catch::Approx(c.expected));
    }

    // The whole representable set, so a change to it cannot slip through silently.
    std::set<double> seen;
    for (int w = 1; w <= 100; w++)
        for (int h = 1; h <= 100; h++)
            seen.insert(thumbhash::component_aspect_ratio(
                    thumbhash::encode(test_image(w, h, false), w, h)));
    CHECK(seen.size() == 13);
    CHECK(*seen.begin() == Catch::Approx(1.0 / 7));
    CHECK(*seen.rbegin() == Catch::Approx(7.0));

    // Callers who know the real size should bypass it entirely.
    auto hash = thumbhash::encode(test_image(100, 64, false), 100, 64);
    auto img = thumbhash::decode(hash, 32, 20);  // the true 1000x637 shape
    CHECK(img.width == 32);
    CHECK(img.height == 20);
}

// A hash's length is a pure function of its header, so a carrier storing peer-supplied values can
// check exact structural validity rather than a loose cap -- a cap would pass a blob of the right
// size but arbitrary content.
TEST_CASE("thumbhash validity is exact, not a length cap", "[image][thumbhash]") {
    std::set<size_t> lengths;
    for (auto alpha : {false, true})
        for (int w = 1; w <= 100; w += 7)
            for (int h = 1; h <= 100; h += 7) {
                auto hash = thumbhash::encode(test_image(w, h, alpha), w, h);
                INFO(w << "x" << h << (alpha ? " rgba" : " rgb"));
                CHECK(thumbhash::valid(hash));
                CHECK(thumbhash::expected_size(hash) == hash.size());
                CHECK(hash.size() <= thumbhash::max_hash_size);
                lengths.insert(hash.size());

                // One byte short or one byte long is not the length its own header demands.
                CHECK_FALSE(thumbhash::valid(std::span{hash}.first(hash.size() - 1)));
                auto padded = hash;
                padded.push_back(std::byte{0});
                CHECK_FALSE(thumbhash::valid(padded));
            }

    // Only eight lengths are reachable at all.
    CHECK(lengths == std::set<size_t>{17, 19, 21, 23, 24, 25});

    // Too short to hold a header at all.
    for (size_t n = 0; n < 5; n++)
        CHECK(thumbhash::expected_size(std::vector<std::byte>(n)) == std::nullopt);
    // Header says alpha, but the alpha DC byte is missing.
    std::vector<std::byte> alpha_hdr(5, std::byte{0});
    alpha_hdr[2] = std::byte{0x80};
    CHECK(thumbhash::expected_size(alpha_hdr) == std::nullopt);
}

TEST_CASE("thumbhash rejects bad input", "[image][thumbhash]") {
    auto px = test_image(8, 8, false);
    CHECK_THROWS_AS(thumbhash::encode(px, 8, 7), std::invalid_argument);  // size mismatch
    CHECK_THROWS_AS(thumbhash::encode(px, 0, 8), std::invalid_argument);  // zero dimension
    CHECK_THROWS_AS(thumbhash::encode(test_image(101, 1, false), 101, 1), std::invalid_argument);

    auto hash = thumbhash::encode(px, 8, 8);
    auto prefix = [&hash](size_t n) { return std::span{hash}.first(n); };
    CHECK_THROWS_AS(thumbhash::decode(prefix(4), 8, 8), std::invalid_argument);
    CHECK_THROWS_AS(thumbhash::decode({}, 8, 8), std::invalid_argument);
    CHECK_THROWS_AS(thumbhash::decode(hash, 0, 4), std::invalid_argument);
    CHECK_THROWS_AS(thumbhash::decode_unsized(hash, 0), std::invalid_argument);
    CHECK_THROWS_AS(thumbhash::decode_unsized(prefix(4)), std::invalid_argument);
    // Truncated in the middle of the AC nibbles.
    CHECK_THROWS_AS(thumbhash::decode(prefix(6), 8, 8), std::invalid_argument);
}

// These vectors pin the floating-point behaviour of the encoder.  A thumbhash is sent to other
// people, so if it varied with the platform's libm or with whether the compiler contracted a*b+c
// into an FMA, it would leak a bit about which client produced it.  src/image/det_trig.hpp removes
// both sources; this test is the backstop that makes a build which reintroduces one fail loudly
// instead of silently fingerprinting users.
//
// If this fails on a new platform, do not regenerate the vectors: find out which assumption broke
// (most likely the rounding mode, or x87 excess precision from a non-SSE2 x86 build).
TEST_CASE("thumbhash is bit-reproducible", "[image][thumbhash]") {
    struct {
        int w, h;
        bool alpha;
        std::string_view expected;
    } const vectors[] = {
            {32, 32, false, "1b67067f262062763f9a885289d879678789670777909a09"sv},
            {64, 48, false, "1b67067da62062763f9a885289d87976767007a999"sv},
            {48, 64, false, "1b67067d2620623f9a2895d879769878767007a999"sv},
            {32, 32, true, "9d3782250a2617b138d871efbd777007b99808688888808968"sv},
            {64, 48, true, "9d3782248c3717a138d871ef7d0777908b8980868808988806"sv},
            {100, 100, false, "1b67067f261061763f9a885189e879678789670777909a09"sv},
            {17, 5, true, "9d378219883506b037d883777007b98828788888808a78"sv},
            {1, 1, false, "d5102ad70708f808888888808f8088f80888808ff8088800"sv},
    };
    for (const auto& v : vectors) {
        auto hash = thumbhash::encode(test_image(v.w, v.h, v.alpha), v.w, v.h);
        INFO(v.w << "x" << v.h << (v.alpha ? " rgba" : " rgb"));
        CHECK(oxenc::to_hex(hash) == v.expected);
    }
}
