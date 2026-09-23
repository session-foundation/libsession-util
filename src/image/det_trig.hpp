#pragma once

// Bit-reproducible trigonometry for the ThumbHash DCT.
//
// std::cos is not required by IEEE-754 to be correctly rounded, and implementations disagree: V8's
// fdlibm-derived cos differs from glibc's by 1 ulp on ~3.5% of the arguments this DCT uses, which
// is enough to change the emitted hash for ~7% of images.  Since a thumbhash is sent to other
// people, that would make it a weak fingerprint of which platform produced it.
//
// Reproducibility here rests on two things:
//
//  - Argument reduction is exact integer arithmetic, so no high-precision pi is needed and no
//    rounding happens before the series.  (This is also *more* accurate than the reference
//    formulation, which hands libm an angle that has already been rounded three times: worst error
//    against a high-precision reference is 1.5e-16 here versus 4.0e-15 there.)
//
//  - Every remaining step is an IEEE-754 operation that the standard requires to be correctly
//    rounded: +, -, * and fusedMultiplyAdd.  The polynomials are written with explicit std::fma
//    rather than `a + z * b`, because the latter is contractible: a compiler may or may not fuse
//    it depending on -ffp-contract and on whether the target has an FMA instruction, and the fused
//    and unfused results differ in the last bit.  Spelling the fusion out makes the result
//    independent of the build rather than dependent on a flag.
//
// What this still assumes: the default round-to-nearest-even rounding mode, and no x87 excess
// precision (i.e. SSE2 math on x86).  Both hold on every platform we target.
// tests/test_image_thumbhash.cpp pins hash vectors so that a build which breaks either fails
// loudly rather than silently leaking.

#include <cmath>
#include <cstdint>

namespace session::image::detail {

namespace trig {

    // cos(u) and sin(u) by Taylor series on |u| <= pi/4, where the series is well conditioned.
    // Terms run past u^18/18! ~= 3e-18, comfortably under a double's 2.2e-16 relative resolution.
    // Evaluated by Horner from the smallest term up, each step a single fused multiply-add.
    inline double cos_series(double z) {     // z = u*u
        double c = -1.0 / 6402373705728000;  // -1/18!
        c = std::fma(c, z, 1.0 / 20922789888000);
        c = std::fma(c, z, -1.0 / 87178291200);
        c = std::fma(c, z, 1.0 / 479001600);
        c = std::fma(c, z, -1.0 / 3628800);
        c = std::fma(c, z, 1.0 / 40320);
        c = std::fma(c, z, -1.0 / 720);
        c = std::fma(c, z, 1.0 / 24);
        c = std::fma(c, z, -1.0 / 2);
        return std::fma(c, z, 1.0);
    }

    inline double sin_series(double u, double z) {  // z = u*u
        double s = 1.0 / 355687428096000;           // 1/17!
        s = std::fma(s, z, -1.0 / 1307674368000);
        s = std::fma(s, z, 1.0 / 6227020800);
        s = std::fma(s, z, -1.0 / 39916800);
        s = std::fma(s, z, 1.0 / 362880);
        s = std::fma(s, z, -1.0 / 5040);
        s = std::fma(s, z, 1.0 / 120);
        s = std::fma(s, z, -1.0 / 6);
        s = std::fma(s, z, 1.0);
        return u * s;
    }

    // The double nearest pi.  Only ever multiplies an already-reduced ratio in [0, 1/4], so its
    // error contributes at most ~1e-16 to the angle.
    inline constexpr double pi = 3.14159265358979323846;

}  // namespace trig

/// cos(pi * n / d), for d > 0.  Identical on every IEEE-754 platform, in any build configuration.
inline double cos_pi(int64_t n, int64_t d) {
    // Reduce to one period exactly, in integers: cos has period 2 in n/d.
    int64_t p = 2 * d;
    n %= p;
    if (n < 0)
        n += p;
    if (n > d)
        n = p - n;  // cos(2pi - t) == cos(t);  now 0 <= n <= d
    double sign = 1.0;
    if (2 * n > d) {
        n = d - n;  // cos(pi - t) == -cos(t);  now t <= pi/2
        sign = -1.0;
    }
    if (4 * n > d) {
        // t > pi/4: swap to the sine of the complement, pi/2 - t == pi*(d-2n)/(2d), which keeps
        // the series argument inside [0, pi/4].
        double u = trig::pi * (double(d - 2 * n) / double(2 * d));
        return sign * trig::sin_series(u, u * u);
    }
    double u = trig::pi * (double(n) / double(d));
    return sign * trig::cos_series(u * u);
}

/// The DCT basis value cos(pi/n * k * (i + 0.5)) that ThumbHash needs.
///
/// Upstream writes this literally as `cos(pi / n * k * (i + 0.5))`, which rounds the angle three
/// times before libm ever sees it.  Restating it as an exact ratio lets cos_pi reduce it in
/// integers instead, which is both reproducible and rather more accurate.
///
/// Defining THUMBHASH_REFERENCE_COS selects that upstream formulation instead.  It is the
/// definition of the algorithm, and is kept so the computation we are approximating stays legible
/// and so the deterministic path can be measured against it, but it is not reproducible -- it
/// depends on the platform's std::cos.  Production builds must not define it.
inline double cos_dct(int k, int i, int n) {
#ifdef THUMBHASH_REFERENCE_COS
    return std::cos(trig::pi / n * k * (i + 0.5));
#else
    return cos_pi(int64_t(k) * (2 * i + 1), 2 * int64_t(n));
#endif
}

}  // namespace session::image::detail
