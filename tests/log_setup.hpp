#pragma once

#include <algorithm>
#include <array>
#include <catch2/catch_session.hpp>
#include <oxen/log.hpp>
#include <string>

/// Holds the --log-level / --log-file option state and applies it after argument parsing.
struct LogSetup {
    std::string level = "critical";
    std::string file = "stderr";

    /// Returns a Clara option pipeline for --log-level and --log-file.
    auto opts() {
        using namespace Catch::Clara;
        return Opt(level,
                   "level")["--log-level"]("oxen-logging log level to apply to the test run") |
               Opt(file, "file")["--log-file"](
                       "oxen-logging log file to output logs to, or one of "
                       "stdout/-/stderr/syslog.");
    }

    /// Initialises the oxen-logging sink from the parsed level/file values.
    void apply() const {
        constexpr std::array print_vals = {
                "stdout", "-", "", "stderr", "nocolor", "stdout-nocolor", "stderr-nocolor"};
        oxen::log::Type type;
        if (std::count(print_vals.begin(), print_vals.end(), file))
            type = oxen::log::Type::Print;
        else if (file == "syslog")
            type = oxen::log::Type::System;
        else
            type = oxen::log::Type::File;

        oxen::log::add_sink(
                type, file, "[%T.%f] [%*] [\x1b[1m%n\x1b[0m:%^%l%$|\x1b[3m%g:%#\x1b[0m] %v");
        oxen::log::apply_categories(level);
    }
};
