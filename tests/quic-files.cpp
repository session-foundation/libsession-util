#include <fmt/chrono.h>
#include <fmt/format.h>
#include <oxenc/hex.h>
#include <sodium/randombytes.h>

#include <CLI/CLI.hpp>
#include <chrono>
#include <filesystem>
#include <fstream>
#include <future>
#include <iostream>
#include <oxen/log.hpp>
#include <oxen/log/format.hpp>
#include <session/attachments.hpp>
#include <session/network/backends/session_file_server.hpp>
#include <session/network/network_opt.hpp>
#include <session/network/session_network.hpp>
#include <session/util.hpp>

#include "dns_utils.hpp"

using namespace std::literals;

namespace {

using session::human_size;
using clock = std::chrono::steady_clock;

namespace net = session::network;
namespace fs = net::file_server;
namespace attachment = session::attachment;

using upload_result = std::variant<std::pair<net::file_metadata, session::cleared_b32>, int16_t>;
using download_result = std::variant<net::file_metadata, int16_t>;
using on_data_t = std::function<void(const net::file_metadata&, std::span<const std::byte>)>;

using session::test::resolve_host;

// --- Generic upload/download that take a transport-initiation callback ---

int do_upload(
        const std::string& filename,
        attachment::Domain domain,
        std::optional<std::chrono::seconds> ttl,
        std::shared_ptr<net::Network> network,
        std::string download_cmd_hint) {
    auto path = std::filesystem::path{filename};
    if (!std::filesystem::exists(path)) {
        fmt::print(stderr, "File not found: {}\n", path.string());
        return 1;
    }
    auto file_size = static_cast<int64_t>(std::filesystem::file_size(path));
    fmt::print(stderr, "Uploading {} ({})...\n", path.string(), human_size{file_size});

    std::array<std::byte, 32> seed;
    randombytes_buf(seed.data(), seed.size());

    auto start = clock::now();
    std::promise<upload_result> promise;
    auto future = promise.get_future();

    net::FileUploadRequest req;
    req.file = path;
    req.domain = domain;
    req.allow_large = true;
    req.ttl = ttl;
    req.request_timeout = 60s;
    req.overall_timeout = 300s;
    req.progress_interval = 250ms;
    req.on_complete = [&](auto result, bool) { promise.set_value(std::move(result)); };

    auto last_progress = start;
    int64_t last_progress_bytes = 0;
    req.on_progress = [&](int64_t acked, int64_t total) {
        auto now = clock::now();
        auto since_last = std::chrono::duration<double>(now - last_progress).count();
        auto recent_speed = since_last > 0 ? human_size{static_cast<int64_t>(
                                                     (acked - last_progress_bytes) / since_last)}
                                           : human_size{0};
        auto pct = total > 0 ? 100.0 * acked / total : 0.0;
        fmt::print(
                stderr,
                "[{}/{}] {:.1f}% {}/s\n",
                human_size{acked},
                human_size{total},
                pct,
                recent_speed);
        last_progress = now;
        last_progress_bytes = acked;
    };

    network->upload_file(std::move(req), seed);

    auto result = future.get();
    auto elapsed_s = std::chrono::duration<double>(clock::now() - start).count();

    if (auto* pair = std::get_if<std::pair<net::file_metadata, session::cleared_b32>>(&result)) {
        auto& [meta, key] = *pair;
        auto key_hex = oxenc::to_hex(key.begin(), key.end());
        auto speed = human_size{static_cast<int64_t>(meta.size / std::max(elapsed_s, 0.001))};

        fmt::print(
                "\nUpload complete!\n"
                "  File ID:  {}\n"
                "  Key:      {}\n"
                "  Size:     {}\n"
                "  Time:     {:.1f}s\n"
                "  Speed:    {}/s\n"
                "\n"
                "To download:\n"
                "{} {} {}\n",
                meta.id,
                key_hex,
                human_size{meta.size},
                elapsed_s,
                speed,
                download_cmd_hint,
                meta.id,
                key_hex);
        return 0;
    }

    fmt::print(stderr, "Upload failed with error {}\n", std::get<int16_t>(result));
    return 1;
}

int do_download(
        const std::string& key_hex,
        const std::string& output,
        std::function<void(on_data_t, std::function<void(download_result)>)> initiate) {
    if (key_hex.size() != 64 || !oxenc::is_hex(key_hex)) {
        fmt::print(stderr, "Invalid key: expected 64 hex characters\n");
        return 1;
    }

    std::array<std::byte, 32> key;
    oxenc::from_hex(key_hex.begin(), key_hex.end(), reinterpret_cast<char*>(key.data()));

    std::ofstream out_file;
    std::ostream* out_stream = &std::cout;
    if (!output.empty()) {
        out_file.open(output, std::ios::binary);
        if (!out_file)
            throw std::runtime_error{fmt::format("Failed to open {} for writing", output)};
        out_stream = &out_file;
    }

    int64_t decrypted_bytes = 0;
    attachment::Decryptor decryptor{key, [&](std::span<const std::byte> decrypted) {
                                        out_stream->write(
                                                reinterpret_cast<const char*>(decrypted.data()),
                                                decrypted.size());
                                        decrypted_bytes += decrypted.size();
                                    }};

    auto start = clock::now();
    std::promise<download_result> promise;
    auto future = promise.get_future();
    int64_t received_bytes = 0;
    bool first_data = true;
    auto last_progress = start;
    int64_t last_progress_bytes = 0;

    initiate(
            [&](const net::file_metadata& info, std::span<const std::byte> data) {
                auto now = clock::now();

                if (first_data) {
                    first_data = false;
                    auto latency = std::chrono::duration<double, std::milli>(now - start);
                    fmt::print(
                            stderr,
                            "Transfer started after {:.0f}ms (file size: {})\n",
                            latency.count(),
                            human_size{info.size});
                    last_progress = now;
                }

                received_bytes += data.size();

                if (!decryptor.update(data))
                    throw std::runtime_error{
                            fmt::format("Decryption failed at byte {}", received_bytes)};

                auto since_last = now - last_progress;
                if (since_last >= 2s) {
                    auto since_last_s = std::chrono::duration<double>(since_last).count();
                    auto recent_speed = human_size{static_cast<int64_t>(
                            (received_bytes - last_progress_bytes) / since_last_s)};
                    fmt::print(
                            stderr,
                            "[{}/{}] {}/s\n",
                            human_size{received_bytes},
                            human_size{info.size},
                            recent_speed);
                    last_progress = now;
                    last_progress_bytes = received_bytes;
                }
            },
            [&](download_result r) { promise.set_value(std::move(r)); });

    auto result = future.get();
    auto elapsed_s = std::chrono::duration<double>(clock::now() - start).count();

    if (auto* meta = std::get_if<net::file_metadata>(&result)) {
        if (!decryptor.finalize()) {
            if (out_file.is_open()) {
                out_file.close();
                std::filesystem::remove(output);
            }
            fmt::print(stderr, "Download succeeded but decryption finalization failed\n");
            return 1;
        }

        auto speed = human_size{static_cast<int64_t>(received_bytes / std::max(elapsed_s, 0.001))};
        fmt::print(
                "Download complete: {} encrypted, {} decrypted in {:.1f}s ({}/s)\n",
                human_size{received_bytes},
                human_size{decrypted_bytes},
                elapsed_s,
                speed);

        if (!output.empty())
            fmt::print("Written to {}\n", output);
        return 0;
    }

    if (out_file.is_open()) {
        out_file.close();
        std::filesystem::remove(output);
    }
    fmt::print(stderr, "Download failed with error {}\n", std::get<int16_t>(result));
    return 1;
}

// --- Mode-specific runners ---

struct CliArgs {
    // Mode
    bool srouter = false;
    bool testnet = true;

    // Direct mode
    std::string server_pubkey_hex;
    std::string server_address = "::1";
    uint16_t server_port = fs::QUIC_DEFAULT_PORT;
    size_t max_udp_payload = 0;

    // Upload
    std::string upload_filename;
    attachment::Domain domain = attachment::Domain::ATTACHMENT;
    std::optional<std::chrono::seconds> ttl{3600s};

    // Download
    std::string dl_source;
    std::string dl_key_hex;
    std::string dl_output;

    const char* argv0;
};

int run(const CliArgs& args, bool is_upload) {
    auto netid = args.testnet ? net::opt::netid::testnet() : net::opt::netid::mainnet();
    auto router = args.srouter ? net::opt::router::session_router() : net::opt::router::direct();
    auto cache_dir = std::filesystem::temp_directory_path() /
                     (args.testnet ? "quic_files_cache_testnet" : "quic_files_cache");
    std::filesystem::create_directories(cache_dir);

    std::vector<net::opt::any> net_opts;
    net_opts.push_back(netid);
    net_opts.push_back(router);
    net_opts.push_back(net::opt::cache_directory{cache_dir});

    // For direct mode, pass the QUIC file server address/pubkey/port so that DirectRouter
    // uses the QUIC protocol instead of the legacy HTTP path.
    if (!args.srouter) {
        auto resolved = resolve_host(args.server_address);
        if (resolved != args.server_address)
            fmt::print(stderr, "Resolved {} -> {}\n", args.server_address, resolved);

        net_opts.push_back(net::opt::quic_file_server_ed_pubkey{args.server_pubkey_hex});
        net_opts.push_back(net::opt::quic_file_server_address{resolved});
        net_opts.push_back(net::opt::quic_file_server_port{args.server_port});
    }

    if (args.max_udp_payload > 0)
        net_opts.push_back(net::opt::quic_max_udp_payload{args.max_udp_payload});

    fmt::print(
            stderr,
            "Starting network ({}, {})...\n",
            args.testnet ? "testnet" : "mainnet",
            args.srouter ? "session-router" : "direct");

    auto network = std::make_shared<net::Network>(net_opts);

    std::string mode_hint = fmt::format(
            "{}{}{}",
            args.argv0,
            args.srouter ? " --srouter" : "",
            args.testnet ? "" : " --mainnet");

    if (is_upload) {
        return do_upload(
                args.upload_filename,
                args.domain,
                args.ttl,
                network,
                fmt::format("{} download", mode_hint));
    }

    // Build download URL from file ID if not already a URL
    std::string download_url;
    if (args.dl_source.find("://") != std::string::npos)
        download_url = args.dl_source;
    else
        download_url = fs::generate_download_url(
                args.dl_source, network->file_server_config, /*stream_encrypted=*/true);

    fmt::print(stderr, "Downloading: {}\n", download_url);
    return do_download(args.dl_key_hex, args.dl_output, [&](on_data_t on_data, auto cb) {
        net::DownloadRequest req;
        req.download_url = download_url;
        req.request_timeout = 60s;
        req.overall_timeout = 300s;
        req.on_data = std::move(on_data);
        req.on_complete = [cb = std::move(cb)](auto r, bool) { cb(std::move(r)); };
        network->download(std::move(req));
    });
}

}  // namespace

int main(int argc, char* argv[]) {
    CLI::App app{"QUIC file server upload/download tool"};
    app.require_subcommand(1);
    app.fallthrough();  // Allow global options after subcommand

    CliArgs args;
    args.argv0 = argv[0];

    bool use_direct = false, use_mainnet = false;
    app.add_flag("--srouter", args.srouter, "Route via session-router (default: direct)");
    app.add_flag("--direct", use_direct, "Connect directly to the file server");
    app.add_flag("--mainnet", use_mainnet, "Use mainnet (default: testnet)");

    app.add_option("--server", args.server_pubkey_hex, "Ed25519 pubkey of the file server (hex)");
    app.add_option("--address", args.server_address, "Server address (hostname or IP)");
    app.add_option(
            "--port",
            args.server_port,
            fmt::format("Server port (default: {})", fs::QUIC_DEFAULT_PORT));

    app.add_option(
            "--max-udp-payload",
            args.max_udp_payload,
            "Cap network-level QUIC UDP payload size (limits path MTU discovery; minimum 1200)");

    std::string log_level = "warning";
    std::string log_file = "stderr";
    app.add_option(
            "--log-level",
            log_level,
            "Log level/categories (e.g. warning, debug, quic-file-client=trace)");
    app.add_option("--log-file", log_file, "Log output: stderr, stdout, -, or a file path");

    bool profile_pic = false, max_ttl = false;
    int64_t ttl_seconds = 3600;
    auto* upload_cmd = app.add_subcommand("upload", "Encrypt and upload a file");
    upload_cmd->add_option("filename", args.upload_filename, "File to upload")->required();
    upload_cmd->add_flag("--profile-pic", profile_pic, "Use PROFILE_PIC encryption domain");
    upload_cmd->add_flag("--max-ttl", max_ttl, "Use server's maximum TTL instead of default 1h");
    upload_cmd->add_option(
            "--ttl", ttl_seconds, "TTL in seconds (default: 3600; ignored if --max-ttl)");

    auto* download_cmd = app.add_subcommand("download", "Download and decrypt a file");
    download_cmd
            ->add_option(
                    "source",
                    args.dl_source,
                    "File ID or download URL (e.g. http://host/file/ID#sr=addr.sesh:port)")
            ->required();
    download_cmd->add_option("key", args.dl_key_hex, "Decryption key (hex)")->required();
    download_cmd->add_option("output", args.dl_output, "Output filename (default: stdout)");

    CLI11_PARSE(app, argc, argv);

    if (args.srouter + use_direct > 1) {
        fmt::print(stderr, "Error: --srouter and --direct are mutually exclusive\n");
        return 1;
    }
    if (!args.srouter && !use_direct)
        use_direct = true;
    if (use_mainnet)
        args.testnet = false;

    // For direct mode, default the server pubkey and address from the known file server configs.
    if (!args.srouter) {
        if (args.server_pubkey_hex.empty()) {
            auto& pk = args.testnet ? fs::QUIC_FS_ED_PUBKEY_TESTNET : fs::QUIC_FS_ED_PUBKEY_MAINNET;
            args.server_pubkey_hex = oxenc::to_hex(pk.begin(), pk.end());
        }
        if (args.server_address == "::1") {
            args.server_address =
                    args.testnet ? "superduperfiles.oxen.io" : "anna.session.foundation";
        }
    }

    if (profile_pic)
        args.domain = attachment::Domain::PROFILE_PIC;
    if (max_ttl)
        args.ttl.reset();
    else
        args.ttl.emplace(ttl_seconds);

    // Set up logging
    {
        constexpr std::array print_vals = {"stdout"sv, "-"sv, ""sv, "stderr"sv};
        namespace log = oxen::log;
        auto log_type = std::count(print_vals.begin(), print_vals.end(), log_file)
                              ? log::Type::Print
                      : log_file == "syslog" ? log::Type::System
                                             : log::Type::File;
        log::add_sink(log_type, log_file);

        auto cats = log::extract_categories(log_level);
        cats.apply();
    }

    return run(args, upload_cmd->parsed());
}
