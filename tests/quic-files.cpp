#include <fmt/chrono.h>
#include <fmt/format.h>
#include <oxenc/hex.h>
#include <sodium/randombytes.h>

#include <CLI/CLI.hpp>
#include <any>
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

static constexpr auto STATUS_CAT = "file";

namespace {

namespace log = oxen::log;
static auto logcat = log::Cat(STATUS_CAT);

using session::human_size;
using clock = std::chrono::steady_clock;

namespace net = session::network;
namespace fs = net::file_server;
namespace attachment = session::attachment;

using transfer_result = std::variant<net::file_metadata, int16_t>;
using on_complete_t = std::function<void(transfer_result)>;
using on_data_t =
        std::function<void(const net::file_metadata&, std::span<const std::byte>)>;

std::vector<std::byte> read_file(const std::filesystem::path& path) {
    std::ifstream f{path, std::ios::binary | std::ios::ate};
    if (!f)
        throw std::runtime_error{fmt::format("Failed to open {}", path.string())};
    auto size = f.tellg();
    f.seekg(0);
    std::vector<std::byte> data(size);
    f.read(reinterpret_cast<char*>(data.data()), size);
    return data;
}

using session::test::resolve_host;

// --- Generic upload/download that take a transport-initiation callback ---

int do_upload(
        const std::string& filename,
        attachment::Domain domain,
        std::optional<std::chrono::seconds> ttl,
        std::function<void(std::vector<std::byte>, std::optional<std::chrono::seconds>, on_complete_t)>
                initiate,
        std::string download_cmd_hint) {
    auto path = std::filesystem::path{filename};
    log::info(logcat, "Reading {}...", path.string());
    auto plaintext = read_file(path);
    log::info(logcat, "Plaintext size: {}", human_size{static_cast<int64_t>(plaintext.size())});

    std::array<std::byte, 32> seed;
    randombytes_buf(seed.data(), seed.size());

    log::info(
            logcat,
            "Encrypting (domain: {})...",
            domain == attachment::Domain::PROFILE_PIC ? "profile-pic" : "attachment");
    auto [encrypted, key] = attachment::encrypt(seed, plaintext, domain, true);
    auto enc_size = static_cast<int64_t>(encrypted.size());
    log::info(logcat, "Encrypted size: {}", human_size{enc_size});

    auto start = clock::now();
    std::promise<transfer_result> promise;
    auto future = promise.get_future();

    log::info(logcat, "Uploading {}...", human_size{enc_size});
    initiate(
            std::move(encrypted),
            ttl,
            [&](transfer_result r) { promise.set_value(std::move(r)); });

    auto result = future.get();
    auto elapsed_s = std::chrono::duration<double>(clock::now() - start).count();

    if (auto* meta = std::get_if<net::file_metadata>(&result)) {
        auto key_hex = oxenc::to_hex(key.begin(), key.end());
        auto speed = human_size{static_cast<int64_t>(enc_size / std::max(elapsed_s, 0.001))};

        log::info(
                logcat,
                "\nUpload complete!\n"
                "  File ID:  {}\n"
                "  Key:      {}\n"
                "  Size:     {}\n"
                "  Time:     {:.1f}s\n"
                "  Speed:    {}/s\n"
                "\n"
                "To download:\n"
                "{} {} {}",
                meta->id,
                key_hex,
                human_size{meta->size},
                elapsed_s,
                speed,
                download_cmd_hint,
                meta->id,
                key_hex);
        return 0;
    }

    log::error(logcat, "Upload failed with error {}", std::get<int16_t>(result));
    return 1;
}

int do_download(
        const std::string& key_hex,
        const std::string& output,
        std::function<void(on_data_t, on_complete_t)> initiate) {
    if (key_hex.size() != 64 || !oxenc::is_hex(key_hex)) {
        log::error(logcat, "Invalid key: expected 64 hex characters");
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
        out_stream->write(reinterpret_cast<const char*>(decrypted.data()), decrypted.size());
        decrypted_bytes += decrypted.size();
    }};

    auto start = clock::now();
    std::promise<transfer_result> promise;
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
                    log::info(
                            logcat,
                            "Transfer started after {:.0f}ms (file size: {})",
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
                    log::info(
                            logcat,
                            "[{}/{}] {}/s",
                            human_size{received_bytes},
                            human_size{info.size},
                            recent_speed);
                    last_progress = now;
                    last_progress_bytes = received_bytes;
                }
            },
            [&](transfer_result r) { promise.set_value(std::move(r)); });

    auto result = future.get();
    auto elapsed_s = std::chrono::duration<double>(clock::now() - start).count();

    if (auto* meta = std::get_if<net::file_metadata>(&result)) {
        if (!decryptor.finalize()) {
            if (out_file.is_open()) {
                out_file.close();
                std::filesystem::remove(output);
            }
            log::error(logcat, "Download succeeded but decryption finalization failed");
            return 1;
        }

        auto speed = human_size{
                static_cast<int64_t>(received_bytes / std::max(elapsed_s, 0.001))};
        log::info(
                logcat,
                "Download complete: {} encrypted, {} decrypted in {:.1f}s ({}/s)",
                human_size{received_bytes},
                human_size{decrypted_bytes},
                elapsed_s,
                speed);

        if (!output.empty())
            log::info(logcat, "Written to {}", output);
        return 0;
    }

    if (out_file.is_open()) {
        out_file.close();
        std::filesystem::remove(output);
    }
    log::error(logcat, "Download failed with error {}", std::get<int16_t>(result));
    return 1;
}

// --- Mode-specific runners ---

struct CliArgs {
    // Mode
    bool srouter = false;
    bool testnet = false;

    // Direct mode
    std::string server_pubkey_hex;
    std::string server_address = "::1";
    uint16_t server_port = fs::QUIC_DEFAULT_PORT;

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
    auto cache_dir = std::filesystem::temp_directory_path() / "quic_files_cache";
    std::filesystem::create_directories(cache_dir);

    std::vector<std::any> net_opts;
    net_opts.push_back(netid);
    net_opts.push_back(router);
    net_opts.push_back(net::opt::cache_directory{cache_dir});

    // For direct mode, pass the QUIC file server address/pubkey/port so that DirectRouter
    // uses the QUIC protocol instead of the legacy HTTP path.
    if (!args.srouter) {
        if (args.server_pubkey_hex.empty() || args.server_pubkey_hex.size() != 64 ||
            !oxenc::is_hex(args.server_pubkey_hex)) {
            fmt::print(stderr, "Error: --server (64 hex Ed25519 pubkey) is required for --direct\n");
            return 1;
        }
        if (args.server_address.empty()) {
            fmt::print(stderr, "Error: --address is required for --direct\n");
            return 1;
        }

        auto resolved = resolve_host(args.server_address);
        if (resolved != args.server_address)
            log::info(logcat, "Resolved {} -> {}", args.server_address, resolved);

        net_opts.push_back(net::opt::quic_file_server_ed_pubkey{args.server_pubkey_hex});
        net_opts.push_back(net::opt::quic_file_server_address{resolved});
        net_opts.push_back(net::opt::quic_file_server_port{args.server_port});
    }

    log::info(
            logcat,
            "Starting network ({}, {})...",
            args.testnet ? "testnet" : "mainnet",
            args.srouter ? "session-router" : "direct");

    auto network = std::make_shared<net::Network>(net_opts);

    std::string mode_hint = args.srouter
            ? fmt::format("{} --srouter{}", args.argv0, args.testnet ? " --testnet" : "")
            : fmt::format("{} --direct --server {} --address {} --port {}",
                    args.argv0, args.server_pubkey_hex, args.server_address, args.server_port);

    if (is_upload) {
        return do_upload(
                args.upload_filename,
                args.domain,
                args.ttl,
                [&](auto data, auto ttl, auto cb) {
                    auto uc = std::make_shared<std::vector<unsigned char>>(
                            reinterpret_cast<const unsigned char*>(data.data()),
                            reinterpret_cast<const unsigned char*>(data.data() + data.size()));
                    bool consumed = false;
                    net::UploadRequest req;
                    req.request_timeout = 60s;
                    req.overall_timeout = 300s;
                    req.ttl = ttl;
                    req.next_data = [uc, consumed]() mutable -> std::vector<unsigned char> {
                        if (consumed)
                            return {};
                        consumed = true;
                        return std::move(*uc);
                    };
                    req.on_complete = [cb = std::move(cb)](auto r, bool) {
                        cb(std::move(r));
                    };
                    network->upload(std::move(req));
                },
                fmt::format("{} download", mode_hint));
    }

    // Build download URL from file ID if not already a URL
    std::string download_url;
    if (args.dl_source.find("://") != std::string::npos)
        download_url = args.dl_source;
    else
        download_url = fs::generate_download_url(args.dl_source, network->file_server_config);

    log::info(logcat, "Downloading: {}", download_url);
    return do_download(args.dl_key_hex, args.dl_output, [&](auto on_data, auto cb) {
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

    CliArgs args;
    args.argv0 = argv[0];

    bool use_direct = false;
    app.add_flag("--srouter", args.srouter, "Route via session-router (onion-routed)");
    app.add_flag("--direct", use_direct, "Connect directly to the file server (no routing)");
    app.add_flag("--testnet", args.testnet, "Use testnet (default: mainnet; only for --srouter)");

    app.add_option("--server", args.server_pubkey_hex, "Ed25519 pubkey of the file server (hex)");
    app.add_option(
            "--address",
            args.server_address,
            "Server address; hostnames are resolved via DNS (default: ::1)");
    app.add_option(
            "--port",
            args.server_port,
            fmt::format("Server port (default: {})", fs::QUIC_DEFAULT_PORT));

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
    upload_cmd->add_option("--ttl", ttl_seconds, "TTL in seconds (default: 3600; ignored if --max-ttl)");

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
        if (!cats.cat_levels.count(STATUS_CAT))
            cats.cat_levels[STATUS_CAT] = log::Level::info;
        cats.apply();
    }

    return run(args, upload_cmd->parsed());
}
