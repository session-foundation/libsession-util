#include "session/network/routing/onion_request_router.hpp"

#include <fmt/ranges.h>

#include <oxen/log.hpp>
#include <oxen/log/format.hpp>

#include "session/network/network_opt.hpp"
#include "session/onionreq/builder.hpp"
#include "session/onionreq/response_parser.hpp"
#include "session/random.hpp"

using namespace oxen;
using namespace session;
using namespace session::network;
using namespace std::literals;
using namespace oxen::log::literals;

namespace session::network {

namespace {
    auto cat = oxen::log::Cat("network");

    constexpr auto node_not_found_prefix = "502 Bad Gateway\n\nNext node not found: "sv;
    constexpr auto node_not_found_prefix_no_status = "Next node not found: "sv;

    enum class PathSelectionBehaviour {
        random,
        new_or_least_busy,
    };

    inline std::string to_string(RequestCategory category, bool single_path_mode) {
        if (single_path_mode)
            return "single_path";

        return to_string(category);
    }

    PathSelectionBehaviour get_path_selection_behaviour(RequestCategory category) {
        switch (category) {
            case RequestCategory::standard: return PathSelectionBehaviour::random;
            case RequestCategory::upload: return PathSelectionBehaviour::new_or_least_busy;
            case RequestCategory::download: return PathSelectionBehaviour::new_or_least_busy;
        }
        return PathSelectionBehaviour::random;
    }

    std::vector<service_node> extract_nodes(
            const std::unordered_map<RequestCategory, std::vector<OnionPath>>& paths,
            const std::unordered_map<std::string, std::vector<service_node>>& pending_paths) {
        std::vector<service_node> all_used_nodes;

        for (const auto& [pt, path_list] : paths)
            for (const auto& p : path_list)
                all_used_nodes.insert(all_used_nodes.end(), p.nodes.begin(), p.nodes.end());

        for (const auto& [pid, nodes] : pending_paths)
            all_used_nodes.insert(all_used_nodes.end(), nodes.begin(), nodes.end());

        return all_used_nodes;
    }
}  // namespace

std::string OnionPath::to_string() const {
    std::vector<std::string> node_descriptions;
    std::transform(
            nodes.begin(),
            nodes.end(),
            std::back_inserter(node_descriptions),
            [](const service_node& node) { return node.to_string(); });

    return "{}"_format(fmt::join(node_descriptions, ", "));
}

OnionRequestRouter::OnionRequestRouter(
        config::OnionRequestRouterConfig config,
        std::shared_ptr<oxen::quic::Loop> loop,
        std::weak_ptr<SnodePool> snode_pool,
        std::weak_ptr<ITransport> transport) :
        _config{std::move(config)}, _loop{std::move(loop)}, _snode_pool{snode_pool}, _transport{transport} {
    log::trace(cat, "[OnionRequestRouter] Initializing.");

    _request_queues[RequestCategory::standard] =
            std::make_shared<detail::RequestQueue>(_loop, _config.request_timeout_check_frequency);
    _request_queues[RequestCategory::upload] =
            std::make_shared<detail::RequestQueue>(_loop, _config.request_timeout_check_frequency);
    _request_queues[RequestCategory::download] =
            std::make_shared<detail::RequestQueue>(_loop, _config.request_timeout_check_frequency);

    _loop->call_soon([this] {
        auto snode_pool = _snode_pool.lock();
        if (!snode_pool) {
            log::critical(
                    cat, "[OnionRequestRouter] SnodePool was destroyed, cannot setup router.");
            return;
        }

        if (snode_pool->size() == 0)
            snode_pool->refresh_if_needed({}, [weak_self = weak_from_this()] {
                if (auto self = weak_self.lock())
                    self->_loop->call([weak_self] {
                        if (auto self = weak_self.lock())
                            self->_finish_setup();
                    });
            });
        else
            _finish_setup();
    });
}

OnionRequestRouter::~OnionRequestRouter() {
    // Use 'call_get' to force this to be synchronous
    if (_loop)
        _loop->call_get([this] { _close_connections(); });
    log::debug(cat, "[OnionRequestRouter] Destroyed.");
}

// MARK: IRouter

void OnionRequestRouter::suspend() {
    // Use 'call_get' to force this to be synchronous
    _loop->call_get([this] {
        _suspended = true;
        _close_connections();
        log::info(cat, "[OnionRequestRouter] Suspended.");
    });
}

void OnionRequestRouter::resume(bool automatically_reconnect) {
    // Use 'call_get' to force this to be synchronous
    _loop->call_get([this, automatically_reconnect] {
        if (!_suspended)
            return;

        _suspended = false;

        if (automatically_reconnect)
            _pre_build_paths_if_needed();

        log::info(cat, "[OnionRequestRouter] Resumed.");
    });
}

void OnionRequestRouter::close_connections() {
    // Use 'call_get' to force this to be synchronous
    _loop->call_get([this] { _close_connections(); });
}

std::vector<PathInfo> OnionRequestRouter::get_active_paths() {
    return _loop->call_get([this] {
        std::vector<PathInfo> result;
        result.reserve(_paths.size());

        for (const auto& [category, path_list] : _paths)
            for (const auto& p : path_list)
                result.push_back({p.nodes, OnionPathMetadata{category}});

        return result;
    });
}

std::vector<service_node> OnionRequestRouter::get_all_used_nodes() {
    return _loop->call_get([this] { return extract_nodes(_paths, _pending_paths); });
}

void OnionRequestRouter::send_request(Request request, network_response_callback_t callback) {
    _loop->call([weak_self = weak_from_this(), req = std::move(request), cb = std::move(callback)] {
        if (auto self = weak_self.lock())
            self->_send_request_internal(std::move(req), std::move(cb));
    });
}

// MARK: Internal Logic

void OnionRequestRouter::_finish_setup() {
    // Start processing requests
    _ready = true;
    log::debug(cat, "[OnionRequestRouter] Finishing setup, router is now ready.");

    // Pre-build paths if needed
    _pre_build_paths_if_needed();

    // Process any requests that were queued before we were ready
    for (auto& [category, queue] : _request_queues) {
        if (!queue->is_empty()) {
            auto pending = queue->pop_all();
            log::debug(
                    cat,
                    "[OnionRequestRouter] Processing {} requests queued during initialization for "
                    "category '{}'.",
                    pending.size(),
                    to_string(category));

            for (auto& [req, cb] : pending)
                _send_request_internal(std::move(req), std::move(cb));
        }
    }
}

void OnionRequestRouter::_pre_build_paths_if_needed() {
    if (!_config.disable_pre_build_paths) {
        log::info(cat, "[OnionRequestRouter] Pre-building initial paths.");

        auto schedule_build = [this](RequestCategory category, int count) {
            for (int i = 0; i < count; ++i)
                _build_path(
                        category,
                        "pre-build-{}-{}"_format(
                                to_string(category, _config.single_path_mode), i + 1),
                        {});
        };

        if (_config.single_path_mode) {
            log::debug(cat, "[OnionRequestRouter] Pre-building 1 path for single_path_mode.");
            schedule_build(RequestCategory::standard, 1);
        } else {
            for (const auto& [category, min_count] : _config.min_path_counts) {
                if (min_count > 0) {
                    log::debug(
                            cat,
                            "[OnionRequestRouter] Pre-building {} path(s) for category '{}'.",
                            min_count,
                            to_string(category, _config.single_path_mode));
                    schedule_build(category, min_count);
                }
            }
        }
    } else
        log::debug(cat, "[OnionRequestRouter] Path pre-building is disabled.");
}

void OnionRequestRouter::_close_connections() {
    // Cancel any pending requests (they can't succeed once the connection is closed)
    for (auto& [path_type, path_type_queue] : _request_queues) {
        auto to_fail = path_type_queue->pop_all();

        for (const auto& [req, callback] : to_fail)
            callback(
                    false,
                    false,
                    ERROR_NETWORK_SUSPENDED,
                    {content_type_plain_text},
                    "Network is suspended.");
    }

    // Remove any failure listeners for the edge nodes of the current paths
    if (auto transport = _transport.lock())
        for (const auto& [category, path_list] : _paths)
            for (const auto& p : path_list)
                if (!p.nodes.empty())
                    transport->remove_failure_listeners(
                            ed25519_pubkey::from_bytes(p.nodes[0].view_remote_key()));

    // Clear all storage of requests, paths and connections so that we are in a fresh state on
    // relaunch
    //
    // The connection status is recalculated based on these values so we need to call them
    // before recalculation so it correctly detects the "disconnected" state
    _paths.clear();
    _paths_pending_drop.clear();
    _in_progress_path_builds.clear();
    _path_build_retries.clear();
    _pending_paths.clear();
    _update_status();
    log::info(cat, "[OnionRequestRouter] Closed all connections.");
}

void OnionRequestRouter::_update_status() {
    ConnectionStatus new_status = ConnectionStatus::disconnected;

    // If we have at least one active "standard" path we are considered connected
    auto paths_it = _paths.find(RequestCategory::standard);
    if (paths_it != _paths.end() && !paths_it->second.empty())
        new_status = ConnectionStatus::connected;
    // If we have at least one active non-standard path then considered connecting (not properly
    // connected, but some requests may work)
    else if (std::any_of(
                     _paths.begin(), _paths.end(), [](const auto& p) { return !p.second.empty(); }))
        new_status = ConnectionStatus::connecting;
    // Otherwise if we are building one then we are connecting
    else if (std::any_of(
                     _in_progress_path_builds.begin(),
                     _in_progress_path_builds.end(),
                     [](const auto& p) { return p.second > 0; }))
        new_status = ConnectionStatus::connecting;

    if (_status.load() != new_status) {
        _status.store(new_status);

        if (on_status_changed)
            on_status_changed();
    }
}

void OnionRequestRouter::_send_request_internal(
        Request request, network_response_callback_t callback) {
    // If we are suspended then fail immediately
    if (_suspended)
        return callback(
                false,
                false,
                ERROR_NETWORK_SUSPENDED,
                {content_type_plain_text},
                "OnionRequestRouter is suspended.");

    auto initiating_req_category =
            (_config.single_path_mode ? RequestCategory::standard : request.category);

    if (!_ready) {
        log::debug(
                cat,
                "[OnionRequestRouter Request {}]: Router not ready, queueing request.",
                request.request_id);

        try {
            _request_queues.at(initiating_req_category)
                    ->add(std::move(request), std::move(callback));
        } catch (const std::exception& e) {
            log::critical(
                    cat,
                    "[OnionRequestRouter] No request queue for category '{}', request {} is being "
                    "dropped.",
                    to_string(initiating_req_category, _config.single_path_mode),
                    request.request_id);
            return callback(
                    false, false, -1, {content_type_plain_text}, "Unhandled request category");
        }
        return;
    }

    // Try to use an existing path if we have one
    log::trace(
            cat,
            "[OnionRouter Request {}]: Received request for category '{}', searching for a path.",
            request.request_id,
            to_string(initiating_req_category, _config.single_path_mode));
    OnionPath* path = _find_valid_path(request);

    if (path) {
        log::debug(
                cat,
                "[OnionRouter Request {}]: Found valid path {}, sending.",
                request.request_id,
                path->id);
        _send_on_path(*path, std::move(request), std::move(callback));
        return;
    }

    // No valid path, queue the request an build a path
    log::debug(
            cat,
            "[OnionRouter Request {}]: No path available, queueing request.",
            request.request_id);

    // Add the request to the queue for its category
    auto initiating_req_id = request.request_id;

    try {
        _request_queues.at(initiating_req_category)->add(std::move(request), std::move(callback));
    } catch (const std::exception& e) {
        log::critical(
                cat,
                "[OnionRequestRouter] No request queue for category '{}', request {} is being "
                "dropped.",
                to_string(initiating_req_category, _config.single_path_mode),
                request.request_id);
        return callback(false, false, -1, {content_type_plain_text}, "Unhandled request category");
    }

    // Check if we need to build additional paths
    const auto current =
            _paths.count(initiating_req_category) ? _paths.at(initiating_req_category).size() : 0;
    const auto in_progress = _in_progress_path_builds[initiating_req_category];
    bool should_build = false;

    // In single path mode, we only build if we have zero paths (current or in-progress)
    if (_config.single_path_mode)
        should_build = (current + in_progress == 0);
    else {
        // In multi-path mode, we build if we are below the min number
        const auto needed = _config.min_path_counts.at(initiating_req_category);
        should_build = (current + in_progress < needed);
    }

    if (should_build) {
        log::info(
                cat,
                "[OnionRouter Request {}]: Path count for '{}' is insufficient, building new path.",
                initiating_req_id,
                to_string(initiating_req_category, _config.single_path_mode));

        _build_path(initiating_req_category, initiating_req_id, {});
    }
}

void OnionRequestRouter::_build_path(
        RequestCategory category,
        std::optional<std::string> initiating_req_id,
        const std::vector<service_node>& nodes_to_exclude_,
        std::optional<std::string> original_path_id) {
    if (_suspended) {
        log::info(cat, "Ignoring build_path call as network is suspended.");
        return;
    }

    const std::string req_id_log = (initiating_req_id ? *initiating_req_id : "internal");
    const std::string path_id = original_path_id.value_or("P-" + random::random_base32(4));
    log::info(
            cat,
            "[OnionRouter Request {} Path {}]: Starting build for {} path.",
            req_id_log,
            path_id,
            to_string(category, _config.single_path_mode));

    // If we were misconfigured to have a `path_length` of `0` then just fail all requests
    if (_config.path_length == 0) {
        log::error(
                cat,
                "[OnionRouter Request {} Path {}]: Cannot build path, path_size is configured to "
                "0.",
                req_id_log,
                path_id);

        auto queue_it = _request_queues.find(category);
        if (queue_it == _request_queues.end()) {
            log::critical(
                    cat,
                    "[OnionRequestRouter] No request queue for category '{}'.",
                    to_string(category, _config.single_path_mode));
            return;
        }

        if (!queue_it->second->is_empty()) {
            auto to_fail = queue_it->second->pop_all();

            for (const auto& [req, cb] : to_fail)
                cb(false,
                   false,
                   -1,
                   {content_type_plain_text},
                   "Router misconfigured: path_length is 0.");
        }
        return;
    }

    _in_progress_path_builds[category]++;
    _update_status();

    auto nodes_to_exclude = extract_nodes(_paths, _pending_paths);
    nodes_to_exclude.insert(
            nodes_to_exclude.end(), nodes_to_exclude_.begin(), nodes_to_exclude_.end());

    std::vector<service_node> path_nodes;

    auto snode_pool = _snode_pool.lock();
    if (!snode_pool) {
        log::critical(cat, "[OnionRequestRouter] SnodePool was destroyed, cannot build path.");
        return;
    }

    path_nodes = snode_pool->get_unused_nodes(_config.path_length, nodes_to_exclude);

    // If we don't have enough nodes to build a path then we should try to refresh the snode pool
    if (path_nodes.size() < _config.path_length) {
        log::warning(
                cat,
                "[OnionRouter Request {} Path {}]: Failed to get enough nodes from SnodePool (need "
                "{}, got {}), queueing retry after pool refresh.",
                req_id_log,
                path_id,
                _config.path_length,
                path_nodes.size());
        _in_progress_path_builds[category]--;

        snode_pool->refresh_if_needed(
                nodes_to_exclude,
                [weak_self = weak_from_this(), category, initiating_req_id, nodes_to_exclude]() {
                    auto self = weak_self.lock();
                    if (!self)
                        return;

                    log::info(
                            cat,
                            "[OnionRouter Request {}]: SnodePool refresh complete, "
                            "retrying "
                            "path build.",
                            initiating_req_id.value_or("internal"));
                    self->_build_path(category, initiating_req_id, nodes_to_exclude);
                });
        return;
    }

    // Attempty to verify connectivity to the edge node
    _pending_paths[path_id] = path_nodes;
    auto edge_node = path_nodes.front();
    log::debug(
            cat,
            "[OnionRouter Request {} Path {}]: Testing connectivity to edge node {}.",
            req_id_log,
            path_id,
            edge_node.to_string());

    auto transport = _transport.lock();
    if (!transport) {
        log::critical(cat, "[OnionRequestRouter] Transport was destroyed, cannot build path.");
        return;
    }

    transport->verify_connectivity(
            edge_node,
            3s,
            "{} - Path Build {}"_format(req_id_log, path_id),
            [weak_self = weak_from_this(), path_id, category, initiating_req_id](bool success) {
                if (auto self = weak_self.lock())
                    self->_on_edge_connectivity_response(
                            path_id, category, initiating_req_id, success);
            });
}

void OnionRequestRouter::_on_edge_connectivity_response(
        const std::string& path_id,
        RequestCategory category,
        std::optional<std::string> initiating_req_id,
        bool success) {
    const std::string req_id_log = initiating_req_id.value_or("internal");

    auto pending_it = _pending_paths.find(path_id);
    if (pending_it == _pending_paths.end()) {
        log::warning(
                cat,
                "[OnionRouter Request {} Path {}]: Received connection callback for a path that is "
                "no longer pending, ignoring.",
                req_id_log,
                path_id);
        return;
    }

    // Extract the pending path nodes and remove it from the pending list
    auto path_nodes = std::move(pending_it->second);
    _pending_paths.erase(pending_it);

    const auto& edge_node = path_nodes.front();

    if (_in_progress_path_builds[category] > 0)
        _in_progress_path_builds[category]--;

    if (!success) {
        // The edge node failed so record the failure and try to build a new path to replace this
        // failed one (excluding the failed edge node from the next attempt)
        log::warning(
                cat,
                "[OnionRouter Request {} Path {}]: Failed to verify connectivity to edge node {}, "
                "retrying path build.",
                req_id_log,
                path_id,
                edge_node.to_string());
        if (auto snode_pool = _snode_pool.lock())
            snode_pool->record_node_failure(edge_node);

        int& retries = _path_build_retries[path_id];
        retries++;

        // If we tried, and failed, to build the path too many times then give up and fail all
        // pending requests
        if (retries > _config.path_build_retry_limit) {
            log::critical(
                    cat,
                    "[OnionRouter Path {}]: Aborting build after {} failed attempts.",
                    path_id,
                    retries);
            _path_build_retries.erase(path_id);
            _update_status();

            auto queue_it = _request_queues.find(category);
            if (queue_it == _request_queues.end()) {
                log::critical(
                        cat,
                        "[OnionRequestRouter] No request queue for category '{}'.",
                        to_string(category, _config.single_path_mode));
                return;
            }

            if (!queue_it->second->is_empty()) {
                auto to_fail = queue_it->second->pop_all();
                log::error(
                        cat,
                        "[OnionRequestRouter] Failing {} queued requests for '{}' paths due to "
                        "persistent path build failures.",
                        to_fail.size(),
                        to_string(category, _config.single_path_mode));

                for (const auto& [req, cb] : to_fail)
                    cb(false,
                       false,
                       -1,
                       {content_type_plain_text},
                       "Failed to build a required onion path after multiple retries.");
            }
            return;
        }

        auto delay = _config.retry_delay.exponential(retries);
        log::info(
                cat,
                "[OnionRouter Path {}]: Retrying path build in {}ms (attempt {}/{})",
                path_id,
                delay.count(),
                retries,
                _config.path_build_retry_limit);
        _update_status();

        _loop->call_later(
                delay,
                [weak_self = weak_from_this(), path_id, category, initiating_req_id, edge_node] {
                    if (auto self = weak_self.lock())
                        self->_build_path(category, initiating_req_id, {edge_node}, path_id);
                });
        return;
    }

    OnionPath new_path{path_id, std::move(path_nodes)};
    log::info(
            cat,
            "[OnionRouter Request {} Path {}]: New {} path is active with nodes: [{}].",
            req_id_log,
            path_id,
            to_string(category, _config.single_path_mode),
            new_path.to_string());
    _paths[category].push_back(std::move(new_path));
    _path_build_retries.erase(path_id);
    _update_status();

    // Now, check the queue for any requests that were waiting for this path.
    auto queue_it = _request_queues.find(category);
    if (queue_it == _request_queues.end()) {
        log::critical(
                cat,
                "[OnionRequestRouter] No request queue for category '{}'.",
                to_string(category, _config.single_path_mode));
        return;
    }

    auto pending_requests = queue_it->second->pop_all();

    if (!pending_requests.empty()) {
        std::deque<std::pair<Request, network_response_callback_t>> requeue;
        log::debug(
                cat,
                "[OnionRouter Request {} Path {}]: Processing {} queued requests.",
                req_id_log,
                path_id,
                pending_requests.size());

        for (auto&& [req, cb] : std::move(pending_requests)) {
            // Retrieve any path that is valid for the request
            OnionPath* path_to_use = _find_valid_path(req);

            if (path_to_use)
                _send_on_path(*path_to_use, std::move(req), std::move(cb));
            else
                requeue.emplace_back(std::move(req), std::move(cb));
        }

        // Put any un-sendable requests back into the front of the queue (or fail in
        // `single_path_mode`)
        if (!requeue.empty()) {
            if (_config.single_path_mode) {
                log::warning(
                        cat,
                        "[OnionRouter Path {}]: {} requests could not be sent on the single "
                        "available path, failing them.",
                        path_id,
                        requeue.size());
                for (const auto& [req, cb] : requeue)
                    cb(false,
                       false,
                       -1,
                       {content_type_plain_text},
                       "Request destination conflicts with the only available path in "
                       "single_path_mode");

                return;
            }

            log::debug(
                    cat,
                    "[OnionRouter Path {}]: Unable to process {} queued requests, requing them.",
                    path_id,
                    requeue.size());

            while (!requeue.empty()) {
                auto& req_pair = requeue.back();
                queue_it->second->add_front(std::move(req_pair));
                requeue.pop_back();
            }

            if (_in_progress_path_builds[category] == 0) {
                log::info(
                        cat,
                        "[OnionRequestRouter] Building additional {} path for remaining requests.",
                        to_string(category, _config.single_path_mode));
                _build_path(category, "requeue-build", {});
            }
        }
    }

    // Now that we've established a path we need to start observing it in case the connection is
    // lost
    auto transport = _transport.lock();
    if (!transport)
        return;

    transport->add_failure_listener(
            ed25519_pubkey::from_bytes(edge_node.view_remote_key()),
            [weak_self = weak_from_this(), pid = path_id, category] {
                auto self = weak_self.lock();
                if (!self)
                    return;

                log::warning(
                        cat,
                        "[OnionRequestRouter Path {}]: Transport reported connection "
                        "failure, "
                        "retiring path.",
                        pid);

                // Set the failure_count of the path to the max value and report the error
                // to trigger a rebuild
                auto& active_paths = self->_paths[category];
                auto path_it = std::find_if(
                        active_paths.begin(), active_paths.end(), [&pid](const auto& p) {
                            return p.id == pid;
                        });

                if (path_it != active_paths.end())
                    path_it->failure_count = self->_config.path_failure_threshold;

                self->_handle_path_failure(pid, category, "Edge connection lost");
            });
}

OnionPath* OnionRequestRouter::_find_valid_path(const Request& request) {
    auto it = _paths.find(request.category);
    if (it == _paths.end() || it->second.empty())
        return nullptr;

    std::vector<OnionPath>& candidate_paths = it->second;
    std::vector<OnionPath*> suitable_paths;
    suitable_paths.reserve(candidate_paths.size());

    auto target_node = std::get_if<service_node>(&request.destination);

    for (OnionPath& path : candidate_paths) {
        // Ignore failed paths (these should have been removed from the list but better to be safe)
        if (path.failure_count >= _config.path_failure_threshold)
            continue;

        // Filter by destination conflict
        if (target_node) {
            bool conflict = false;

            for (const auto& path_node : path.nodes) {
                if (path_node == *target_node) {
                    conflict = true;
                    break;
                }
            }

            if (conflict && _config.single_path_mode)
                log::warning(
                        cat,
                        "[OnionRouter Request {}]: Path destination conflicts with the only "
                        "available path, but single_path_mode is enabled, proceeding.",
                        request.request_id);
            else if (conflict)
                continue;
        }

        suitable_paths.push_back(&path);
    }

    if (suitable_paths.empty())
        return nullptr;

    PathSelectionBehaviour behaviour = get_path_selection_behaviour(request.category);

    switch (behaviour) {
        case PathSelectionBehaviour::new_or_least_busy: {
            // Sort by the number of pending requests, ascending
            std::sort(
                    suitable_paths.begin(),
                    suitable_paths.end(),
                    [](const OnionPath* a, const OnionPath* b) {
                        return a->pending_requests < b->pending_requests;
                    });

            OnionPath* best_path = suitable_paths.front();
            const auto min_paths_for_type = _config.min_path_counts[request.category];

            // Return the path with the fewest pending requests if we had one with no requets, or
            // already have the minimum number of paths for this type
            if (best_path->pending_requests == 0 || candidate_paths.size() >= min_paths_for_type)
                return best_path;

            // Otherwise we want to build a new path (for this PathSelectionBehaviour the assuption
            // is that it'd be faster to build a new path and send the request along that rather
            // than use an existing path)
            return nullptr;
        }

        case PathSelectionBehaviour::random:
        default:
            // Shuffle the suitable paths to pick a random one.
            std::shuffle(suitable_paths.begin(), suitable_paths.end(), csrng);
            return suitable_paths.front();
    }
}

void OnionRequestRouter::_send_on_path(
        OnionPath& path, Request request, network_response_callback_t callback) {
    log::trace(cat, "[OnionRouter Request {}]: Sending on path {}", request.request_id, path.id);

    std::vector<unsigned char> encrypted_blob;
    std::shared_ptr<session::onionreq::ResponseParser> parser;

    try {
        auto builder =
                session::onionreq::Builder(request.destination, request.endpoint, path.nodes);
        encrypted_blob = builder.generate_onion_blob(request.body);
        parser = std::make_shared<session::onionreq::ResponseParser>(builder);
    } catch (const std::exception& e) {
        log::warning(
                cat,
                "[OnionRouter Request {}]: Failed to prepare onion payload: {}",
                request.request_id,
                e.what());
        return callback(
                false,
                false,
                -1,
                {content_type_plain_text},
                "Failed to construct onion request payload");
    }

    // Construct the actual request to send
    std::optional<std::chrono::milliseconds> remaining_overall_timeout =
            (request.overall_timeout.has_value() ? std::optional{request.time_remaining()}
                                                 : std::nullopt);
    Request onion_request{
            request.request_id,
            network_destination{path.nodes.front()},  // Send to edge node
            std::string{"onion_req"},                 // Send to onion request handling endpoint
            std::move(encrypted_blob),                // Encrypted payload
            request.category,
            request.time_remaining(),
            remaining_overall_timeout};

    // Increment the `pending_requests` and actually send the `onion_request`
    path.pending_requests++;

    auto transport = _transport.lock();
    if (!transport) {
        log::critical(cat, "[OnionRequestRouter] Transport was destroyed, cannot send request.");
        return;
    }

    auto decryption_callback = [weak_self = weak_from_this(),
                                parser = std::move(parser),
                                path_id = path.id,
                                original_request = std::move(request),
                                cb = std::move(callback)](
                                       bool success,
                                       bool timeout,
                                       int16_t status,
                                       auto headers,
                                       auto response) {
        auto self = weak_self.lock();
        if (!self)
            return;

        try {
            if (!success)
                throw std::runtime_error{response.value_or("Unknown request failure")};
            if (timeout)
                throw std::runtime_error{response.value_or("Timed out")};
            if (!response)
                throw std::runtime_error{"Unexpected empty response"};

            onionreq::DecryptedResponse decrypted = parser->decrypted_response(*response);
            self->_handle_transport_response(
                    path_id,
                    std::move(original_request),
                    true,
                    false,
                    decrypted.status_code,
                    std::move(decrypted.headers),
                    std::move(decrypted.body),
                    std::move(cb));
        } catch (const std::exception& e) {
            self->_handle_transport_response(
                    path_id,
                    std::move(original_request),
                    false,
                    timeout,
                    status,
                    std::move(headers),
                    std::move("Failed to handle onion response due to error: {}"_format(e.what())),
                    std::move(cb));
        }
    };

    transport->send_request(std::move(onion_request), std::move(decryption_callback));
}

void OnionRequestRouter::_handle_transport_response(
        std::string path_id,
        Request original_request,
        bool success,
        bool timeout,
        int16_t status_code,
        std::vector<std::pair<std::string, std::string>> headers,
        std::optional<std::string> decrypted_body,
        network_response_callback_t callback) {
    auto final_success = success;
    auto final_timeout = timeout;
    auto final_status_code = status_code;
    std::vector<std::pair<std::string, std::string>> final_headers = headers;
    bool should_penalize_path = false;
    bool is_server_dest = std::holds_alternative<ServerDestination>(original_request.destination);

    if (decrypted_body)
        if (auto uniform_error = Response::find_uniform_batch_error(*decrypted_body))
            final_status_code = *uniform_error;

    if (final_success)
        final_success = (final_status_code >= 200 && final_status_code <= 299);

    if (!final_success) {
        switch (final_status_code) {
            // These errors that are NEVER the path's fault
            case 400:  // Bad Request
            case 403:  // Forbidden
            case 404:  // Not Found
            case 406:  // Not Acceptable (clock skew)
            case 425:  // Too Early (also clock skew)
                // These are application-level or client-side errors. Do nothing to
                // the path.
                log::trace(
                        cat,
                        "[OnionRouter Request {}]: Received benign error {}, path is considered "
                        "healthy.",
                        original_request.request_id,
                        final_status_code);
                break;

            // These errors are only the path's fault if the destination is not a
            // server
            case 500:  // Internal Server Error
                if (!is_server_dest)
                    should_penalize_path = true;
                break;

            case 504:  // Gateway Timeout
                final_timeout = true;

                if (!is_server_dest)
                    should_penalize_path = true;
                break;

            // A status of -1 generally indicates either a timeout or some internal error
            case -1: break;

            // Any other non-success code is treated as a potential path issue.
            default: should_penalize_path = true; break;
        }
    }

    // If we got a timeout and the destination wasn't a server then we need to
    // assume it was from a path node
    if (!is_server_dest && timeout)
        should_penalize_path = true;

    // Handle the failure if needed
    if (should_penalize_path) {
        log::debug(
                cat,
                "[OnionRouter Request {}]: Received error {} on path {}, handling "
                "failure.",
                original_request.request_id,
                final_status_code,
                path_id);
        _handle_path_failure(path_id, original_request.category, decrypted_body);
    }

    // Clean up paths if needed
    _decrement_and_cleanup_path(path_id, original_request.category);

    // Now we can trigger the callback with the result
    return callback(
            final_success,
            final_timeout,
            final_status_code,
            std::move(headers),
            std::move(decrypted_body));
}

void OnionRequestRouter::_decrement_and_cleanup_path(
        const std::string& path_id, RequestCategory category) {
    // Check active paths first
    auto& active_paths = _paths[category];

    if (auto it = std::find_if(
                active_paths.begin(),
                active_paths.end(),
                [&path_id](const auto& p) { return p.id == path_id; });
        it != active_paths.end()) {
        if (it->pending_requests > 0)
            it->pending_requests--;

        // The path is still active so we don't need to do anything else
        return;
    }

    // If we didn't find an active path then check paths pending drop
    auto& dying_paths = _paths_pending_drop[category];
    if (auto it = std::find_if(
                dying_paths.begin(),
                dying_paths.end(),
                [&path_id](const auto& p) { return p.id == path_id; });
        it != dying_paths.end()) {
        if (it->pending_requests > 0)
            it->pending_requests--;

        // If this was the last request, we can now safely delete the path
        if (it->pending_requests == 0) {
            log::debug(
                    cat,
                    "[OnionRequestRouter] Retiring path {} as it has no more pending requests.",
                    path_id);
            dying_paths.erase(it);
        }

        return;
    }

    // This can happen if the path was already retired and removed, it's not an error
    log::trace(
            cat,
            "[OnionRequestRouter] Request completed on path {}, which has already been removed.",
            path_id);
}

void OnionRequestRouter::_handle_path_failure(
        const std::string& path_id,
        const RequestCategory& request_category,
        const std::optional<std::string>& error_body) {
    auto& active_paths = _paths[request_category];
    auto path_it =
            std::find_if(active_paths.begin(), active_paths.end(), [&path_id](const auto& p) {
                return p.id == path_id;
            });

    // If the path is no longer in the active list then no need to do anything
    if (path_it == active_paths.end()) {
        log::trace(
                cat,
                "[OnionRouter Path {}]: Failure on path, but path is no longer active.",
                path_id);
        return;
    }

    // Increment the `failure_count` on the path
    OnionPath& path = *path_it;
    path.failure_count++;

    // If the path is still potentially valid then check if the response has one of the
    // 'node_not_found' prefixes
    if (path.failure_count < _config.path_failure_threshold) {
        std::optional<std::string_view> ed25519PublicKey;

        if (error_body) {
            if (error_body->starts_with(node_not_found_prefix))
                ed25519PublicKey = {error_body->data() + node_not_found_prefix.size()};
            else if (error_body->starts_with(node_not_found_prefix_no_status))
                ed25519PublicKey = {error_body->data() + node_not_found_prefix_no_status.size()};
        }

        // If we found a result then try to extract the pubkey and replace that node in the path. We
        // do still want to increment the `failure_count` on the path in this case to prevent a
        // rogue relay from using this error as a mechanism to take full control of the path
        if (ed25519PublicKey && ed25519PublicKey->size() == 64 &&
            oxenc::is_hex(*ed25519PublicKey)) {
            try {
                session::network::ed25519_pubkey bad_node_pk =
                        session::network::ed25519_pubkey::from_hex(*ed25519PublicKey);
                auto edpk_view = to_span(bad_node_pk.view());

                auto bad_node_it = std::find_if(
                        path.nodes.begin(), path.nodes.end(), [&edpk_view](const auto& node) {
                            return to_string_view(node.view_remote_key()) ==
                                   to_string_view(edpk_view);
                        });

                if (bad_node_it != path.nodes.end()) {
                    log::debug(
                            cat,
                            "[OnionRouter Path {}]: Failure identified for specific node {}.",
                            path.id,
                            bad_node_pk.view());
                    std::vector<service_node> replacements;

                    auto snode_pool = _snode_pool.lock();
                    if (!snode_pool) {
                        log::critical(
                                cat,
                                "[OnionRequestRouter] Cannot repair path as SnodePool was "
                                "destroyed, dropping instead.");
                        path.failure_count = _config.path_failure_threshold;
                        return;
                    }

                    // Flag the bad node as permanently failed until the next cache refresh
                    snode_pool->record_node_failure(*bad_node_it, true);

                    auto used_nodes = extract_nodes(_paths, _pending_paths);
                    replacements = snode_pool->get_unused_nodes(1, used_nodes);

                    // If we found a replacement node then swap out the bad one and reset the
                    // path failure count (assume the bad node was the cause of any failures),
                    // we can then stop here (the path is repaired so no need to continue)
                    if (!replacements.empty()) {
                        log::info(
                                cat,
                                "[OnionRouter Path {}]: Repairing path by replacing node {} "
                                "with {}.",
                                path.id,
                                bad_node_it->to_string(),
                                replacements[0].to_string());
                        *bad_node_it = replacements[0];
                    } else {
                        log::warning(
                                cat,
                                "[OnionRouter Path {}]: Cannot repair path due to lack of "
                                "replacement node, dropping instead.",
                                path.id);
                        path.failure_count = _config.path_failure_threshold;
                    }
                }
            } catch (...) { /* Invalid pubkey, fall through to general failure */
            }
        }
    }

    log::debug(
            cat,
            "[OnionRouter Path {}]: Recorded failure, total failures: {}/{}",
            path.id,
            path.failure_count,
            _config.path_failure_threshold);

    // If the path has exceeded its failure threshold, retire it.
    if (path.failure_count >= _config.path_failure_threshold) {
        log::warning(
                cat, "[OnionRouter Path {}]: Path has exceeded its failure threshold.", path.id);

        // Tell the SnodePool that all nodes on this path are now suspect
        if (auto snode_pool = _snode_pool.lock())
            for (const auto& node : path.nodes)
                snode_pool->record_node_failure(node);

        // Remove failure listeners for the path
        if (auto transport = _transport.lock())
            if (!path.nodes.empty())
                transport->remove_failure_listeners(
                        ed25519_pubkey::from_bytes(path.nodes[0].view_remote_key()));

        // Store for subsequent path building
        const auto old_path_id = path.id;
        auto nodes_to_exclude = path.nodes;

        if (path.pending_requests == 0) {
            log::debug(cat, "[OnionRouter Path {}]: Retiring idle path immediately.", old_path_id);
            active_paths.erase(path_it);
            _update_status();
        } else {
            log::debug(
                    cat,
                    "[OnionRouter Path {}]: Retiring active path ({} pending requests), moving to "
                    "pending drop.",
                    old_path_id,
                    path.pending_requests);
            _paths_pending_drop[request_category].push_back(std::move(path));
            active_paths.erase(path_it);
            _update_status();
        }

        // Automatically rebuild if needed
        RequestCategory category_to_rebuild =
                (_config.single_path_mode ? RequestCategory::standard : request_category);
        const auto min_paths =
                (_config.single_path_mode ? 1 : _config.min_path_counts.at(category_to_rebuild));
        const auto current_active =
                (_paths.count(category_to_rebuild) ? _paths.at(category_to_rebuild).size() : 0);
        const auto in_progress = _in_progress_path_builds[category_to_rebuild];

        if (current_active + in_progress < min_paths) {
            log::info(
                    cat,
                    "[OnionRequestRouter] Path count for {} is below the minimum {}, building "
                    "replacement.",
                    to_string(request_category, _config.single_path_mode),
                    min_paths);
            _build_path(request_category, "failure-replacement-" + old_path_id, nodes_to_exclude);
        }
    }
}

}  // namespace session::network
