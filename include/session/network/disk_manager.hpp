#pragma once

#include <condition_variable>
#include <deque>
#include <functional>
#include <mutex>
#include <oxen/log.hpp>
#include <oxen/log/format.hpp>
#include <string>
#include <thread>
#include <unordered_set>

namespace session::network {

class empty_file_exception : public std::runtime_error {
  public:
    empty_file_exception() : std::runtime_error("Empty file") {}
};

namespace {
    inline auto disk_cat = oxen::log::Cat("disk-manager");

    struct TaskEntry {
        std::string tag;
        std::function<void()> task;
    };

    struct string_hash {
        using is_transparent = void;

        size_t operator()(std::string_view sv) const { return std::hash<std::string_view>{}(sv); }
    };
}  // namespace

class DiskManager {
  public:
    DiskManager() { _thread = std::thread(&DiskManager::_loop, this); }

    ~DiskManager() {
        {
            std::lock_guard lock{_mutex};
            _shutdown = true;
        }
        _cv.notify_one();
        if (_thread.joinable())
            _thread.join();
    }

    // Triggers a task. If a task with the same 'tag' is already pending,
    // it won't be added again (coalescing).
    void trigger(std::string_view tag_, std::function<void()> task) {
        {
            std::lock_guard lock{_mutex};

            if (_shutdown)
                return;

            if (_pending_tags.find(tag_) != _pending_tags.end())
                return;

            std::string tag{tag_};
            _pending_tags.insert(tag);
            _tasks.push_back({std::move(tag), std::move(task)});
        }
        _cv.notify_one();
    }

  private:
    std::thread _thread;
    std::mutex _mutex;
    std::condition_variable _cv;
    bool _shutdown = false;

    std::deque<TaskEntry> _tasks;
    std::unordered_set<std::string, string_hash, std::equal_to<>> _pending_tags;

    void _loop() {
        while (true) {
            TaskEntry current;
            {
                std::unique_lock lock{_mutex};
                _cv.wait(lock, [this] { return _shutdown || !_tasks.empty(); });

                if (_shutdown && _tasks.empty())
                    break;

                current = std::move(_tasks.front());
                _tasks.pop_front();
                _pending_tags.erase(current.tag);
            }

            try {
                current.task();
            } catch (const std::exception& e) {
                oxen::log::error(disk_cat, "Unhandled exception: {}", e.what());
            }
        }
    }
};

}  // namespace session::network
