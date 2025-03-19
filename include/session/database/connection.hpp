#pragma once

#include <string>
#include <functional>
#include <memory>

struct sqlite3;
struct sqlite3_stmt;

namespace session::database {

class Connection {
private:
    sqlite3* db_{nullptr};
    std::string key_;

public:
    Connection(const std::string& path, const std::string& key);
    ~Connection();

    // Prevent copying
    Connection(const Connection&) = delete;
    Connection& operator=(const Connection&) = delete;
    
    // Allow moving
    Connection(Connection&& other) noexcept;
    Connection& operator=(Connection&& other) noexcept;

    sqlite3* handle() { return db_; }
    
    void exec(const std::string& sql);
    void query(const std::string& sql, std::function<void(sqlite3_stmt*)> callback);
};

} // namespace session::database