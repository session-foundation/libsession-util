#include <fstream>
#include <session/file.hpp>

namespace session {

std::ofstream open_for_writing(const fs::path& filename) {
    std::ofstream out;
    out.exceptions(std::ios_base::failbit | std::ios_base::badbit);
    out.open(filename, std::ios_base::binary | std::ios_base::out | std::ios_base::trunc);
    out.exceptions(std::ios_base::badbit);
    return out;
}

std::ifstream open_for_reading(const fs::path& filename) {
    std::ifstream in;
    in.exceptions(std::ios_base::failbit | std::ios_base::badbit);
    in.open(filename, std::ios::binary | std::ios::in);
    in.exceptions(std::ios_base::badbit);
    return in;
}

std::vector<std::byte> read_whole_file(const fs::path& filename) {
    auto in = open_for_reading(filename);
    in.seekg(0, std::ios::end);
    auto size = in.tellg();
    in.seekg(0, std::ios::beg);

    if (size <= 0)
        return {};

    std::vector<std::byte> contents(static_cast<size_t>(size));
    if (!in.read(reinterpret_cast<char*>(contents.data()), size))
        return {};

    return contents;
}

void write_whole_file(const fs::path& filename, std::string_view contents) {
    auto out = open_for_writing(filename);
    out.write(contents.data(), static_cast<std::streamsize>(contents.size()));
}

}  // namespace session
