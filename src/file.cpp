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

std::string read_whole_file(const fs::path& filename) {
    auto in = open_for_reading(filename);
    std::string contents;
    in.seekg(0, std::ios::end);
    auto size = in.tellg();
    in.seekg(0, std::ios::beg);
    contents.resize(size);
    in.read(contents.data(), size);
    return contents;
}

void write_whole_file(const fs::path& filename, std::string_view contents) {
    auto out = open_for_writing(filename);
    out.write(contents.data(), static_cast<std::streamsize>(contents.size()));
}

}  // namespace session
