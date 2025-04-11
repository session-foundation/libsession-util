#pragma once
#include <filesystem>
#include <iosfwd>
#include <string>
#include <string_view>

// Utility functions for working with files

namespace session {

namespace fs = std::filesystem;

/// Opens a file for writing of binary data, setting up the returned ofstream with exceptions
/// enabled for any failures.  This also throws if the file cannot be opened.  If the file already
/// exists it will be truncated.
std::ofstream open_for_writing(const fs::path& filename);

/// Opens a file for reading of binary data, setting up the returned ifstream with exceptions
/// enabled for any failures.  This also throws if the file cannot be opened.
std::ifstream open_for_reading(const fs::path& filename);

/// Reads a (binary) file from disk into the string `contents`.
std::string read_whole_file(const fs::path& filename);

/// Dumps (binary) string contents to disk. The file is overwritten if it already exists.
void write_whole_file(const fs::path& filename, std::string_view contents = "");

}  // namespace session
