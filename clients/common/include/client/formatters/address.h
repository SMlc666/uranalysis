#pragma once

#include <cstdint>
#include <string>

namespace client::fmt {

/// Format an address as hexadecimal (e.g., "0x1234")
std::string hex(std::uint64_t value);

/// Format an address with zero-padding to specified width
std::string hex_padded(std::uint64_t value, int width = 16);

/// Parse a uint64 from text (supports decimal and 0x prefix)
/// Returns true on success, false on failure
bool parse_u64(const std::string& text, std::uint64_t& out);

/// Convert string to lowercase
std::string to_lower(const std::string& input);

/// Check if text matches filter (case-insensitive substring match)
bool matches_filter(const std::string& filter, const std::string& text);

}  // namespace client::fmt