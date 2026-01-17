#pragma once

#include <cstdint>
#include <optional>
#include <string>

#include "client/session.h"

namespace client::util {

/**
 * @brief Result of resolving an address input.
 * 
 * Supports:
 * - Hex: 0x1234, 0X1234
 * - Decimal: 1234
 * - Symbol: main, _start, MyClass::method
 * - Current cursor: . or $
 * - Relative: +0x10, -0x20, .+0x10
 */
struct AddressResult {
    bool success = false;
    uint64_t address = 0;
    std::string error;
    std::string resolved_name;  // If resolved from symbol, the name
};

/**
 * @brief Resolve an address string to a numeric address.
 * 
 * @param input The address string (hex, decimal, symbol, or special)
 * @param session The current session (for symbol lookup and cursor)
 * @return AddressResult with success/failure and resolved address
 */
AddressResult resolve_address(const std::string& input, const Session& session);

/**
 * @brief Parse a numeric value (hex or decimal) without symbol lookup.
 */
bool parse_number(const std::string& input, uint64_t& out);

/**
 * @brief Try to find a symbol by name and return its address.
 */
std::optional<uint64_t> lookup_symbol(const std::string& name, const Session& session);

} // namespace client::util
