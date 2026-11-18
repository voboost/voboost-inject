#pragma once

#include <cstddef>
#include <cstdint>
#include <string_view>
#include <utility>
#include <vector>

inline bool strict_utf8_to_utf16(std::string_view input,
                                 std::vector<uint16_t> *output) {
    if (!output) {
        return false;
    }
    output->clear();
    std::vector<uint16_t> converted;
    for (size_t index = 0; index < input.size();) {
        uint8_t first = static_cast<uint8_t>(input[index]);
        uint32_t codepoint = 0;
        size_t length = 0;
        if (first <= 0x7f) {
            codepoint = first;
            length = 1;
        } else if (first >= 0xc2 && first <= 0xdf) {
            codepoint = first & 0x1f;
            length = 2;
        } else if (first >= 0xe0 && first <= 0xef) {
            codepoint = first & 0x0f;
            length = 3;
        } else if (first >= 0xf0 && first <= 0xf4) {
            codepoint = first & 0x07;
            length = 4;
        } else {
            return false;
        }
        if (length > input.size() - index) {
            return false;
        }
        for (size_t offset = 1; offset < length; offset++) {
            uint8_t continuation = static_cast<uint8_t>(input[index + offset]);
            if ((continuation & 0xc0) != 0x80) {
                return false;
            }
            codepoint = (codepoint << 6) | (continuation & 0x3f);
        }
        if ((length == 3 && codepoint < 0x800)
            || (length == 4 && codepoint < 0x10000)
            || (codepoint >= 0xd800 && codepoint <= 0xdfff)
            || codepoint > 0x10ffff) {
            return false;
        }
        if (codepoint < 0x10000) {
            converted.push_back(static_cast<uint16_t>(codepoint));
        } else {
            codepoint -= 0x10000;
            converted.push_back(static_cast<uint16_t>(0xd800 + (codepoint >> 10)));
            converted.push_back(static_cast<uint16_t>(0xdc00 + (codepoint & 0x3ff)));
        }
        index += length;
    }
    *output = std::move(converted);
    return true;
}
