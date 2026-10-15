#pragma once

#include <cctype>
#include <cstdint>
#include <stdexcept>
#include <string_view>
#include <vector>

inline std::vector<std::uint8_t>
parseHex(std::string_view text)
{
    std::vector<std::uint8_t> bytes;

    int highNibble = -1;

    for (const char character : text)
    {
        if (std::isspace(
            static_cast<unsigned char>(
                character
                )))
        {
            continue;
        }

        int value = -1;

        if (character >= '0' &&
            character <= '9')
        {
            value = character - '0';
        }
        else if (character >= 'A' &&
            character <= 'F')
        {
            value =
                character - 'A' + 10;
        }
        else if (character >= 'a' &&
            character <= 'f')
        {
            value =
                character - 'a' + 10;
        }
        else
        {
            throw std::runtime_error(
                "Invalid character in hex fixture"
            );
        }

        if (highNibble < 0)
        {
            highNibble = value;
        }
        else
        {
            bytes.push_back(
                static_cast<std::uint8_t>(
                    (highNibble << 4) |
                    value
                    )
            );

            highNibble = -1;
        }
    }

    if (highNibble >= 0)
    {
        throw std::runtime_error(
            "Hex fixture contains an odd number of digits"
        );
    }

    return bytes;
}