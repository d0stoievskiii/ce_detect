#pragma once

#include "detectors/MemorySignatureDetector.hpp"

#include <cstdint>
#include <vector>

class MemoryPatternMatcher
{
public:
    static bool findPattern(
        const std::vector<std::uint8_t>& buffer,
        const MemorySignature& signature
    );

    static std::vector<std::size_t> findOccurrences(
        const std::vector<std::uint8_t>& buffer,
        const MemorySignature& signature
    );
};