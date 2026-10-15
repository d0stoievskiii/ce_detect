#include "../../ce_detect/src/detectors/MemoryPatternMatcher.hpp"

#include <cassert>
#include <vector>

void runMemoryPatternMatcherTests()
{
    // Exact match.
    {
        const std::vector<std::uint8_t> buffer
        {
            0x10, 0x20, 0x30, 0x40
        };

        const MemorySignature signature
        {
            "Exact",
            { 0x20, 0x30 },
            "xx",
            10
        };

        const auto occurrences =
            MemoryPatternMatcher::findOccurrences(
                buffer,
                signature
            );

        assert(occurrences.size() == 1);
        assert(occurrences[0] == 1);

        assert(
            MemoryPatternMatcher::findPattern(
                buffer,
                signature
            )
        );
    }

    // Wildcard.
    {
        const std::vector<std::uint8_t> buffer
        {
            0xAA, 0xBB, 0xCC
        };

        const MemorySignature signature
        {
            "Wildcard",
            { 0xAA, 0x00, 0xCC },
            "x?x",
            10
        };

        assert(
            MemoryPatternMatcher::findPattern(
                buffer,
                signature
            )
        );
    }

    // Mismatch.
    {
        const std::vector<std::uint8_t> buffer
        {
            0xAA, 0xBB, 0xCC
        };

        const MemorySignature signature
        {
            "Mismatch",
            { 0xAA, 0x99, 0xCC },
            "xxx",
            10
        };

        assert(
            !MemoryPatternMatcher::findPattern(
                buffer,
                signature
            )
        );
    }

    // Multiple occurrences.
    {
        const std::vector<std::uint8_t> buffer
        {
            0xAA, 0xBB,
            0x00,
            0xAA, 0xBB
        };

        const MemorySignature signature
        {
            "Repeated",
            { 0xAA, 0xBB },
            "xx",
            10
        };

        const auto occurrences =
            MemoryPatternMatcher::findOccurrences(
                buffer,
                signature
            );

        assert(occurrences.size() == 2);
        assert(occurrences[0] == 0);
        assert(occurrences[1] == 3);
    }

    // Overlapping matches.
    {
        const std::vector<std::uint8_t> buffer
        {
            0xAA, 0xAA, 0xAA
        };

        const MemorySignature signature
        {
            "Overlap",
            { 0xAA, 0xAA },
            "xx",
            10
        };

        const auto occurrences =
            MemoryPatternMatcher::findOccurrences(
                buffer,
                signature
            );

        assert(occurrences.size() == 2);
        assert(occurrences[0] == 0);
        assert(occurrences[1] == 1);
    }

    // Empty pattern.
    {
        const MemorySignature signature
        {
            "Empty",
            {},
            "",
            10
        };

        assert(
            MemoryPatternMatcher::findOccurrences(
                { 0xAA },
                signature
            ).empty()
        );
    }

    // Mask length mismatch.
    {
        const MemorySignature signature
        {
            "Bad mask",
            { 0xAA, 0xBB },
            "x",
            10
        };

        assert(
            MemoryPatternMatcher::findOccurrences(
                { 0xAA, 0xBB },
                signature
            ).empty()
        );
    }

    // Invalid mask character.
    {
        const MemorySignature signature
        {
            "Invalid mask",
            { 0xAA, 0xBB },
            "x*",
            10
        };

        assert(
            MemoryPatternMatcher::findOccurrences(
                { 0xAA, 0xBB },
                signature
            ).empty()
        );
    }
}