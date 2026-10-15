#include "../../ce_detect/src/detectors/SignatureFamilyMatcher.hpp"

#include <Windows.h>

#include <cassert>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace
{
    MemorySignature makeSignature(
        std::string name,
        std::vector<std::uint8_t> bytes
    )
    {
        const auto mask =
            std::string(bytes.size(), 'x');

        return MemorySignature
        {
            std::move(name),
            std::move(bytes),
            mask,
            0
        };
    }

    MemoryRegion makeRegion(
        std::uintptr_t baseAddress,
        std::vector<std::uint8_t> bytes,
        DWORD protection = PAGE_READONLY,
        DWORD type = MEM_IMAGE
    )
    {
        return MemoryRegion
        {
            baseAddress,
            protection,
            type,
            std::move(bytes)
        };
    }
}

void runSignatureFamilyMatcherTests()
{
    // Basic ordered family.
    {
        const auto region =
            makeRegion(
                0x100000,
                {
                    0xAA,
                    0x00,
                    0x00,
                    0xBB
                }
            );

        const SignatureFamily family
        {
            "Simple family",

            {
                {
                    "A",
                    makeSignature(
                        "A pattern",
                        { 0xAA }
                    ),
                    0
                },

                {
                    "B",
                    makeSignature(
                        "B pattern",
                        { 0xBB }
                    ),
                    3
                }
            },

            15
        };

        const auto result =
            SignatureFamilyMatcher::match(
                region,
                family
            );

        assert(result.matched);
        assert(result.anchors.size() == 2);

        assert(result.anchors[0].offset == 0);
        assert(result.anchors[1].offset == 3);

        assert(
            result.anchors[0].address ==
            0x100000
        );

        assert(
            result.anchors[1].address ==
            0x100003
        );
    }

    // Backtracking required.
    //
    // A at 0 cannot reach B.
    // A at 10 can reach B.
    {
        const auto region =
            makeRegion(
                0x200000,
                {
                    // A #1 at 0
                    0xAA,

                    0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00,

                    // A #2 at 10
                    0xAA,

                    0x00,
                    0x00,

                    // B at 13
                    0xBB
                }
            );

        const SignatureFamily family
        {
            "Backtracking family",

            {
                {
                    "A",
                    makeSignature(
                        "A",
                        { 0xAA }
                    ),
                    0
                },

                {
                    "B",
                    makeSignature(
                        "B",
                        { 0xBB }
                    ),
                    4
                }
            },

            15
        };

        const auto result =
            SignatureFamilyMatcher::match(
                region,
                family
            );

        assert(result.matched);
        assert(result.anchors.size() == 2);

        assert(result.anchors[0].offset == 10);
        assert(result.anchors[1].offset == 13);

        assert(
            result.anchors[0].address ==
            0x20000A
        );

        assert(
            result.anchors[1].address ==
            0x20000D
        );
    }

    // Wrong anchor order.
    {
        const auto region =
            makeRegion(
                0x300000,
                {
                    0xBB,
                    0x00,
                    0xAA
                }
            );

        const SignatureFamily family
        {
            "Wrong order",

            {
                {
                    "A",
                    makeSignature(
                        "A",
                        { 0xAA }
                    ),
                    0
                },

                {
                    "B",
                    makeSignature(
                        "B",
                        { 0xBB }
                    ),
                    10
                }
            },

            15
        };

        const auto result =
            SignatureFamilyMatcher::match(
                region,
                family
            );

        assert(!result.matched);
        assert(result.anchors.empty());
    }

    // Correct order, but distance too large.
    {
        const auto region =
            makeRegion(
                0x400000,
                {
                    0xAA,

                    0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00,

                    0xBB
                }
            );

        const SignatureFamily family
        {
            "Too far",

            {
                {
                    "A",
                    makeSignature(
                        "A",
                        { 0xAA }
                    ),
                    0
                },

                {
                    "B",
                    makeSignature(
                        "B",
                        { 0xBB }
                    ),
                    4
                }
            },

            15
        };

        const auto result =
            SignatureFamilyMatcher::match(
                region,
                family
            );

        assert(!result.matched);
    }

    // Three-anchor backtracking.
    {
        const auto region =
            makeRegion(
                0x500000,
                {
                    // First incomplete chain.
                    0xAA,       // 0
                    0x00,
                    0xBB,       // 2

                    0x00, 0x00, 0x00,
                    0x00, 0x00, 0x00,

                    // Valid chain.
                    0xAA,       // 9
                    0x00,
                    0xBB,       // 11
                    0x00,
                    0xCC        // 13
                }
            );

        const SignatureFamily family
        {
            "Three anchor family",

            {
                {
                    "A",
                    makeSignature(
                        "A",
                        { 0xAA }
                    ),
                    0
                },

                {
                    "B",
                    makeSignature(
                        "B",
                        { 0xBB }
                    ),
                    2
                },

                {
                    "C",
                    makeSignature(
                        "C",
                        { 0xCC }
                    ),
                    2
                }
            },

            15
        };

        const auto result =
            SignatureFamilyMatcher::match(
                region,
                family
            );

        assert(result.matched);
        assert(result.anchors.size() == 3);

        assert(result.anchors[0].offset == 9);
        assert(result.anchors[1].offset == 11);
        assert(result.anchors[2].offset == 13);
    }

    // Missing anchor.
    {
        const auto region =
            makeRegion(
                0x600000,
                {
                    0xAA,
                    0x00,
                    0x00
                }
            );

        const SignatureFamily family
        {
            "Missing B",

            {
                {
                    "A",
                    makeSignature(
                        "A",
                        { 0xAA }
                    ),
                    0
                },

                {
                    "B",
                    makeSignature(
                        "B",
                        { 0xBB }
                    ),
                    10
                }
            },

            15
        };

        const auto result =
            SignatureFamilyMatcher::match(
                region,
                family
            );

        assert(!result.matched);
    }

    // Empty family should not match.
    {
        const auto region =
            makeRegion(
                0x700000,
                { 0xAA }
            );

        const SignatureFamily family
        {
            "Empty family",
            {},
            15
        };

        const auto result =
            SignatureFamilyMatcher::match(
                region,
                family
            );

        assert(!result.matched);
    }
}