#include "../../ce_detect/src/detectors/MemorySignatureDefinitions.hpp"
#include "../../ce_detect/src/detectors/SignatureFamilyMatcher.hpp"

#include "fixtures/FirstScan74.hpp"
#include "fixtures/FirstScan75.hpp"
#include "../../ce_detect/include/HexFixture.hpp"

#include <Windows.h>

#include <algorithm>
#include <cassert>
#include <cstdint>
#include <string_view>
#include <vector>

namespace
{
    constexpr std::size_t FirstStateImmediateOffset = 10;
    constexpr std::size_t CallOpcodeOffset = 30;
    constexpr std::size_t SecondStateImmediateOffset = 45;
    MemoryRegion makeCodeRegion(
        std::uintptr_t baseAddress,
        std::vector<std::uint8_t> bytes
    )
    {
        return MemoryRegion
        {
            baseAddress,
            PAGE_EXECUTE_READ,
            MEM_IMAGE,
            std::move(bytes)
        };
    }

    const AnchorMatch* findAnchor(
        const SignatureFamilyMatch& match,
        std::string_view name
    )
    {
        const auto iterator =
            std::find_if(
                match.anchors.begin(),
                match.anchors.end(),
                [name](const AnchorMatch& anchor)
                {
                    return anchor.anchorName ==
                        name;
                }
            );

        if (iterator == match.anchors.end())
        {
            return nullptr;
        }

        return &*iterator;
    }

    void assertStateTransition(
        const MemoryRegion& region,
        const AnchorMatch& anchor
    )
    {
        const std::size_t offset =
            anchor.offset;

        constexpr std::size_t AnchorSize = 49;

        assert(
            offset + AnchorSize <=
            region.bytes.size()
        );

        // mov rax,[rbp+this]
        assert(region.bytes[offset + 0] == 0x48);
        assert(region.bytes[offset + 1] == 0x8B);
        assert(region.bytes[offset + 2] == 0x45);
        assert(region.bytes[offset + 3] == 0xF8);

        // mov dword ptr [rax+284h], imm32
        assert(region.bytes[offset + 4] == 0xC7);
        assert(region.bytes[offset + 5] == 0x80);

        // displacement = 0x284
        assert(region.bytes[offset + 6] == 0x84);
        assert(region.bytes[offset + 7] == 0x02);
        assert(region.bytes[offset + 8] == 0x00);
        assert(region.bytes[offset + 9] == 0x00);

        // state = 0x3FD
        assert(region.bytes[offset + 10] == 0xFD);
        assert(region.bytes[offset + 11] == 0x03);
        assert(region.bytes[offset + 12] == 0x00);
        assert(region.bytes[offset + 13] == 0x00);

        // Argument setup.
        assert(region.bytes[offset + 14] == 0x44);
        assert(region.bytes[offset + 18] == 0x4C);
        assert(region.bytes[offset + 22] == 0x48);
        assert(region.bytes[offset + 26] == 0x48);

        // CALL rel32.
        assert(
            region.bytes[
                offset + CallOpcodeOffset
            ] == 0xE8
        );

        /*
         * Bytes 31..34 are intentionally ignored.
         *
         * They encode the relative target and therefore
         * change when binary layout changes.
         */

         // mov rax,[rbp+this]
        assert(region.bytes[offset + 35] == 0x48);
        assert(region.bytes[offset + 36] == 0x8B);
        assert(region.bytes[offset + 37] == 0x45);
        assert(region.bytes[offset + 38] == 0xF8);

        // mov dword ptr [rax+284h], imm32
        assert(region.bytes[offset + 39] == 0xC7);
        assert(region.bytes[offset + 40] == 0x80);

        // displacement = 0x284
        assert(region.bytes[offset + 41] == 0x84);
        assert(region.bytes[offset + 42] == 0x02);
        assert(region.bytes[offset + 43] == 0x00);
        assert(region.bytes[offset + 44] == 0x00);

        // state = 0x3FE
        assert(region.bytes[offset + 45] == 0xFE);
        assert(region.bytes[offset + 46] == 0x03);
        assert(region.bytes[offset + 47] == 0x00);
        assert(region.bytes[offset + 48] == 0x00);
    }
}

void testFirstScan74Regression()
{
    const auto region =
        makeCodeRegion(
            0x00543C20,
            parseHex(
                RegressionFixtures::FirstScan74
            )
        );

    const auto family =
        MemorySignatureDefinitions::
        makeFirstScanFamily();

    const auto result =
        SignatureFamilyMatcher::match(
            region,
            family
        );

    assert(result.matched);

    assert(
        result.anchors.size() ==
        family.anchors.size()
    );

    const auto* transition =
        findAnchor(
            result,
            "Scanner phase 0x3FD -> 0x3FE"
        );

    assert(transition != nullptr);

    assertStateTransition(
        region,
        *transition
    );
}

void testFirstScan75Regression()
{
    const auto region =
        makeCodeRegion(
            0x00559680,
            parseHex(
                RegressionFixtures::FirstScan75
            )
        );

    const auto family =
        MemorySignatureDefinitions::
        makeFirstScanFamily();

    const auto result =
        SignatureFamilyMatcher::match(
            region,
            family
        );

    assert(result.matched);

    assert(
        result.anchors.size() ==
        family.anchors.size()
    );

    const auto* transition =
        findAnchor(
            result,
            "Scanner phase 0x3FD -> 0x3FE"
        );

    assert(transition != nullptr);

    assertStateTransition(
        region,
        *transition
    );
}

void testFirstScanBrokenStateTransitionFails()
{
    auto bytes =
        parseHex(
            RegressionFixtures::FirstScan75
        );

    /*
     * Locate the exact late transition pattern:
     *
     *   [this + 0x284] = 0x3FD
     *   ...
     *   E8 <rel32>
     *   ...
     *   [this + 0x284] = 0x3FE
     *
     * We deliberately search for the stable prefix of that
     * transition instead of hard-coding an absolute fixture offset.
     */
    const MemorySignature transitionPrefix
    {
        "Transition prefix",

        {
            0x48, 0x8B, 0x45, 0xF8,

            0xC7, 0x80,
            0x84, 0x02, 0x00, 0x00,

            0xFD, 0x03, 0x00, 0x00,

            0x44, 0x8B, 0x4D, 0xC8,
            0x4C, 0x8B, 0x45, 0xB8,
            0x48, 0x8B, 0x55, 0xE0,
            0x48, 0x8B, 0x4D, 0xF8,

            0xE8
        },

        std::string(31, 'x'),

        0
    };

    const auto occurrences =
        MemoryPatternMatcher::findOccurrences(
            bytes,
            transitionPrefix
        );

    /*
     * This fixture is expected to contain exactly one
     * FirstScan 0x3FD transition.
     */
    assert(occurrences.size() == 1);

    const std::size_t transitionOffset =
        occurrences[0];

    constexpr std::size_t SecondStateImmediateOffset =
        45;

    /*
     * Sanity check the unmodified fixture before corrupting it.
     *
     * FE 03 00 00 == 0x3FE.
     */
    assert(
        bytes[
            transitionOffset +
                SecondStateImmediateOffset
        ] == 0xFE
    );

    assert(
        bytes[
            transitionOffset +
                SecondStateImmediateOffset + 1
        ] == 0x03
    );

    /*
     * Break the transition:
     *
     *     0x3FD -> call -> 0x3FE
     *
     * becomes:
     *
     *     0x3FD -> call -> 0x3FF
     *
     * Everything else in FirstScan remains untouched.
     */
    bytes[
        transitionOffset +
            SecondStateImmediateOffset
    ] = 0xFF;

    const auto region =
        makeCodeRegion(
            0x00559680,
            std::move(bytes)
        );

    const auto family =
        MemorySignatureDefinitions::
        makeFirstScanFamily();

    const auto result =
        SignatureFamilyMatcher::match(
            region,
            family
        );

    /*
     * All earlier FirstScan anchors are still present,
     * but the required final transition has been broken.
     *
     * Therefore the complete family must not match.
     */
    assert(!result.matched);
    assert(result.anchors.empty());
}

void runFirstScanSignatureRegressionTests()
{
    testFirstScan74Regression();
    testFirstScan75Regression();

    testFirstScanBrokenStateTransitionFails();
}