#include "../../ce_detect/src/detectors/MemorySignatureDetector.hpp"

#include <Windows.h>

#include <cassert>
#include <cstdint>
#include <string>
#include <utility>
#include <vector>

namespace
{
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

    MemorySignature makeSignature(
        std::string name,
        std::vector<std::uint8_t> bytes,
        int score
    )
    {
        const auto mask =
            std::string(bytes.size(), 'x');

        return MemorySignature
        {
            std::move(name),
            std::move(bytes),
            mask,
            score
        };
    }

    SignatureFamily makeTwoAnchorFamily(
        std::string name,
        int score,
        std::size_t maxDistance = 4
    )
    {
        return SignatureFamily
        {
            std::move(name),

            {
                {
                    "A",
                    makeSignature(
                        "A",
                        { 0xAA },
                        0
                    ),
                    0
                },

                {
                    "B",
                    makeSignature(
                        "B",
                        { 0xBB },
                        0
                    ),
                    maxDistance
                }
            },

            score
        };
    }
}

void runMemorySignatureDetectorTests()
{
    DetectionContext context;
    context.processId = 1234;

    // Standalone signature.
    {
        std::vector<MemorySignature> signatures
        {
            makeSignature(
                "Signature A",
                { 0xAA, 0xBB },
                10
            )
        };

        MemorySignatureDetector detector(
            signatures,
            {},
            [](DWORD)
            {
                return std::vector<MemoryRegion>
                {
                    makeRegion(
                        0x100000,
                        {
                            0x10,
                            0xAA,
                            0xBB,
                            0x20
                        }
                    )
                };
            }
        );

        const auto result =
            detector.scan(context);

        assert(result.detected);
        assert(result.score == 10);
        assert(result.evidence.size() == 1);
    }

    // Two standalone signatures accumulate.
    {
        std::vector<MemorySignature> signatures
        {
            makeSignature(
                "Signature A",
                { 0xAA },
                10
            ),

            makeSignature(
                "Signature B",
                { 0xBB },
                10
            )
        };

        MemorySignatureDetector detector(
            signatures,
            {},
            [](DWORD)
            {
                return std::vector<MemoryRegion>
                {
                    makeRegion(
                        0x200000,
                        {
                            0xAA,
                            0xBB
                        }
                    )
                };
            }
        );

        const auto result =
            detector.scan(context);

        assert(result.detected);
        assert(result.score == 20);
        assert(result.evidence.size() == 2);
    }

    // Same standalone signature in multiple regions counts once.
    {
        std::vector<MemorySignature> signatures
        {
            makeSignature(
                "Repeated signature",
                { 0xAA, 0xBB },
                10
            )
        };

        MemorySignatureDetector detector(
            signatures,
            {},
            [](DWORD)
            {
                return std::vector<MemoryRegion>
                {
                    makeRegion(
                        0x300000,
                        { 0xAA, 0xBB }
                    ),

                        makeRegion(
                            0x400000,
                            {
                                0x00,
                                0xAA,
                                0xBB
                            }
                        )
                };
            }
        );

        const auto result =
            detector.scan(context);

        assert(result.detected);
        assert(result.score == 10);
        assert(result.evidence.size() == 1);
    }

    // Family-only match.
    {
        const auto family =
            makeTwoAnchorFamily(
                "Test family",
                15
            );

        MemorySignatureDetector detector(
            {},
            { family },
            [](DWORD)
            {
                return std::vector<MemoryRegion>
                {
                    makeRegion(
                        0x500000,
                        {
                            0xAA,
                            0x00,
                            0x00,
                            0xBB
                        }
                    )
                };
            }
        );

        const auto result =
            detector.scan(context);

        assert(result.detected);
        assert(result.score == 15);
        assert(result.evidence.size() == 1);
    }

    // Family should fail if anchors are too far apart.
    {
        const auto family =
            makeTwoAnchorFamily(
                "Distance family",
                15,
                2
            );

        MemorySignatureDetector detector(
            {},
            { family },
            [](DWORD)
            {
                return std::vector<MemoryRegion>
                {
                    makeRegion(
                        0x600000,
                        {
                            0xAA,
                            0x00,
                            0x00,
                            0x00,
                            0xBB
                        }
                    )
                };
            }
        );

        const auto result =
            detector.scan(context);

        assert(!result.detected);
        assert(result.score == 0);
        assert(result.evidence.empty());
    }

    // Same family in several regions counts once.
    {
        const auto family =
            makeTwoAnchorFamily(
                "Repeated family",
                15
            );

        MemorySignatureDetector detector(
            {},
            { family },
            [](DWORD)
            {
                return std::vector<MemoryRegion>
                {
                    makeRegion(
                        0x700000,
                        {
                            0xAA,
                            0x00,
                            0xBB
                        }
                    ),

                        makeRegion(
                            0x800000,
                            {
                                0xAA,
                                0x00,
                                0xBB
                            }
                        )
                };
            }
        );

        const auto result =
            detector.scan(context);

        assert(result.detected);
        assert(result.score == 15);
        assert(result.evidence.size() == 1);
    }

    // Standalone + family accumulate.
    {
        std::vector<MemorySignature> signatures
        {
            makeSignature(
                "Standalone",
                { 0x11, 0x22 },
                10
            )
        };

        const auto family =
            makeTwoAnchorFamily(
                "Family",
                15
            );

        MemorySignatureDetector detector(
            signatures,
            { family },
            [](DWORD)
            {
                return std::vector<MemoryRegion>
                {
                    makeRegion(
                        0x900000,
                        {
                            0x11,
                            0x22,

                            0xAA,
                            0x00,
                            0xBB
                        }
                    )
                };
            }
        );

        const auto result =
            detector.scan(context);

        assert(result.detected);
        assert(result.score == 25);
        assert(result.evidence.size() == 2);
    }

    // Standalone + family raw score over cap.
    {
        std::vector<MemorySignature> signatures
        {
            makeSignature(
                "Standalone",
                { 0x11 },
                20
            )
        };

        const auto family =
            makeTwoAnchorFamily(
                "Strong family",
                20
            );

        MemorySignatureDetector detector(
            signatures,
            { family },
            [](DWORD)
            {
                return std::vector<MemoryRegion>
                {
                    makeRegion(
                        0xA00000,
                        {
                            0x11,

                            0xAA,
                            0x00,
                            0xBB
                        }
                    )
                };
            }
        );

        const auto result =
            detector.scan(context);

        // Raw score = 40.
        // Detector cap = 30.
        assert(result.detected);
        assert(result.score == 30);

        // Evidence remains complete.
        assert(result.evidence.size() == 2);
    }

    // No match.
    {
        std::vector<MemorySignature> signatures
        {
            makeSignature(
                "Signature A",
                { 0xAA, 0xBB },
                10
            )
        };

        const auto family =
            makeTwoAnchorFamily(
                "Family",
                15
            );

        MemorySignatureDetector detector(
            signatures,
            { family },
            [](DWORD)
            {
                return std::vector<MemoryRegion>
                {
                    makeRegion(
                        0xB00000,
                        {
                            0x10,
                            0x20,
                            0x30
                        }
                    )
                };
            }
        );

        const auto result =
            detector.scan(context);

        assert(!result.detected);
        assert(result.score == 0);
        assert(result.evidence.empty());
    }

    // Empty memory-reader result.
    {
        MemorySignatureDetector detector(
            {
                makeSignature(
                    "Signature",
                    { 0xAA },
                    10
                )
            },
            {
                makeTwoAnchorFamily(
                    "Family",
                    15
                )
            },
            [](DWORD)
            {
                return std::vector<MemoryRegion>{};
            }
        );

        const auto result =
            detector.scan(context);

        assert(!result.detected);
        assert(result.score == 0);
        assert(result.evidence.empty());
    }

    // Region metadata currently does not filter matching.
    //
    // The injected reader may return MEM_PRIVATE,
    // and scan() still checks its bytes.
    {
        std::vector<MemorySignature> signatures
        {
            makeSignature(
                "Private-memory signature",
                { 0xAA },
                10
            )
        };

        MemorySignatureDetector detector(
            signatures,
            {},
            [](DWORD)
            {
                return std::vector<MemoryRegion>
                {
                    makeRegion(
                        0xC00000,
                        { 0xAA },
                        PAGE_READWRITE,
                        MEM_PRIVATE
                    )
                };
            }
        );

        const auto result =
            detector.scan(context);

        assert(result.detected);
        assert(result.score == 10);
    }
}