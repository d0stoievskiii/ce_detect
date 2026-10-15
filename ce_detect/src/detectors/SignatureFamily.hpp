#pragma once

#include "detectors/MemoryTypes.hpp"

#include <cstddef>
#include <cstdint>
#include <string>
#include <vector>
#include <utility>

struct SignatureAnchor
{
    std::string name;
    std::vector<MemorySignature> signatures;
    std::size_t maxDistanceFromPrevious{};

    SignatureAnchor(
        std::string name,
        MemorySignature signature,
        std::size_t maxDistanceFromPrevious
    )
        : name(std::move(name)),
        signatures{
            std::move(signature)
        },
        maxDistanceFromPrevious(
            maxDistanceFromPrevious
        )
    {
    }

    SignatureAnchor(
        std::string name,
        std::vector<MemorySignature> signatures,
        std::size_t maxDistanceFromPrevious
    )
        : name(std::move(name)),
        signatures(
            std::move(signatures)
        ),
        maxDistanceFromPrevious(
            maxDistanceFromPrevious
        )
    {
    }
};

struct SignatureFamily
{
    std::string name;

    std::vector<SignatureAnchor> anchors;

    int score{};
};

struct AnchorMatch
{
    std::string anchorName;

    std::size_t offset{};

    std::uintptr_t address{};
};

struct SignatureFamilyMatch
{
    bool matched{ false };

    std::vector<AnchorMatch> anchors;
};