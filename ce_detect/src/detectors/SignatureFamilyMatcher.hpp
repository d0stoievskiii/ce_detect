#pragma once

#include "SignatureFamily.hpp"

#include <cstddef>
#include <vector>

class SignatureFamilyMatcher
{
public:
    static SignatureFamilyMatch match(
        const MemoryRegion& region,
        const SignatureFamily& family
    );

private:
    struct SignatureOccurrence
    {
        std::size_t offset{};
        std::size_t length{};
    };

    static bool matchRecursive(
        const MemoryRegion& region,
        const SignatureFamily& family,
        const std::vector<
        std::vector<SignatureOccurrence>
        >& occurrences,
        std::size_t anchorIndex,
        std::size_t previousOffset,
        std::size_t previousLength,
        bool hasPrevious,
        std::vector<AnchorMatch>& currentMatches
    );
};