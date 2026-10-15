#include "SignatureFamilyMatcher.hpp"

#include "MemoryPatternMatcher.hpp"

#include <algorithm>

SignatureFamilyMatch SignatureFamilyMatcher::match(
    const MemoryRegion& region,
    const SignatureFamily& family
)
{
    SignatureFamilyMatch result;

    if (family.anchors.empty())
    {
        return result;
    }

    /*
     * Find every possible occurrence for every semantic anchor.
     *
     * An anchor may contain multiple alternative signatures
     * representing different CE/compiler versions.
     *
     * We also retain the size of the specific alternative that
     * matched because maxDistanceFromPrevious is measured from
     * the END of the previous match.
     */
    std::vector<
        std::vector<SignatureOccurrence>
    > occurrences;

    occurrences.reserve(
        family.anchors.size()
    );

    for (const auto& anchor : family.anchors)
    {
        std::vector<SignatureOccurrence>
            anchorOccurrences;

        /*
         * Any alternative may satisfy this semantic anchor.
         */
        for (const auto& alternative :
            anchor.signatures)
        {
            const auto matches =
                MemoryPatternMatcher::findOccurrences(
                    region.bytes,
                    alternative
                );

            for (const std::size_t offset : matches)
            {
                anchorOccurrences.push_back(
                    {
                        offset,
                        alternative.bytes.size()
                    }
                );
            }
        }

        /*
         * If no alternative for this required anchor occurs,
         * the whole family cannot match.
         */
        if (anchorOccurrences.empty())
        {
            return result;
        }

        /*
         * Backtracking works best when occurrences are ordered
         * by their location in memory.
         *
         * If two alternatives match at the same offset, prefer
         * the longer one first. It represents the more specific
         * match and gives us the correct previousEnd.
         */
        std::sort(
            anchorOccurrences.begin(),
            anchorOccurrences.end(),
            [](
                const SignatureOccurrence& lhs,
                const SignatureOccurrence& rhs
                )
            {
                if (lhs.offset != rhs.offset)
                {
                    return lhs.offset <
                        rhs.offset;
                }

                return lhs.length >
                    rhs.length;
            }
        );

        /*
         * Remove exact duplicates.
         *
         * Do NOT deduplicate only by offset, because two
         * alternatives may begin at the same offset but have
         * different lengths. The length matters when computing
         * the next anchor's distance.
         */
        anchorOccurrences.erase(
            std::unique(
                anchorOccurrences.begin(),
                anchorOccurrences.end(),
                [](
                    const SignatureOccurrence& lhs,
                    const SignatureOccurrence& rhs
                    )
                {
                    return
                        lhs.offset == rhs.offset &&
                        lhs.length == rhs.length;
                }
            ),
            anchorOccurrences.end()
        );

        occurrences.push_back(
            std::move(anchorOccurrences)
        );
    }

    std::vector<AnchorMatch> currentMatches;

    const bool matched =
        matchRecursive(
            region,
            family,
            occurrences,
            0,
            0,
            0,
            false,
            currentMatches
        );

    if (!matched)
    {
        return result;
    }

    result.matched = true;
    result.anchors =
        std::move(currentMatches);

    return result;
}

bool SignatureFamilyMatcher::matchRecursive(
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
)
{
    /*
     * Base case:
     *
     * Every semantic anchor has been successfully matched.
     */
    if (anchorIndex >= family.anchors.size())
    {
        return true;
    }

    const auto& anchor =
        family.anchors[anchorIndex];

    const auto& anchorOccurrences =
        occurrences[anchorIndex];

    for (const auto& occurrence :
        anchorOccurrences)
    {
        if (hasPrevious)
        {
            const std::size_t previousEnd =
                previousOffset +
                previousLength;

            /*
             * Current anchor must begin after the previous
             * matched alternative ends.
             */
            if (occurrence.offset < previousEnd)
            {
                continue;
            }

            const std::size_t distance =
                occurrence.offset -
                previousEnd;

            /*
             * Current semantic anchor is too far away from
             * the previous one.
             */
            if (distance >
                anchor.maxDistanceFromPrevious)
            {
                continue;
            }
        }

        /*
         * This occurrence is locally valid.
         *
         * Add it to the tentative family chain.
         */
        currentMatches.push_back(
            {
                anchor.name,
                occurrence.offset,
                region.baseAddress +
                    occurrence.offset
            }
        );

        /*
         * Continue using the length of the actual signature
         * alternative that matched.
         */
        const bool matchedRest =
            matchRecursive(
                region,
                family,
                occurrences,
                anchorIndex + 1,
                occurrence.offset,
                occurrence.length,
                true,
                currentMatches
            );

        if (matchedRest)
        {
            return true;
        }

        /*
         * Dead end.
         *
         * Remove this occurrence and try another possible
         * alternative/occurrence for the same anchor.
         */
        currentMatches.pop_back();
    }

    return false;
}