#include "MemoryPatternMatcher.hpp"

#include <cstddef>

std::vector<std::size_t>
MemoryPatternMatcher::findOccurrences(
    const std::vector<std::uint8_t>& buffer,
    const MemorySignature& signature
)
{
    std::vector<std::size_t> occurrences;

    if (signature.bytes.empty())
    {
        return occurrences;
    }

    if (signature.bytes.size() != signature.mask.size())
    {
        return occurrences;
    }

    if (buffer.size() < signature.bytes.size())
    {
        return occurrences;
    }

    const std::size_t lastStart =
        buffer.size() - signature.bytes.size();

    for (std::size_t start = 0;
        start <= lastStart;
        ++start)
    {
        bool matches = true;

        for (std::size_t i = 0;
            i < signature.bytes.size();
            ++i)
        {
            if (signature.mask[i] == '?')
            {
                continue;
            }

            if (signature.mask[i] != 'x')
            {
                matches = false;
                break;
            }

            if (buffer[start + i] !=
                signature.bytes[i])
            {
                matches = false;
                break;
            }
        }

        if (matches)
        {
            occurrences.push_back(start);
        }
    }

    return occurrences;
}

bool MemoryPatternMatcher::findPattern(
    const std::vector<std::uint8_t>& buffer,
    const MemorySignature& signature
)
{
    return !findOccurrences(
        buffer,
        signature
    ).empty();
}