#include "../../ce_detect/include/DetectionTypes.hpp"

#include <cassert>
#include <vector>

void runConfidenceLevelTests()
{
    struct TestCase
    {
        int score;
        ConfidenceLevel expected;
    };

    const std::vector<TestCase> cases
    {
        { 0,   ConfidenceLevel::NotDetected },
        { 1,   ConfidenceLevel::VeryLow },
        { 19,  ConfidenceLevel::VeryLow },
        { 20,  ConfidenceLevel::Low },
        { 39,  ConfidenceLevel::Low },
        { 40,  ConfidenceLevel::Medium },
        { 59,  ConfidenceLevel::Medium },
        { 60,  ConfidenceLevel::High },
        { 79,  ConfidenceLevel::High },
        { 80,  ConfidenceLevel::VeryHigh },
        { 100, ConfidenceLevel::VeryHigh }
    };

    for (const auto& test : cases)
    {
        assert(
            classifyConfidence(test.score) ==
            test.expected
        );
    }
}