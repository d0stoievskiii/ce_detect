#pragma once

#include <Windows.h>

#include <filesystem>
#include <string>
#include <vector>

enum class ConfidenceLevel
{
    NotDetected,
    VeryLow,
    Low,
    Medium,
    High,
    VeryHigh
};

struct DetectionContext
{
    DWORD processId{};
    std::wstring processName;
    std::filesystem::path executablePath;
};

struct DetectionResult
{
    std::string detectorName;
    bool detected{ false };
    int score{ 0 };

    std::vector<std::string> evidence;
};

struct DetectionReport
{
    DWORD processId{};
    std::wstring processName;

    int totalScore{ 0 };
    ConfidenceLevel confidence{ ConfidenceLevel::NotDetected };

    std::vector<DetectionResult> results;
};

inline std::string toString(ConfidenceLevel level)
{
    switch (level)
    {
    case ConfidenceLevel::NotDetected:
        return "NOT DETECTED";

    case ConfidenceLevel::VeryLow:
        return "VERY LOW";

    case ConfidenceLevel::Low:
        return "LOW";

    case ConfidenceLevel::Medium:
        return "MEDIUM";

    case ConfidenceLevel::High:
        return "HIGH";

    case ConfidenceLevel::VeryHigh:
        return "VERY HIGH";
    }

    return "UNKNOWN";
}

inline ConfidenceLevel classifyConfidence(int score)
{
    if (score >= 80)
    {
        return ConfidenceLevel::VeryHigh;
    }

    if (score >= 60)
    {
        return ConfidenceLevel::High;
    }

    if (score >= 40)
    {
        return ConfidenceLevel::Medium;
    }

    if (score >= 20)
    {
        return ConfidenceLevel::Low;
    }

    if (score > 0)
    {
        return ConfidenceLevel::VeryLow;
    }

    return ConfidenceLevel::NotDetected;
}