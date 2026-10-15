#pragma once

#include "IDetector.hpp"

#include <string>
#include <vector>

class ProcessNameDetector final : public IDetector
{
public:
    std::string name() const override;

    DetectionResult scan(
        const DetectionContext& context
    ) const override;

private:
    static std::wstring toLower(
        std::wstring value
    );

    const std::vector<std::wstring> knownProcessNames_
    {
        L"cheatengine.exe",
        L"cheatengine-x86_64.exe",
        L"cheatengine-i386.exe"
    };

    static constexpr int MatchScore = 10;
};