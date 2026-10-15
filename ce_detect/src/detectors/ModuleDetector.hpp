#pragma once

#include "IDetector.hpp"

#include <functional>
#include <string>
#include <unordered_map>
#include <vector>

class ModuleDetector final : public IDetector
{
public:
    using ModuleEnumerator =
        std::function<std::vector<std::wstring>(DWORD)>;

    ModuleDetector();

    explicit ModuleDetector(
        ModuleEnumerator enumerator
    );

    std::string name() const override;

    DetectionResult scan(
        const DetectionContext& context
    ) const override;

private:
    static std::vector<std::wstring>
    enumerateModules(DWORD processId);

    static std::wstring toLower(
        std::wstring value
    );

    static std::string narrow(
        const std::wstring& value
    );

    ModuleEnumerator enumerator_;

    const std::unordered_map<std::wstring, int>
        knownModules_
    {
        { L"ced3d9hook64.dll",  15 },
        { L"ced3d10hook64.dll", 15 },
        { L"ced3d11hook64.dll", 15 }
    };

    static constexpr int MaxScore = 30;
};