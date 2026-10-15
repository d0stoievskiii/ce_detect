#pragma once

#include "IDetector.hpp"

#include <functional>
#include <string>
#include <unordered_map>
#include <vector>

class DriverDetector final : public IDetector
{
public:
    using DriverEnumerator =
        std::function<std::vector<std::wstring>()>;

    DriverDetector();

    explicit DriverDetector(
        DriverEnumerator enumerator
    );

    std::string name() const override;

    DetectionResult scan(
        const DetectionContext& context
    ) const override;

private:
    static std::vector<std::wstring>
        enumerateLoadedDrivers();

    static std::wstring toLower(
        std::wstring value
    );

    static std::string narrow(
        const std::wstring& value
    );

    DriverEnumerator enumerator_;

    const std::unordered_map<std::wstring, int>
        knownDrivers_
    {
        { L"dbk32.sys", 30 },
        { L"dbk64.sys", 30 }
    };

    static constexpr int MaxScore = 30;
};