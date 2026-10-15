#pragma once

#include "IDetector.hpp"

#include <functional>
#include <string>
#include <vector>

struct WindowInfo
{
    std::wstring title;
    std::wstring className;
};

class WindowDetector final : public IDetector
{
public:
    using WindowEnumerator =
        std::function<std::vector<WindowInfo>(DWORD)>;

    WindowDetector();

    explicit WindowDetector(
        WindowEnumerator enumerator
    );

    std::string name() const override;

    DetectionResult scan(
        const DetectionContext& context
    ) const override;

private:
    static std::vector<WindowInfo>
        enumerateWindows(DWORD processId);

    static std::wstring toLower(
        std::wstring value
    );

    static std::string narrow(
        const std::wstring& value
    );

    static bool containsKnownTitle(
        const std::wstring& title
    );

    WindowEnumerator enumerator_;

    static constexpr int TitleMatchScore = 10;
    static constexpr int MaxScore = 10;
};