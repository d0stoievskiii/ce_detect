#include "detectors/WindowDetector.hpp"

#include <Windows.h>

#include <algorithm>
#include <cwctype>
#include <utility>

namespace
{
    struct EnumWindowsData
    {
        DWORD processId;
        std::vector<WindowInfo>* windows;
    };

    BOOL CALLBACK enumWindowsCallback(
        HWND hwnd,
        LPARAM lParam
    )
    {
        auto* data =
            reinterpret_cast<EnumWindowsData*>(lParam);

        DWORD windowProcessId = 0;

        GetWindowThreadProcessId(
            hwnd,
            &windowProcessId
        );

        if (windowProcessId != data->processId)
        {
            return TRUE;
        }

        const int titleLength =
            GetWindowTextLengthW(hwnd);

        std::wstring title;

        if (titleLength > 0)
        {
            title.resize(
                static_cast<std::size_t>(
                    titleLength + 1
                    )
            );

            const int copied =
                GetWindowTextW(
                    hwnd,
                    title.data(),
                    titleLength + 1
                );

            if (copied > 0)
            {
                title.resize(
                    static_cast<std::size_t>(
                        copied
                        )
                );
            }
            else
            {
                title.clear();
            }
        }

        wchar_t classBuffer[256]{};

        const int classLength =
            GetClassNameW(
                hwnd,
                classBuffer,
                static_cast<int>(
                    std::size(classBuffer)
                    )
            );

        std::wstring className;

        if (classLength > 0)
        {
            className.assign(
                classBuffer,
                static_cast<std::size_t>(
                    classLength
                    )
            );
        }

        data->windows->push_back(
            {
                std::move(title),
                std::move(className)
            }
        );

        return TRUE;
    }
}

WindowDetector::WindowDetector()
    : enumerator_(enumerateWindows)
{
}

WindowDetector::WindowDetector(
    WindowEnumerator enumerator
)
    : enumerator_(std::move(enumerator))
{
}

std::string WindowDetector::name() const
{
    return "Window Detector";
}

DetectionResult WindowDetector::scan(
    const DetectionContext& context
) const
{
    DetectionResult result;
    result.detectorName = name();

    const auto windows =
        enumerator_(context.processId);

    int totalScore = 0;

    for (const auto& window : windows)
    {
        if (!containsKnownTitle(window.title))
        {
            continue;
        }

        totalScore += TitleMatchScore;

        result.evidence.push_back(
            "Known Cheat Engine window title detected: "
            + narrow(window.title)
            + " (+"
            + std::to_string(TitleMatchScore)
            + ")"
        );
    }

    if (totalScore > 0)
    {
        result.detected = true;
        result.score =
            min(
                totalScore,
                MaxScore
            );
    }

    return result;
}

std::vector<WindowInfo>
WindowDetector::enumerateWindows(
    DWORD processId
)
{
    std::vector<WindowInfo> windows;

    EnumWindowsData data
    {
        processId,
        &windows
    };

    EnumWindows(
        enumWindowsCallback,
        reinterpret_cast<LPARAM>(&data)
    );

    return windows;
}

std::wstring WindowDetector::toLower(
    std::wstring value
)
{
    std::transform(
        value.begin(),
        value.end(),
        value.begin(),
        [](wchar_t character)
        {
            return static_cast<wchar_t>(
                std::towlower(character)
                );
        }
    );

    return value;
}

std::string WindowDetector::narrow(
    const std::wstring& value
)
{
    return std::string(
        value.begin(),
        value.end()
    );
}

bool WindowDetector::containsKnownTitle(
    const std::wstring& title
)
{
    if (title.empty())
    {
        return false;
    }

    const std::wstring normalized =
        toLower(title);

    static const std::vector<std::wstring>
        knownTitles
    {
        L"cheat engine",
        L"fudce app ce"
    };

    for (const auto& knownTitle : knownTitles)
    {
        if (normalized.find(knownTitle) !=
            std::wstring::npos)
        {
            return true;
        }
    }

    return false;
}