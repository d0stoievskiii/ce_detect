#include "detectors/ModuleDetector.hpp"

#include <Windows.h>
#include <TlHelp32.h>

#include <algorithm>
#include <cwctype>
#include <utility>

#include <unordered_set>

ModuleDetector::ModuleDetector()
    : enumerator_(enumerateModules)
{
}

ModuleDetector::ModuleDetector(
    ModuleEnumerator enumerator
)
    : enumerator_(std::move(enumerator))
{
}

std::string ModuleDetector::name() const
{
    return "Module Detector";
}

DetectionResult ModuleDetector::scan(
    const DetectionContext& context
) const
{
    DetectionResult result;
    result.detectorName = name();

    const auto modules =
        enumerator_(context.processId);

    int totalScore = 0;

    std::unordered_set<std::wstring>
        matchedModules;

    for (const auto& module : modules)
    {
        const std::wstring normalized =
            toLower(module);

        const auto match =
            knownModules_.find(normalized);

        if (match == knownModules_.end())
        {
            continue;
        }

        /*
         * If this normalized module name has already
         * contributed, ignore duplicate occurrences.
         */
        if (!matchedModules.insert(normalized).second)
        {
            continue;
        }

        const int weight =
            match->second;

        totalScore += weight;

        result.evidence.push_back(
            "Known Cheat Engine module loaded: "
            + narrow(normalized)
            + " (+"
            + std::to_string(weight)
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

std::vector<std::wstring>
ModuleDetector::enumerateModules(
    DWORD processId
)
{
    std::vector<std::wstring> modules;

    HANDLE snapshot =
        CreateToolhelp32Snapshot(
            TH32CS_SNAPMODULE |
            TH32CS_SNAPMODULE32,
            processId
        );

    if (snapshot == INVALID_HANDLE_VALUE)
    {
        return modules;
    }

    MODULEENTRY32W entry{};
    entry.dwSize = sizeof(entry);

    if (!Module32FirstW(snapshot, &entry))
    {
        CloseHandle(snapshot);
        return modules;
    }

    do
    {
        modules.emplace_back(
            entry.szModule
        );

    } while (
        Module32NextW(snapshot, &entry)
    );

    CloseHandle(snapshot);

    return modules;
}

std::wstring ModuleDetector::toLower(
    std::wstring value
)
{
    std::transform(
        value.begin(),
        value.end(),
        value.begin(),
        [](wchar_t c)
        {
            return static_cast<wchar_t>(
                std::towlower(c)
            );
        }
    );

    return value;
}

std::string ModuleDetector::narrow(
    const std::wstring& value
)
{
    return std::string(
        value.begin(),
        value.end()
    );
}