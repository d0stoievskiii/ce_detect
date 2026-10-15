#include "detectors/DriverDetector.hpp"

#include <Windows.h>
#include <Psapi.h>

#include <algorithm>
#include <cwctype>
#include <utility>
#include <vector>

DriverDetector::DriverDetector()
    : enumerator_(enumerateLoadedDrivers)
{
}

DriverDetector::DriverDetector(
    DriverEnumerator enumerator
)
    : enumerator_(std::move(enumerator))
{
}

std::string DriverDetector::name() const
{
    return "Driver Detector";
}

DetectionResult DriverDetector::scan(
    const DetectionContext& context
) const
{
    // The driver check is system-wide.
    // Context is unused for this detector.
    (void)context;

    DetectionResult result;
    result.detectorName = name();

    const auto drivers =
        enumerator_();

    int totalScore = 0;

    for (const auto& driver : drivers)
    {
        const std::wstring normalized =
            toLower(driver);

        const auto match =
            knownDrivers_.find(normalized);

        if (match == knownDrivers_.end())
        {
            continue;
        }

        const int weight =
            match->second;

        totalScore += weight;

        result.evidence.push_back(
            "Known Cheat Engine driver loaded: "
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
DriverDetector::enumerateLoadedDrivers()
{
    std::vector<std::wstring> drivers;

    std::vector<LPVOID> addresses(1024);

    DWORD bytesNeeded = 0;

    if (!EnumDeviceDrivers(
        addresses.data(),
        static_cast<DWORD>(
            addresses.size() *
            sizeof(LPVOID)
            ),
        &bytesNeeded))
    {
        return drivers;
    }

    /*
     * If our initial buffer was too small,
     * resize and ask again.
     */
    if (bytesNeeded >
        addresses.size() *
        sizeof(LPVOID))
    {
        addresses.resize(
            bytesNeeded /
            sizeof(LPVOID)
        );

        if (!EnumDeviceDrivers(
            addresses.data(),
            static_cast<DWORD>(
                addresses.size() *
                sizeof(LPVOID)
                ),
            &bytesNeeded))
        {
            return drivers;
        }
    }

    const std::size_t driverCount =
        bytesNeeded /
        sizeof(LPVOID);

    for (std::size_t i = 0;
        i < driverCount;
        ++i)
    {
        wchar_t nameBuffer[MAX_PATH]{};

        const DWORD length =
            GetDeviceDriverBaseNameW(
                addresses[i],
                nameBuffer,
                static_cast<DWORD>(
                    std::size(nameBuffer)
                    )
            );

        if (length == 0)
        {
            continue;
        }

        drivers.emplace_back(
            nameBuffer,
            static_cast<std::size_t>(
                length
                )
        );
    }

    return drivers;
}

std::wstring DriverDetector::toLower(
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

std::string DriverDetector::narrow(
    const std::wstring& value
)
{
    return std::string(
        value.begin(),
        value.end()
    );
}