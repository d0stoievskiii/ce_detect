#include "detectors/ProcessNameDetector.hpp"

#include <algorithm>
#include <cwctype>

std::string ProcessNameDetector::name() const
{
    return "Process Name Detector";
}

DetectionResult ProcessNameDetector::scan(
    const DetectionContext& context
) const
{
    DetectionResult result;
    result.detectorName = name();

    const std::wstring normalizedProcessName =
        toLower(context.processName);

    for (const auto& knownName : knownProcessNames_)
    {
        if (normalizedProcessName ==
            toLower(knownName))
        {
            result.detected = true;
            result.score = MatchScore;

            result.evidence.push_back(
                "Known Cheat Engine process name detected."
            );

            break;
        }
    }

    return result;
}

std::wstring ProcessNameDetector::toLower(
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