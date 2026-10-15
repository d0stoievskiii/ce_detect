#include "ConsoleReporter.hpp"

#include <iostream>

void ConsoleReporter::print(
    const DetectionReport& report
) const
{
    std::wcout
        << L"Process: "
        << report.processName
        << L'\n';

    std::cout
        << "PID: "
        << report.processId
        << '\n';

    for (const auto& result : report.results)
    {
        if (!result.detected)
        {
            continue;
        }

        std::cout
            << "[+] "
            << result.detectorName
            << "  +"
            << result.score
            << '\n';

        for (const auto& evidence :
            result.evidence)
        {
            std::cout
                << "    "
                << evidence
                << '\n';
        }
    }

    std::cout
        << "\nConfidence score: "
        << report.totalScore
        << "/100\n";

    std::cout
        << "Classification: "
        << toString(report.confidence)
        << "\n\n";
}

void ConsoleReporter::print(
    const std::vector<DetectionReport>& reports
) const
{
    if (reports.empty())
    {
        std::cout
            << "No Cheat Engine indicators detected.\n";

        return;
    }

    for (const auto& report : reports)
    {
        print(report);
    }
}