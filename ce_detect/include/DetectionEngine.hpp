#pragma once

#include "DetectionTypes.hpp"
#include "IDetector.hpp"

#include <Windows.h>
#include <TlHelp32.h>

#include <algorithm>
#include <filesystem>
#include <memory>
#include <string>
#include <vector>

class DetectionEngine
{
public:
    void addDetector(
        std::unique_ptr<IDetector> detector
    )
    {
        detectors_.push_back(
            std::move(detector)
        );
    }

    void addSystemDetector(
        std::unique_ptr<IDetector> detector
    )
    {
        systemDetectors_.push_back(
            std::move(detector)
        );
    }

    std::vector<DetectionReport>
        scanProcesses() const
    {
        std::vector<DetectionReport> reports;

        std::vector<DetectionResult> systemResults;

        DetectionContext systemContext{};

        for (const auto& detector : systemDetectors_)
        {
            systemResults.push_back(
                detector->scan(systemContext)
            );
        }

        HANDLE snapshot =
            CreateToolhelp32Snapshot(
                TH32CS_SNAPPROCESS,
                0
            );

        if (snapshot ==
            INVALID_HANDLE_VALUE)
        {
            return reports;
        }

        PROCESSENTRY32W processEntry{};
        processEntry.dwSize =
            sizeof(PROCESSENTRY32W);

        if (!Process32FirstW(
            snapshot,
            &processEntry))
        {
            CloseHandle(snapshot);
            return reports;
        }

        do
        {
            DetectionContext context;

            context.processId =
                processEntry.th32ProcessID;

            context.processName =
                processEntry.szExeFile;

            context.executablePath =
                getExecutablePath(
                    context.processId
                );

            DetectionReport report =
                scanProcess(
                    context,
                    systemResults
                );

            if (report.totalScore > 0)
            {
                reports.push_back(
                    std::move(report)
                );
            }

        } while (
            Process32NextW(
                snapshot,
                &processEntry
            )
            );

        CloseHandle(snapshot);

        return reports;
    }

private:
    std::vector<std::unique_ptr<IDetector>> detectors_;
    std::vector<std::unique_ptr<IDetector>> systemDetectors_;

    static std::filesystem::path
        getExecutablePath(DWORD processId)
    {
        HANDLE processHandle =
            OpenProcess(
                PROCESS_QUERY_LIMITED_INFORMATION,
                FALSE,
                processId
            );

        if (processHandle == nullptr)
        {
            return {};
        }

        std::wstring buffer(32768, L'\0');

        DWORD bufferSize =
            static_cast<DWORD>(
                buffer.size()
                );

        if (!QueryFullProcessImageNameW(
            processHandle,
            0,
            buffer.data(),
            &bufferSize))
        {
            CloseHandle(processHandle);
            return {};
        }

        CloseHandle(processHandle);

        buffer.resize(bufferSize);

        return std::filesystem::path(buffer);
    }

    DetectionReport scanProcess(
        const DetectionContext& context,
        const std::vector<DetectionResult>& systemResults
    ) const
    {
        DetectionReport report;

        report.processId =
            context.processId;

        report.processName =
            context.processName;

        for (const auto& detector :
            detectors_)
        {
            DetectionResult result =
                detector->scan(context);

            report.totalScore +=
                result.score;

            report.results.push_back(
                std::move(result)
            );
        }

        for (const auto& result : systemResults)
        {
            report.totalScore += result.score;
            report.results.push_back(result);
        }

        report.totalScore =
            min(
                report.totalScore,
                100
            );

        report.confidence =
            classifyConfidence(report.totalScore);

        return report;
    }
};