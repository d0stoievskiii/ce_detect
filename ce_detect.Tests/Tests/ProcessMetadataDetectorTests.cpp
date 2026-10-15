#include "detectors/ProcessMetadataDetector.hpp"

#include <cassert>
#include <filesystem>
#include <optional>

void runProcessMetadataDetectorTests()
{
    DetectionContext context;
    context.executablePath =
        L"C:\\fake\\calculator.exe";

    // ProductName match.
    {
        ProcessMetadataDetector detector(
            [](const std::filesystem::path&)
            -> std::optional<FileMetadata>
            {
                return FileMetadata
                {
                    L"Cheat Engine",
                    L"",
                    L"",
                    L""
                };
            }
        );

        const auto result =
            detector.scan(context);

        assert(result.detected);
        assert(result.score == 15);
        assert(result.evidence.size() == 1);
    }

    // OriginalFilename match.
    {
        ProcessMetadataDetector detector(
            [](const std::filesystem::path&)
            -> std::optional<FileMetadata>
            {
                return FileMetadata
                {
                    L"",
                    L"",
                    L"cheatengine-x86_64.exe",
                    L""
                };
            }
        );

        const auto result =
            detector.scan(context);

        assert(result.detected);
        assert(result.score == 20);
        assert(result.evidence.size() == 1);
    }

    // Multiple fields match, score capped at 25.
    {
        ProcessMetadataDetector detector(
            [](const std::filesystem::path&)
            -> std::optional<FileMetadata>
            {
                return FileMetadata
                {
                    L"Cheat Engine",
                    L"Cheat Engine 7.5",
                    L"cheatengine-x86_64.exe",
                    L"Cheat Engine Project"
                };
            }
        );

        const auto result =
            detector.scan(context);

        assert(result.detected);

        // Raw score:
        // 15 + 10 + 20 + 5 = 50
        //
        // Detector cap:
        assert(result.score == 25);

        // Evidence for every matching field is preserved.
        assert(result.evidence.size() == 4);
    }

    // Matching is case-insensitive.
    {
        ProcessMetadataDetector detector(
            [](const std::filesystem::path&)
            -> std::optional<FileMetadata>
            {
                return FileMetadata
                {
                    L"CHEAT ENGINE 7.5",
                    L"",
                    L"",
                    L""
                };
            }
        );

        const auto result =
            detector.scan(context);

        assert(result.detected);
        assert(result.score == 15);
    }

    // Unrelated executable metadata.
    {
        ProcessMetadataDetector detector(
            [](const std::filesystem::path&)
            -> std::optional<FileMetadata>
            {
                return FileMetadata
                {
                    L"Windows Notepad",
                    L"Notepad",
                    L"notepad.exe",
                    L"Microsoft Corporation"
                };
            }
        );

        const auto result =
            detector.scan(context);

        assert(!result.detected);
        assert(result.score == 0);
        assert(result.evidence.empty());
    }

    // Reader failed / no version resource.
    {
        ProcessMetadataDetector detector(
            [](const std::filesystem::path&)
            -> std::optional<FileMetadata>
            {
                return std::nullopt;
            }
        );

        const auto result =
            detector.scan(context);

        assert(!result.detected);
        assert(result.score == 0);
        assert(result.evidence.empty());
    }

    // No executable path.
    {
        DetectionContext emptyContext;

        ProcessMetadataDetector detector(
            [](const std::filesystem::path&)
            -> std::optional<FileMetadata>
            {
                // This should never be needed.
                return FileMetadata{};
            }
        );

        const auto result =
            detector.scan(emptyContext);

        assert(!result.detected);
        assert(result.score == 0);
    }
}