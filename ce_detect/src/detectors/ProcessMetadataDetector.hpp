#pragma once

#include "IDetector.hpp"

#include <filesystem>
#include <functional>
#include <optional>
#include <string>
#include <vector>

struct FileMetadata
{
    std::wstring productName;
    std::wstring fileDescription;
    std::wstring originalFilename;
    std::wstring companyName;
};

class ProcessMetadataDetector final : public IDetector
{
public:
    using MetadataReader =
        std::function<
        std::optional<FileMetadata>(
            const std::filesystem::path&
        )
        >;

    ProcessMetadataDetector();

    explicit ProcessMetadataDetector(
        MetadataReader metadataReader
    );

    std::string name() const override;

    DetectionResult scan(
        const DetectionContext& context
    ) const override;

private:
    static std::optional<FileMetadata>
        readMetadata(
            const std::filesystem::path& executablePath
        );

    static std::wstring readStringField(
        const std::vector<std::byte>& versionData,
        const std::wstring& fieldName
    );

    static std::wstring toLower(
        std::wstring value
    );

    static bool containsCheatEngineIdentifier(
        const std::wstring& value
    );

    MetadataReader metadataReader_;

    static constexpr int ProductNameScore = 15;
    static constexpr int FileDescriptionScore = 10;
    static constexpr int OriginalFilenameScore = 20;
    static constexpr int CompanyNameScore = 5;

    static constexpr int MaxScore = 25;
};