#include "detectors/ProcessMetadataDetector.hpp"

#include <Windows.h>

#include <algorithm>
#include <cstddef>
#include <cwctype>
#include <utility>

ProcessMetadataDetector::ProcessMetadataDetector()
    : metadataReader_(readMetadata)
{
}

ProcessMetadataDetector::ProcessMetadataDetector(
    MetadataReader metadataReader
)
    : metadataReader_(
        std::move(metadataReader)
    )
{
}

std::string ProcessMetadataDetector::name() const
{
    return "Process Metadata Detector";
}

DetectionResult ProcessMetadataDetector::scan(
    const DetectionContext& context
) const
{
    DetectionResult result;
    result.detectorName = name();

    if (context.executablePath.empty())
    {
        return result;
    }

    const auto metadata =
        metadataReader_(
            context.executablePath
        );

    if (!metadata.has_value())
    {
        return result;
    }

    int totalScore = 0;

    if (containsCheatEngineIdentifier(
        metadata->productName))
    {
        totalScore += ProductNameScore;

        result.evidence.push_back(
            "ProductName contains a known "
            "Cheat Engine identifier. (+"
            + std::to_string(
                ProductNameScore
            )
            + ")"
        );
    }

    if (containsCheatEngineIdentifier(
        metadata->fileDescription))
    {
        totalScore += FileDescriptionScore;

        result.evidence.push_back(
            "FileDescription contains a known "
            "Cheat Engine identifier. (+"
            + std::to_string(
                FileDescriptionScore
            )
            + ")"
        );
    }

    if (containsCheatEngineIdentifier(
        metadata->originalFilename))
    {
        totalScore += OriginalFilenameScore;

        result.evidence.push_back(
            "OriginalFilename contains a known "
            "Cheat Engine identifier. (+"
            + std::to_string(
                OriginalFilenameScore
            )
            + ")"
        );
    }

    if (containsCheatEngineIdentifier(
        metadata->companyName))
    {
        totalScore += CompanyNameScore;

        result.evidence.push_back(
            "CompanyName contains a known "
            "Cheat Engine identifier. (+"
            + std::to_string(
                CompanyNameScore
            )
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

std::optional<FileMetadata>
ProcessMetadataDetector::readMetadata(
    const std::filesystem::path& executablePath
)
{
    const DWORD versionSize =
        GetFileVersionInfoSizeW(
            executablePath.c_str(),
            nullptr
        );

    if (versionSize == 0)
    {
        return std::nullopt;
    }

    std::vector<std::byte> versionData(
        versionSize
    );

    if (!GetFileVersionInfoW(
        executablePath.c_str(),
        0,
        versionSize,
        versionData.data()))
    {
        return std::nullopt;
    }

    FileMetadata metadata;

    metadata.productName =
        readStringField(
            versionData,
            L"ProductName"
        );

    metadata.fileDescription =
        readStringField(
            versionData,
            L"FileDescription"
        );

    metadata.originalFilename =
        readStringField(
            versionData,
            L"OriginalFilename"
        );

    metadata.companyName =
        readStringField(
            versionData,
            L"CompanyName"
        );

    return metadata;
}

std::wstring
ProcessMetadataDetector::readStringField(
    const std::vector<std::byte>& versionData,
    const std::wstring& fieldName
)
{
    struct LanguageAndCodePage
    {
        WORD language;
        WORD codePage;
    };

    LanguageAndCodePage* translations = nullptr;
    UINT translationSize = 0;

    if (!VerQueryValueW(
        versionData.data(),
        L"\\VarFileInfo\\Translation",
        reinterpret_cast<void**>(&translations),
        &translationSize))
    {
        return {};
    }

    if (translations == nullptr ||
        translationSize < sizeof(LanguageAndCodePage))
    {
        return {};
    }

    const std::size_t translationCount =
        translationSize / sizeof(LanguageAndCodePage);

    for (std::size_t i = 0;
        i < translationCount;
        ++i)
    {
        wchar_t query[256]{};

        const int written = swprintf_s(
            query,
            L"\\StringFileInfo\\%04x%04x\\%s",
            translations[i].language,
            translations[i].codePage,
            fieldName.c_str()
        );

        if (written <= 0)
        {
            continue;
        }

        wchar_t* value = nullptr;
        UINT valueLength = 0;

        if (!VerQueryValueW(
            versionData.data(),
            query,
            reinterpret_cast<void**>(&value),
            &valueLength))
        {
            continue;
        }

        if (value == nullptr || valueLength == 0)
        {
            continue;
        }

        /*
         * VerQueryValueW returns the length in WCHARs.
         * Version strings normally include the terminating NUL.
         */
        std::size_t length =
            static_cast<std::size_t>(valueLength);

        if (length > 0 &&
            value[length - 1] == L'\0')
        {
            --length;
        }

        return std::wstring(
            value,
            length
        );
    }

    return {};
}

std::wstring
ProcessMetadataDetector::toLower(
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

bool
ProcessMetadataDetector::containsCheatEngineIdentifier(
    const std::wstring& value
)
{
    if (value.empty())
    {
        return false;
    }

    const std::wstring normalized =
        toLower(value);

    static const std::vector<std::wstring>
        identifiers
    {
        L"cheat engine",
        L"cheatengine"
    };

    for (const auto& identifier :
        identifiers)
    {
        if (normalized.find(identifier) !=
            std::wstring::npos)
        {
            return true;
        }
    }

    return false;
}