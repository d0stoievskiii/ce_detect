#include "detectors/MemorySignatureDetector.hpp"

#include "MemoryPatternMatcher.hpp"
#include "SignatureFamilyMatcher.hpp"
#include "MemorySignatureDefinitions.hpp"

#include <algorithm>
#include <cstddef>
#include <cstdint>
#include <initializer_list>
#include <string>
#include <utility>
#include <vector>


MemorySignatureDetector::MemorySignatureDetector()
    : signatures_(
        MemorySignatureDefinitions::
        makeDefaultStandaloneSignatures()
    ),
    families_(
        MemorySignatureDefinitions::
        makeDefaultSignatureFamilies()
    ),
    memoryReader_(
        readProcessMemoryRegions
    )
{
}

MemorySignatureDetector::MemorySignatureDetector(
    std::vector<MemorySignature> signatures,
    std::vector<SignatureFamily> families,
    MemoryReader memoryReader
)
    : signatures_(
        std::move(signatures)
    ),
    families_(
        std::move(families)
    ),
    memoryReader_(
        std::move(memoryReader)
    )
{
}

std::string MemorySignatureDetector::name() const
{
    return "Memory Signature Detector";
}

DetectionResult MemorySignatureDetector::scan(
    const DetectionContext& context
) const
{
    DetectionResult result;
    result.detectorName = name();

    const auto regions =
        memoryReader_(context.processId);

    int totalScore = 0;

    /*
     * Standalone signatures contribute at most once each.
     */
    std::vector<bool> matchedSignatures(
        signatures_.size(),
        false
    );

    /*
     * Signature families also contribute at most once each.
     */
    std::vector<bool> matchedFamilies(
        families_.size(),
        false
    );

    for (const auto& region : regions)
    {
        // -------------------------------------------------
        // Standalone signatures
        // -------------------------------------------------
        for (std::size_t i = 0;
            i < signatures_.size();
            ++i)
        {
            if (matchedSignatures[i])
            {
                continue;
            }

            const auto& signature =
                signatures_[i];

            if (!MemoryPatternMatcher::findPattern(
                region.bytes,
                signature))
            {
                continue;
            }

            matchedSignatures[i] = true;

            totalScore +=
                signature.score;

            result.evidence.push_back(
                "Memory signature matched: "
                + signature.name
                + " (+"
                + std::to_string(
                    signature.score
                )
                + ")"
            );
        }

        // -------------------------------------------------
        // Signature families
        // -------------------------------------------------
        for (std::size_t i = 0;
            i < families_.size();
            ++i)
        {
            if (matchedFamilies[i])
            {
                continue;
            }

            const auto& family =
                families_[i];

            const auto familyMatch =
                SignatureFamilyMatcher::match(
                    region,
                    family
                );

            if (!familyMatch.matched)
            {
                continue;
            }

            matchedFamilies[i] = true;

            totalScore +=
                family.score;

            result.evidence.push_back(
                "Memory signature family matched: "
                + family.name
                + " (+"
                + std::to_string(
                    family.score
                )
                + ")"
            );
        }
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

std::vector<MemoryRegion>
MemorySignatureDetector::readProcessMemoryRegions(
    DWORD processId
)
{
    std::vector<MemoryRegion> regions;

    HANDLE processHandle =
        OpenProcess(
            PROCESS_QUERY_INFORMATION |
            PROCESS_VM_READ,
            FALSE,
            processId
        );

    if (processHandle == nullptr)
    {
        return regions;
    }

    SYSTEM_INFO systemInfo{};
    GetSystemInfo(&systemInfo);

    auto currentAddress =
        reinterpret_cast<std::uintptr_t>(
            systemInfo.lpMinimumApplicationAddress
            );

    const auto maximumAddress =
        reinterpret_cast<std::uintptr_t>(
            systemInfo.lpMaximumApplicationAddress
            );

    while (currentAddress < maximumAddress)
    {
        MEMORY_BASIC_INFORMATION mbi{};

        const SIZE_T queryResult =
            VirtualQueryEx(
                processHandle,
                reinterpret_cast<LPCVOID>(
                    currentAddress
                    ),
                &mbi,
                sizeof(mbi)
            );

        if (queryResult == 0)
        {
            break;
        }

        const auto regionBase =
            reinterpret_cast<std::uintptr_t>(
                mbi.BaseAddress
                );

        const auto regionSize =
            static_cast<std::size_t>(
                mbi.RegionSize
                );

        const bool shouldRead =
            mbi.State == MEM_COMMIT &&
            isReadableProtection(
                mbi.Protect
            );

        if (shouldRead && regionSize > 0)
        {
            std::vector<std::uint8_t> buffer(
                regionSize
            );

            SIZE_T bytesRead = 0;

            if (ReadProcessMemory(
                processHandle,
                mbi.BaseAddress,
                buffer.data(),
                regionSize,
                &bytesRead) &&
                bytesRead > 0)
            {
                buffer.resize(
                    static_cast<std::size_t>(
                        bytesRead
                        )
                );

                MemoryRegion region;

                region.baseAddress =
                    regionBase;

                region.protection =
                    mbi.Protect;

                region.type =
                    mbi.Type;

                region.bytes =
                    std::move(buffer);

                regions.push_back(
                    std::move(region)
                );
            }
        }

        const auto nextAddress =
            regionBase +
            static_cast<std::uintptr_t>(
                mbi.RegionSize
                );

        /*
         * Protect against overflow or failure
         * to advance through the address space.
         */
        if (nextAddress <= currentAddress)
        {
            break;
        }

        currentAddress =
            nextAddress;
    }

    CloseHandle(processHandle);

    return regions;
}

bool MemorySignatureDetector::isReadableProtection(
    DWORD protection
)
{
    if (protection & PAGE_GUARD)
    {
        return false;
    }

    if (protection & PAGE_NOACCESS)
    {
        return false;
    }

    const DWORD baseProtection =
        protection & 0xFF;

    switch (baseProtection)
    {
    case PAGE_READONLY:
    case PAGE_READWRITE:
    case PAGE_WRITECOPY:
    case PAGE_EXECUTE_READ:
    case PAGE_EXECUTE_READWRITE:
    case PAGE_EXECUTE_WRITECOPY:
        return true;

    default:
        return false;
    }
}