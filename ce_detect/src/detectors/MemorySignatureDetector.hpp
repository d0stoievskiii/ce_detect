#pragma once

#include "IDetector.hpp"
#include "SignatureFamily.hpp"

#include <Windows.h>

#include <cstdint>
#include <functional>
#include <string>
#include <vector>


class MemorySignatureDetector final : public IDetector
{
public:
    using MemoryReader =
        std::function<
        std::vector<MemoryRegion>(DWORD)
        >;

    MemorySignatureDetector();

    MemorySignatureDetector(
        std::vector<MemorySignature> signatures,
        std::vector<SignatureFamily> families,
        MemoryReader memoryReader
    );

    std::string name() const override;

    DetectionResult scan(
        const DetectionContext& context
    ) const override;

private:
    static std::vector<MemoryRegion>
        readProcessMemoryRegions(
            DWORD processId
        );

    static bool isReadableProtection(
        DWORD protection
    );

    std::vector<MemorySignature> signatures_;
    std::vector<SignatureFamily> families_;

    MemoryReader memoryReader_;

    static constexpr int MaxScore = 30;
};