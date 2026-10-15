#pragma once

#include "SignatureFamily.hpp"

#include <string>
#include <vector>

namespace MemorySignatureDefinitions
{
    MemorySignature exactSignature(
        std::string name,
        std::vector<std::uint8_t> bytes
    );

    MemorySignature rel32CallSignature(
        std::string name,
        std::vector<std::uint8_t> bytes,
        std::size_t callOffset
    );

    SignatureFamily makeFirstScanFamily();

    std::vector<MemorySignature>
        makeDefaultStandaloneSignatures();

    std::vector<SignatureFamily>
        makeDefaultSignatureFamilies();
    SignatureFamily makeFirstNextScanFamily();
    SignatureFamily makeNextNextScanFamily();
    SignatureFamily makeConfigureScanRoutineFamily();
    SignatureFamily MemorySignatureDefinitions::makeAutoAssemblerExecutionFamily();
    SignatureFamily MemorySignatureDefinitions::makeSpeedhackInitializationFamily();
    SignatureFamily MemorySignatureDefinitions::makeDebuggerEventLoopFamily();
}