#pragma once
#pragma once

#include <Windows.h>

#include <cstdint>
#include <string>
#include <vector>

struct MemorySignature
{
    std::string name;
    std::vector<std::uint8_t> bytes;
    std::string mask;
    int score;
};

struct MemoryRegion
{
    std::uintptr_t baseAddress{};
    DWORD protection{};
    DWORD type{};

    std::vector<std::uint8_t> bytes;
};