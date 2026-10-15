#pragma once

#include "DetectionTypes.hpp"

#include <string>

class IDetector
{
public:
    virtual ~IDetector() = default;

    virtual std::string name() const = 0;

    virtual DetectionResult scan(
        const DetectionContext& context
    ) const = 0;
};