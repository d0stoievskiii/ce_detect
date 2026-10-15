#pragma once

#include "DetectionTypes.hpp"

#include <vector>

class ConsoleReporter
{
public:
    void print(
        const DetectionReport& report
    ) const;

    void print(
        const std::vector<DetectionReport>& reports
    ) const;
};