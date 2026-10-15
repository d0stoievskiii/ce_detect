#include "detectors/MemorySignatureDefinitions.hpp"

MemorySignature MemorySignatureDefinitions::exactSignature(
    std::string name,
    std::vector<std::uint8_t> bytes
)
{
    const auto size = bytes.size();

    return MemorySignature
    {
        std::move(name),
        std::move(bytes),
        std::string(size, 'x'),
        0
    };
}

MemorySignature maskedSignature(
    std::string name,
    std::vector<std::uint8_t> bytes,
    std::initializer_list<std::size_t> wildcardOffsets
)
{
    std::string mask(
        bytes.size(),
        'x'
    );

    for (const auto offset : wildcardOffsets)
    {
        if (offset < mask.size())
        {
            mask[offset] = '?';
        }
    }

    return MemorySignature
    {
        std::move(name),
        std::move(bytes),
        std::move(mask),
        0
    };
}

/*
 * Marks the 4-byte displacement following an E8 CALL
 * instruction as wildcard.
 *
 * callOffset points to the E8 opcode itself.
 */
MemorySignature MemorySignatureDefinitions::rel32CallSignature(
    std::string name,
    std::vector<std::uint8_t> bytes,
    std::size_t callOffset
)
{
    return maskedSignature(
        std::move(name),
        std::move(bytes),
        {
            callOffset + 1,
            callOffset + 2,
            callOffset + 3,
            callOffset + 4
        }
    );
}

SignatureFamily MemorySignatureDefinitions::makeFirstScanFamily()
{
    return SignatureFamily
    {
        "TScanner.FirstScan",

        {
            // -------------------------------------------------
            // Anchor 1:
            // TScanner range/state fields.
            //
            // Stable across the compared CE 7.4 / 7.5 builds:
            //
            // [this + 0x228] -> STARTREGION
            // [this + 0x22C] -> STOPREGION
            // [this + 0x208] -> scan-state flag
            // -------------------------------------------------
            {
                "Scanner state",

                exactSignature(
                    "FirstScan scanner state",
                    {
                        0x48, 0x8B, 0x45, 0xF8,

                        0x8B, 0x80,
                        0x28, 0x02, 0x00, 0x00,

                        0x89, 0x45, 0xAC,

                        0x48, 0x8B, 0x45, 0xF8,

                        0x8B, 0x80,
                        0x2C, 0x02, 0x00, 0x00,

                        0x89, 0x45, 0xA8,

                        0x48, 0x8B, 0x45, 0xF8,

                        0x80, 0xB8,
                        0x08, 0x02, 0x00, 0x00,
                        0x00
                    }
                ),

                0
            },

        // -------------------------------------------------
        // Anchor 2:
        //
        // mov r9d, 4
        // mov r8d, 103000h
        //
        // The instructions immediately around this differ
        // between CE 7.4 and 7.5, so deliberately keep the
        // anchor narrow.
        // -------------------------------------------------
        {
            "Allocation flags",

            exactSignature(
                "FirstScan allocation flags",
                {
                    0x41, 0xB9,
                    0x04, 0x00, 0x00, 0x00,

                    0x41, 0xB8,
                    0x00, 0x30, 0x10, 0x00
                }
            ),

            32
        },

        // -------------------------------------------------
        // Anchor 3:
        //
        // mov [rbp+MEMORYBUFFER], rax
        // mov rcx, [rbp+this]
        // call ConfigureScanRoutine
        //
        // Relative CALL displacement differs between
        // binaries, so bytes 9..12 are wildcarded.
        // -------------------------------------------------
        {
            "Configure scan routine",

            rel32CallSignature(
                "FirstScan configure routine",
                {
                    0x48, 0x89, 0x45, 0xB8,

                    0x48, 0x8B, 0x4D, 0xF8,

                    0xE8,
                    0x00, 0x00, 0x00, 0x00
                },
                8
            ),

            20
        },

        // -------------------------------------------------
        // Anchor 4:
        //
        // [this + 0x284] = 0x65
        //
        // Followed by setup for the memory-region array.
        // -------------------------------------------------
        {
            "Scanner phase 0x65",

            exactSignature(
                "FirstScan phase 0x65",
                {
                    0x48, 0x8B, 0x45, 0xF8,

                    0xC7, 0x80,
                    0x84, 0x02, 0x00, 0x00,
                    0x65, 0x00, 0x00, 0x00,

                    0x48, 0xC7, 0x45, 0x90,
                    0x10, 0x00, 0x00, 0x00
                }
            ),

            128
        },

        // -------------------------------------------------
        // Anchor 5:
        //
        // [this + 0x284] = 0x66
        //
        // Followed by movement of the current read size
        // into the working state.
        // -------------------------------------------------
        {
            "Scanner phase 0x66",

            exactSignature(
                "FirstScan phase 0x66",
                {
                    0x48, 0x8B, 0x45, 0xF8,

                    0xC7, 0x80,
                    0x84, 0x02, 0x00, 0x00,
                    0x66, 0x00, 0x00, 0x00,

                    0x66, 0x0F, 0x1F,
                    0x44, 0x00, 0x00,

                    0x48, 0x8B, 0x45, 0xB0,

                    0x48, 0x89, 0x45, 0xD8
                }
            ),

            512
        },

        // -------------------------------------------------
        // Anchor 6:
        // Process-memory-read argument setup.
        //
        // The called routine's rel32 displacement varies.
        // -------------------------------------------------
        {
            "Process memory read",

            rel32CallSignature(
                "FirstScan process memory read",
                {
                    0x48, 0x8D, 0x45, 0xC8,

                    0x48, 0x89, 0x44, 0x24, 0x20,

                    0x4C, 0x8B, 0x4D, 0xD0,

                    0x4C, 0x8B, 0x45, 0xB8,

                    0x48, 0x8B, 0x55, 0xE0,

                    0x48, 0x8B, 0x4D, 0xA0,

                    0xE8,
                    0x00, 0x00, 0x00, 0x00
                },
                25
            ),

            128
        },

        // -------------------------------------------------
        // Anchor 7:
        //
        // [this + 0x284] = 0x3FD
        //
        // set up scan-routine arguments
        // call ...
        //
        // [this + 0x284] = 0x3FE
        //
        // This is a particularly distinctive late-stage
        // state transition found in both compared builds.
        // -------------------------------------------------
        {
            "Scanner phase 0x3FD -> 0x3FE",

            rel32CallSignature(
                "FirstScan phase 0x3FD -> 0x3FE",
                {
                    // mov rax, [rbp+this]
                    0x48, 0x8B, 0x45, 0xF8,

                    // mov dword ptr [rax+284h], 3FDh
                    0xC7, 0x80,
                    0x84, 0x02, 0x00, 0x00,
                    0xFD, 0x03, 0x00, 0x00,

                    // mov r9d, [rbp+ACTUALREAD]
                    0x44, 0x8B, 0x4D, 0xC8,

                    // mov r8, [rbp+MEMORYBUFFER]
                    0x4C, 0x8B, 0x45, 0xB8,

                    // mov rdx, [rbp+CURRENTBASE]
                    0x48, 0x8B, 0x55, 0xE0,

                    // mov rcx, [rbp+this]
                    0x48, 0x8B, 0x4D, 0xF8,

                    // call rel32
                    0xE8,
                    0x00, 0x00, 0x00, 0x00,

                    // mov rax, [rbp+this]
                    0x48, 0x8B, 0x45, 0xF8,

                    // mov dword ptr [rax+284h], 3FEh
                    0xC7, 0x80,
                    0x84, 0x02, 0x00, 0x00,
                    0xFE, 0x03, 0x00, 0x00
                },

                /*
                 * Bytes before CALL:
                 *
                 * 4  mov rax
                 * 10 mov state
                 * 4  r9
                 * 4  r8
                 * 4  rdx
                 * 4  rcx
                 * ----
                 * 30
                 *
                 * Therefore E8 is at offset 30.
                 */
                30
            ),

            512
        }
    },

    15
    };
}

std::vector<MemorySignature>
MemorySignatureDefinitions::makeDefaultStandaloneSignatures()
{
    return
    {
        {
            "CE/FPC runtime string: sysconst.sinvalidinput",

            {
                0x73, 0x79, 0x73, 0x63,
                0x6F, 0x6E, 0x73, 0x74,
                0x2E,
                0x73, 0x69, 0x6E,
                0x76, 0x61, 0x6C, 0x69,
                0x64, 0x69, 0x6E, 0x70,
                0x75, 0x74
            },

            std::string(22, 'x'),

        /*
         * Weak signal: this originates from the FPC/Pascal
         * runtime and isn't uniquely Cheat Engine.
         */
        5
    }
    };
}

SignatureFamily MemorySignatureDefinitions::makeFirstNextScanFamily()
{
    return SignatureFamily
    {
        "TScanner.FirstNextScan",

        {
            // -------------------------------------------------
            // Anchor 1:
            //
            // [this + 0x284] = 0x12C
            // call ProcessHandle
            // store returned handle
            //
            // CALL rel32 differs between builds.
            // -------------------------------------------------
            {
                "Scanner phase 0x12C",

                rel32CallSignature(
                    "FirstNextScan phase 0x12C",
                    {
                        // mov rax, [rbp+this]
                        0x48, 0x8B, 0x45, 0xF8,

                        // mov dword ptr [rax+284h],12Ch
                        0xC7, 0x80,
                        0x84, 0x02, 0x00, 0x00,
                        0x2C, 0x01, 0x00, 0x00,

                        // call ProcessHandle
                        0xE8,
                        0x00, 0x00, 0x00, 0x00,

                        // mov [rbp+PHANDLE],rax
                        0x48, 0x89, 0x45, 0xB8
                    },

                    14
                ),

                0
            },

        // -------------------------------------------------
        // Anchor 2:
        //
        // [this+0x228] -> STARTREGION
        // [this+0x22C] -> STOPREGION
        //
        // followed nearby by:
        //
        // mov r9d,4
        // mov r8d,103000h
        //
        // We intentionally do not include the size
        // calculation because it differs between builds.
        // -------------------------------------------------
        {
            "Scanner range",

            exactSignature(
                "FirstNextScan scanner range",
                {
                    0x48, 0x8B, 0x45, 0xF8,

                    0x8B, 0x80,
                    0x28, 0x02, 0x00, 0x00,

                    0x89, 0x45, 0xE4,

                    0x48, 0x8B, 0x45, 0xF8,

                    0x8B, 0x80,
                    0x2C, 0x02, 0x00, 0x00,

                    0x89, 0x45, 0xE0
                }
            ),

            64
        },

        {
            "Allocation flags",

            exactSignature(
                "FirstNextScan allocation flags",
                {
                    // mov r9d,4
                    0x41, 0xB9,
                    0x04, 0x00, 0x00, 0x00,

                    // mov r8d,103000h
                    0x41, 0xB8,
                    0x00, 0x30, 0x10, 0x00
                }
            ),

            64
        },

        // -------------------------------------------------
        // Anchor 3:
        //
        // [this+0x284] = 0x12D
        // mov rcx,[rbp+this]
        // call ConfigureScanRoutine
        // -------------------------------------------------
        {
            "Scanner phase 0x12D",

            rel32CallSignature(
                "FirstNextScan phase 0x12D",
                {
                    0x48, 0x8B, 0x45, 0xF8,

                    0xC7, 0x80,
                    0x84, 0x02, 0x00, 0x00,
                    0x2D, 0x01, 0x00, 0x00,

                    // nop
                    0x90,

                    // mov rcx,[rbp+this]
                    0x48, 0x8B, 0x4D, 0xF8,

                    // call ConfigureScanRoutine
                    0xE8,
                    0x00, 0x00, 0x00, 0x00
                },

                19
            ),

        /*
         * Allocation failure-handling code lies between
         * the allocation sequence and this success path,
         * and differs substantially between compilers.
         */
        512
    },

        // -------------------------------------------------
        // Anchor 4:
        //
        // [this+0x284] = 0x12E
        //
        // setup:
        //   ACTUALREAD
        //   OLDBUFFER
        //   MEMORYBUFFER
        //   CURRENTBASE
        //   this
        //
        // call FirstNextScanMem
        //
        // [this+0x284] = 0x18E
        //
        // This whole structure is identical in both dumps
        // except for the rel32 call displacement.
        // -------------------------------------------------
        {
            "Scanner phase 0x12E -> 0x18E",

            rel32CallSignature(
                "FirstNextScan phase 0x12E -> 0x18E",
                {
                    // mov rax,[rbp+this]
                    0x48, 0x8B, 0x45, 0xF8,

                    // state = 0x12E
                    0xC7, 0x80,
                    0x84, 0x02, 0x00, 0x00,
                    0x2E, 0x01, 0x00, 0x00,

                    // mov eax,[rbp+ACTUALREAD]
                    0x8B, 0x45, 0xC0,

                    // mov [rsp+20h],eax
                    0x89, 0x44, 0x24, 0x20,

                    // mov r9,[rbp+OLDBUFFER]
                    0x4C, 0x8B, 0x4D, 0xD0,

                    // mov r8,[rbp+MEMORYBUFFER]
                    0x4C, 0x8B, 0x45, 0xD8,

                    // mov rdx,[rbp+CURRENTBASE]
                    0x48, 0x8B, 0x55, 0xE8,

                    // mov rcx,[rbp+this]
                    0x48, 0x8B, 0x4D, 0xF8,

                    // call FirstNextScanMem
                    0xE8,
                    0x00, 0x00, 0x00, 0x00,

                    // mov rax,[rbp+this]
                    0x48, 0x8B, 0x45, 0xF8,

                    // state = 0x18E
                    0xC7, 0x80,
                    0x84, 0x02, 0x00, 0x00,
                    0x8E, 0x01, 0x00, 0x00
                },

                /*
                 * Bytes before E8:
                 *
                 * 14 state 0x12E
                 *  3 eax ACTUALREAD
                 *  4 stack arg
                 *  4 r9
                 *  4 r8
                 *  4 rdx
                 *  4 rcx
                 * ----------------
                 * 37
                 */
                37
            ),

        /*
         * Most of the region-processing loop lies
         * between 0x12D and this anchor.
         */
        1536
    },

        // -------------------------------------------------
        // Anchor 5:
        //
        // final callback:
        //
        // rcx = [this+70h]
        // call [this+68h]
        //
        // followed by:
        //
        // [this+284h] = 0x18F
        //
        // This sequence is stable across both versions.
        // -------------------------------------------------
        {
            "Scanner completion 0x18F",

            exactSignature(
                "FirstNextScan completion",
                {
                    0x48, 0x8B, 0x45, 0xF8,

                    0x48, 0x8B, 0x48, 0x70,

                    0x48, 0x8B, 0x45, 0xF8,

                    0xFF, 0x50, 0x68,

                    0x48, 0x8B, 0x45, 0xF8,

                    0xC7, 0x80,
                    0x84, 0x02, 0x00, 0x00,
                    0x8F, 0x01, 0x00, 0x00
                }
            ),

            512
        }
    },

    15
    };
}

SignatureFamily
MemorySignatureDefinitions::makeNextNextScanFamily()
{
    return SignatureFamily
    {
        "TScanner.NextNextScan",

        {
            // -------------------------------------------------
            // Anchor 1
            //
            // mov rax,[rbp+this]
            // mov dword ptr [rax+284h],0C8h
            //
            // This is the initial NextNextScan scanner state.
            // -------------------------------------------------
            {
                "Scanner phase 0xC8",

                exactSignature(
                    "NextNextScan phase 0xC8",
                    {
                        0x48, 0x8B, 0x45, 0xF8,

                        0xC7, 0x80,
                        0x84, 0x02, 0x00, 0x00,
                        0xC8, 0x00, 0x00, 0x00
                    }
                ),

                0
            },

        // -------------------------------------------------
        // Anchor 2
        //
        // Reset OLDADDRESSESGROUP,
        // load this,
        // call ConfigureScanRoutine.
        //
        // CALL displacement changes between builds.
        // -------------------------------------------------
        {
            "Configure scan routine",

            rel32CallSignature(
                "NextNextScan configure routine",
                {
                    // mov [rbp+OLDADDRESSESGROUP],0
                    0x48, 0xC7, 0x45, 0xB0,
                    0x00, 0x00, 0x00, 0x00,

                    // mov rcx,[rbp+this]
                    0x48, 0x8B, 0x4D, 0xF8,

                    // call ConfigureScanRoutine
                    0xE8,
                    0x00, 0x00, 0x00, 0x00
                },

                12
            ),

            64
        },

        // -------------------------------------------------
        // Anchor 3
        //
        // Allocation of the old-memory buffer:
        //
        // mov r9d,4
        // mov r8d,103000h
        // <zero lpAddress>
        // call VirtualAlloc
        // mov [rbp+OLDMEMORY],rax
        //
        // The zeroing instruction differs:
        //
        // 7.4: mov rcx,0
        // 7.5: xor ecx,ecx
        //
        // Therefore don't include it in this anchor.
        // -------------------------------------------------
        {
            "Old-memory allocation flags",

            exactSignature(
                "NextNextScan allocation flags",
                {
                    0x41, 0xB9,
                    0x04, 0x00, 0x00, 0x00,

                    0x41, 0xB8,
                    0x00, 0x30, 0x10, 0x00
                }
            ),

        /*
         * There is substantial file/dynamic-array
         * setup before allocation.
         */
        1024
    },

        // -------------------------------------------------
        // Anchor 4
        //
        // Generic NextNextScanMem worker call.
        //
        // This exact argument setup survives both builds:
        //
        // rdx = OLDADDRESSES
        // r9d = CHUNKSIZE
        // r8  = OLDMEMORY
        // rcx = this
        // call NextNextScanMem
        //
        // rel32 is wildcarded.
        // -------------------------------------------------
        {
            "NextNextScanMem worker",

            rel32CallSignature(
                "NextNextScan generic worker",
                {
                    // mov rdx,[rbp+OLDADDRESSES]
                    0x48, 0x8B, 0x55, 0xC0,

                    // mov r9d,[rbp+CHUNKSIZE]
                    0x44, 0x8B, 0x4D, 0xCC,

                    // mov r8,[rbp+OLDMEMORY]
                    0x4C, 0x8B, 0x45, 0xA8,

                    // mov rcx,[rbp+this]
                    0x48, 0x8B, 0x4D, 0xF8,

                    // call NextNextScanMem
                    0xE8,
                    0x00, 0x00, 0x00, 0x00
                },

                16
            ),

        /*
         * The scan-type dispatch and worker-specific
         * branches make this a large gap.
         */
        4096
    },

        // -------------------------------------------------
        // Anchor 5
        //
        // Final state:
        //
        // [this+284h] = 0x129
        //
        // then invoke the completion callback through
        // [this+68h], passing [this+70h].
        //
        // This sequence is nearly ideal because it is
        // exact and appears at the terminal path.
        // -------------------------------------------------
        {
            "Scanner completion 0x129",

            exactSignature(
                "NextNextScan completion",
                {
                    // mov rax,[rbp+this]
                    0x48, 0x8B, 0x45, 0xF8,

                    // state = 0x129
                    0xC7, 0x80,
                    0x84, 0x02, 0x00, 0x00,
                    0x29, 0x01, 0x00, 0x00,

                    // mov rax,[rbp+this]
                    0x48, 0x8B, 0x45, 0xF8,

                    // mov rcx,[rax+70h]
                    0x48, 0x8B, 0x48, 0x70,

                    // mov rax,[rbp+this]
                    0x48, 0x8B, 0x45, 0xF8,

                    // call qword ptr [rax+68h]
                    0xFF, 0x50, 0x68
                }
            ),

            1024
        }
    },

    15
    };
}

SignatureFamily
MemorySignatureDefinitions::makeConfigureScanRoutineFamily()
{
    return SignatureFamily
    {
        "TScanner.ConfigureScanRoutine",

        {
            // -------------------------------------------------
            // Anchor 1
            //
            // Reset primary scan value/result field:
            //
            //   mov rax,[rbp+this]
            //   mov qword ptr [rax+A8h],0
            //
            // This survives both builds exactly.
            // -------------------------------------------------
            {
                "Reset scanner value",

                exactSignature(
                    "ConfigureScanRoutine reset scanner value",
                    {
                        0x48, 0x8B, 0x45, 0xF8,

                        0x48, 0xC7, 0x80,
                        0xA8, 0x00, 0x00, 0x00,
                        0x00, 0x00, 0x00, 0x00
                    }
                ),

                0
            },

        // -------------------------------------------------
        // Anchor 2
        //
        // Initial buffer-size configuration and scan-type
        // discriminator.
        //
        // We deliberately start after the build-specific
        // global default-value load into +0xC0.
        //
        //   mov rdx,[rbp+this]
        //   mov eax,[global BUFFERSIZE]
        //   mov [rdx+A4h],eax
        //   mov rax,[rbp+this]
        //   cmp byte ptr [rax+209h],0Dh
        //
        // The RIP-relative BUFFERSIZE displacement changes,
        // therefore those 4 bytes are wildcarded.
        // -------------------------------------------------
        {
            "Initial scan type configuration",

            maskedSignature(
                "ConfigureScanRoutine buffer and scan type",
                {
                    0x48, 0x8B, 0x55, 0xF8,

                    // mov eax,[rip+rel32]
                    0x8B, 0x05,
                    0x00, 0x00, 0x00, 0x00,

                    // mov [rdx+A4h],eax
                    0x89, 0x82,
                    0xA4, 0x00, 0x00, 0x00,

                    // mov rax,[rbp+this]
                    0x48, 0x8B, 0x45, 0xF8,

                    // cmp byte ptr [rax+209h],0Dh
                    0x80, 0xB8,
                    0x09, 0x02, 0x00, 0x00,
                    0x0D
                },

                {
                    6, 7, 8, 9
                }
            ),

            64
        },

        // -------------------------------------------------
        // Anchor 3
        //
        // One of the strongest stable semantic markers:
        //
        //   mov rax,[rbp+this]
        //   movzx edx,byte ptr [rax+208h]
        //   mov eax,115Eh
        //   bt eax,edx
        //
        // 0x115E is the mask used to determine which scan
        // modes need value parsing/configuration.
        // -------------------------------------------------
        {
            "Scan-mode mask",

            exactSignature(
                "ConfigureScanRoutine scan-mode mask",
                {
                    0x48, 0x8B, 0x45, 0xF8,

                    0x0F, 0xB6, 0x90,
                    0x08, 0x02, 0x00, 0x00,

                    0xB8,
                    0x5E, 0x11, 0x00, 0x00,

                    0x0F, 0xA3, 0xD0
                }
            ),

        /*
         * Group-data setup and format-settings setup
         * are between the first scan-type checks and
         * this mask.
         */
        1024
    },

        // -------------------------------------------------
        // Anchor 4
        //
        // Generic scanner comparison routine assignment.
        //
        // The routine address itself is RIP-relative and
        // changes between binaries:
        //
        //   mov <this register>,[rbp+this]
        //   lea <function register>,[comparison routine]
        //   mov [this+48h],function
        //   mov [this+50h],this
        //
        // Rather than pinning one comparison function, use
        // the object-slot assignment shape.
        //
        // This version corresponds to the common:
        //
        //   mov rax,[rbp+this]
        //   lea rdx,[rip+routine]
        //   mov [rax+48h],rdx
        //   mov [rax+50h],rax
        //
        // Only the LEA displacement is wildcarded.
        // -------------------------------------------------
        {
            "Comparison routine assignment",

            maskedSignature(
                "ConfigureScanRoutine comparison assignment",
                {
                    0x48, 0x8B, 0x45, 0xF8,

                    // lea rdx,[rip+rel32]
                    0x48, 0x8D, 0x15,
                    0x00, 0x00, 0x00, 0x00,

                    // mov [rax+48h],rdx
                    0x48, 0x89, 0x50, 0x48,

                    // mov [rax+50h],rax
                    0x48, 0x89, 0x40, 0x50
                },

                {
                    7, 8, 9, 10
                }
            ),

        /*
         * ConfigureScanRoutine is large, and routine
         * assignment occurs deep inside the function.
         */
        16384
    },

        // -------------------------------------------------
        // Anchor 5
        //
        // Result buffers are allocated after comparison
        // routine selection:
        //
        //   lea rcx,[this+F8h]
        //   movsxd rdx,FOUNDBUFFERSIZE
        //   call GetMem
        //
        //   lea rcx,[this+100h]
        //   movsxd rdx,FOUNDBUFFERSIZE
        //   call GetMem
        //
        // Calls use rel32 and therefore are wildcarded.
        // -------------------------------------------------
        {
            "Result buffer allocation",

            {
                "ConfigureScanRoutine result buffers",

                {
                    0x48, 0x8B, 0x45, 0xF8,

                    0x48, 0x8D, 0x88,
                    0xF8, 0x00, 0x00, 0x00,

                    0x48, 0x63, 0x95,
                    0x5C, 0xFE, 0xFF, 0xFF,

                    0xE8,
                    0x00, 0x00, 0x00, 0x00,

                    0x48, 0x8B, 0x45, 0xF8,

                    0x48, 0x8D, 0x88,
                    0x00, 0x01, 0x00, 0x00,

                    0x48, 0x63, 0x95,
                    0x5C, 0xFE, 0xFF, 0xFF,

                    0xE8,
                    0x00, 0x00, 0x00, 0x00
                },

        /*
         * Two rel32 CALL operands.
         */
        "xxxxxxxxxxxxxxxxx????"
        "xxxxxxxxxxxxxxxxx????",

        0
    },

    4096
}
},

10
    };
}

SignatureFamily
MemorySignatureDefinitions::makeAutoAssemblerExecutionFamily()
{
    return SignatureFamily
    {
        "Auto Assembler execution",

        {
            // =================================================
            // Anchor 1
            //
            // Parse the {$CCODE(...)}-specific parameters and
            // immediately inspect DATAFORPASS2[0].
            //
            // 7.4 and 7.5 perform the same operation, but the
            // compiler uses different local-variable layouts.
            // =================================================
            {
                "Parse C block parameters",

                {
            // -----------------------------
            // CE 7.4
            // -----------------------------
            maskedSignature(
                "Parse C block parameters - 7.4",
                {
                    // mov rdx,[rbp+p_DATAFORPASS2]
                    0x48, 0x8B, 0x55, 0xE0,

                    // mov rcx,[rbp+S]
                    0x48, 0x8B, 0x4D, 0xC8,

                    // call PARSECBLOCKSPECIFICPARAMETERS
                    0xE8,
                    0x00, 0x00, 0x00, 0x00,

                    // mov rax,[rbp+p_DATAFORPASS2]
                    0x48, 0x8B, 0x45, 0xE0,

                    // cmp qword ptr [rax],0
                    0x48, 0x83, 0x38, 0x00
                },

                {
                    9, 10, 11, 12
                }
            ),

                // -----------------------------
                // CE 7.5
                // -----------------------------
                maskedSignature(
                    "Parse C block parameters - 7.5",
                    {
                        // mov rdx,[rbp+DATAFORPASS2]
                        0x48, 0x8B, 0x95,
                        0xC8, 0xFE, 0xFF, 0xFF,

                        // mov rcx,[rbp+S]
                        0x48, 0x8B, 0x4D, 0xF0,

                        // call PARSECBLOCKSPECIFICPARAMETERS
                        0xE8,
                        0x00, 0x00, 0x00, 0x00,

                        // mov rax,[rbp+DATAFORPASS2]
                        0x48, 0x8B, 0x85,
                        0xC8, 0xFE, 0xFF, 0xFF,

                        // cmp qword ptr [rax],0
                        0x48, 0x83, 0x38, 0x00
                    },

                    {
                        12, 13, 14, 15
                    }
                )
            },

            0
        },

        // =================================================
        // Anchor 2
        //
        // Locate the {$ASM} terminator of the C block.
        //
        // The surrounding local/register allocation differs
        // considerably, so each version gets its own code
        // pattern.
        // =================================================
        {
            "Find ASM terminator",

            {
            // -----------------------------
            // CE 7.4
            // -----------------------------
            maskedSignature(
                "Find {$ASM} - 7.4",
                {
                    // call UPPERCASE
                    0xE8,
                    0x00, 0x00, 0x00, 0x00,

                    // mov rcx,[rbp+uppercase]
                    0x48, 0x8B, 0x8D,
                    0x68, 0xFF, 0xFF, 0xFF,

                    // lea rdx,[rip+"{$ASM}"]
                    0x48, 0x8D, 0x15,
                    0x00, 0x00, 0x00, 0x00,

                    // call FPC_ANSISTR_COMPARE_EQUAL
                    0xE8,
                    0x00, 0x00, 0x00, 0x00,

                    // test rax,rax
                    0x48, 0x85, 0xC0
                },

                {
                    1, 2, 3, 4,
                    15, 16, 17, 18,
                    20, 21, 22, 23
                }
            ),

                // -----------------------------
                // CE 7.5
                // -----------------------------
                maskedSignature(
                    "Find {$ASM} - 7.5",
                    {
                        // call UPPERCASE
                        0xE8,
                        0x00, 0x00, 0x00, 0x00,

                        // mov rcx,[rbp+...]
                        0x48, 0x8B, 0x4D, 0xE0,

                        // lea rdx,[rip+"{$ASM}"]
                        0x48, 0x8D, 0x15,
                        0x00, 0x00, 0x00, 0x00,

                        // call compare
                        0xE8,
                        0x00, 0x00, 0x00, 0x00,

                        // test rax,rax
                        0x48, 0x85, 0xC0
                    },

                    {
                        1, 2, 3, 4,
                        12, 13, 14, 15,
                        17, 18, 19, 20
                    }
                )
            },

            512
        },

        // =================================================
        // Anchor 3
        //
        // Construct:
        //
        // ceinternal_autofree_cfunction_at_line<N>
        //
        // and then:
        //
        // void <FUNCTIONNAME>(void *parameters)
        //
        // This is the strongest identity anchor.
        // =================================================
        {
            "Generate internal C function",

            {
            // -----------------------------
            // CE 7.4
            // -----------------------------
            maskedSignature(
                "Internal C function generation - 7.4",
                {
                    // mov r8,[line-number string]
                    0x4C, 0x8B, 0x85,
                    0x60, 0xFF, 0xFF, 0xFF,

                    // lea rcx,[FUNCTIONNAME]
                    0x48, 0x8D, 0x4D, 0x90,

                    // mov r9d,0
                    0x41, 0xB9,
                    0x00, 0x00, 0x00, 0x00,

                    // lea rdx,[rip+
                    // "ceinternal_autofree_cfunction_at_line"]
                    0x48, 0x8D, 0x15,
                    0x00, 0x00, 0x00, 0x00,

                    // call concat
                    0xE8,
                    0x00, 0x00, 0x00, 0x00,

                    // cleanup temp string
                    0x48, 0x8D, 0x8D,
                    0x60, 0xFF, 0xFF, 0xFF,

                    0xE8,
                    0x00, 0x00, 0x00, 0x00,

                    // lea rax,[rip+"void "]
                    0x48, 0x8D, 0x05,
                    0x00, 0x00, 0x00, 0x00
                },

                {
                    // ceinternal string address
                    19, 20, 21, 22,

                    // concat call
                    24, 25, 26, 27,

                    // decref call
                    36, 37, 38, 39,

                    // "void " address
                    43, 44, 45, 46
                }
            ),

                // -----------------------------
                // CE 7.5
                // -----------------------------
                maskedSignature(
                    "Internal C function generation - 7.5",
                    {
                        // mov r8,[line-number string]
                        0x4C, 0x8B, 0x45, 0xD8,

                        // lea rcx,[FUNCTIONNAME]
                        0x48, 0x8D, 0x4D, 0xE8,

                        // xor r9d,r9d
                        0x45, 0x31, 0xC9,

                        // lea rdx,[rip+
                        // "ceinternal_autofree_cfunction_at_line"]
                        0x48, 0x8D, 0x15,
                        0x00, 0x00, 0x00, 0x00,

                        // call concat
                        0xE8,
                        0x00, 0x00, 0x00, 0x00,

                        // lea rcx,[temp]
                        0x48, 0x8D, 0x4D, 0xD8,

                        // call decref
                        0xE8,
                        0x00, 0x00, 0x00, 0x00,

                        // lea rax,[rip+"void "]
                        0x48, 0x8D, 0x05,
                        0x00, 0x00, 0x00, 0x00
                    },

                    {
                        14, 15, 16, 17,
                        19, 20, 21, 22,
                        29, 30, 31, 32,
                        36, 37, 38, 39
                    }
                )
            },

        /*
         * Parameter handling and C-wrapper generation
         * occurs between the {$ASM} discovery and here.
         */
        2048
    },

        // =================================================
        // Anchor 4
        //
        // Generate AA directive:
        //
        // alloc(<FUNCTIONNAME>_address,8)
        //
        // or, where applicable:
        //
        // alloc(<FUNCTIONNAME>_address,4)
        //
        // Again this is strongly CE-specific.
        // =================================================
        {
            "Generate function address allocation",

            {
            // -----------------------------
            // CE 7.4
            // -----------------------------
            maskedSignature(
                "Function address alloc - 7.4",
                {
                    // lea rax,[rip+"alloc("]
                    0x48, 0x8D, 0x05,
                    0x00, 0x00, 0x00, 0x00,

                    // save string component
                    0x48, 0x89, 0x85,
                    0x48, 0xFF, 0xFF, 0xFF,

                    // mov rax,[FUNCTIONNAME]
                    0x48, 0x8B, 0x45, 0x90,

                    // save component
                    0x48, 0x89, 0x85,
                    0x50, 0xFF, 0xFF, 0xFF,

                    // lea rax,[rip+"_address,8)"]
                    0x48, 0x8D, 0x05,
                    0x00, 0x00, 0x00, 0x00,

                    // save component
                    0x48, 0x89, 0x85,
                    0x58, 0xFF, 0xFF, 0xFF
                },

                {
                    3, 4, 5, 6,
                    27, 28, 29, 30
                }
            ),

                // -----------------------------
                // CE 7.5 - x64 address variant
                // -----------------------------
                maskedSignature(
                    "Function address alloc - 7.5",
                    {
                        // lea rax,[rip+"alloc("]
                        0x48, 0x8D, 0x05,
                        0x00, 0x00, 0x00, 0x00,

                        // local component
                        0x48, 0x89, 0x45, 0xC0,

                        // FUNCTIONNAME
                        0x48, 0x8B, 0x45, 0xE8,

                        0x48, 0x89, 0x45, 0xC8,

                        // lea rax,[rip+"_address,8)"]
                        0x48, 0x8D, 0x05,
                        0x00, 0x00, 0x00, 0x00,

                        0x48, 0x89, 0x45, 0xD0,

                        // lea rdx,array
                        0x48, 0x8D, 0x55, 0xB8,

                        // xor r9d,r9d
                        0x45, 0x31, 0xC9,

                        // r8d = 3
                        0x41, 0xB8,
                        0x03, 0x00, 0x00, 0x00
                    },

                    {
                        3, 4, 5, 6,
                        25, 26, 27, 28
                    }
                )
            },

        /*
         * C compilation/import processing is large.
         */
        8192
    }
},

15
    };
}

SignatureFamily
MemorySignatureDefinitions::makeSpeedhackInitializationFamily()
{
    return SignatureFamily
    {
        "TSpeedhack initialization",

        {
            // =================================================
            // Anchor 1
            //
            // Generate the GetTickCount speedhack hook.
            //
            // We use the fallback path containing both:
            //
            //   realgettickcount
            //   speedhackversion_GetTickCount
            //
            // followed by GenerateAPIHookScript.
            // =================================================
            {
                "Generate GetTickCount speedhack hook",

                {
            // -----------------------------------------
            // CE 7.5
            //
            // 0x553925 .. 0x553950
            // -----------------------------------------
            maskedSignature(
                "Speedhack GetTickCount hook - 7.5",
                {
                    0xC6, 0x44, 0x24, 0x28, 0x00,

                    // lea rax,[rip+...]
                    0x48, 0x8D, 0x05,
                    0x00, 0x00, 0x00, 0x00,

                    0x48, 0x89, 0x44, 0x24, 0x20,

                    // mov rdx,[rbp+FNAME]
                    0x48, 0x8B, 0x55, 0xA8,

                    // mov rcx,[rbp+SCRIPT]
                    0x48, 0x8B, 0x4D, 0xE0,

                    // lea r9,[rip+"realgettickcount"]
                    0x4C, 0x8D, 0x0D,
                    0x00, 0x00, 0x00, 0x00,

                    // lea r8,[rip+
                    // "speedhackversion_GetTickCount"]
                    0x4C, 0x8D, 0x05,
                    0x00, 0x00, 0x00, 0x00,

                    // call GenerateAPIHookScript
                    0xE8,
                    0x00, 0x00, 0x00, 0x00
                },
                {
                    // First RIP-relative LEA
                    8, 9, 10, 11,

                    // "realgettickcount"
                    28, 29, 30, 31,

                    // "speedhackversion_GetTickCount"
                    35, 36, 37, 38,

                    // GenerateAPIHookScript
                    40, 41, 42, 43
                }
            ),

                // -----------------------------------------
                // CE 7.4
                //
                // 0x56BA07 .. 0x56BA35
                // -----------------------------------------
                maskedSignature(
                    "Speedhack GetTickCount hook - 7.4",
                    {
                        0xC6, 0x44, 0x24, 0x28, 0x00,

                        // lea rax,[rip+...]
                        0x48, 0x8D, 0x05,
                        0x00, 0x00, 0x00, 0x00,

                        0x48, 0x89, 0x44, 0x24, 0x20,

                        // mov rcx,[rbp+SCRIPT]
                        0x48, 0x8B, 0x4D, 0xE0,

                        // lea r9,[rip+"realgettickcount"]
                        0x4C, 0x8D, 0x0D,
                        0x00, 0x00, 0x00, 0x00,

                        // lea r8,[rip+
                        // "speedhackversion_GetTickCount"]
                        0x4C, 0x8D, 0x05,
                        0x00, 0x00, 0x00, 0x00,

                        // lea rdx,[rip+"GetTickCount"]
                        0x48, 0x8D, 0x15,
                        0x00, 0x00, 0x00, 0x00,

                        // call GenerateAPIHookScript
                        0xE8,
                        0x00, 0x00, 0x00, 0x00
                    },
                    {
                        8, 9, 10, 11,

                        24, 25, 26, 27,

                        31, 32, 33, 34,

                        38, 39, 40, 41,

                        43, 44, 45, 46
                    }
                )
            },

            0
        },

        // =================================================
        // Anchor 2
        //
        // Create TDisableInfo and execute the initial
        // speedhack AA script.
        //
        // The 7.5 build contains the debug message:
        //
        //   "Speedhack: init1"
        //
        // between construction and AutoAssemble.
        //
        // 7.4 does not have the same sequence, therefore
        // separate alternatives are required.
        // =================================================
        {
            "Execute initial speedhack script",

            {
            // -----------------------------------------
            // CE 7.5
            //
            // 0x553955 .. 0x55399E
            // -----------------------------------------
            maskedSignature(
                "Speedhack initial AutoAssemble - 7.5",
                {
                    // mov edx,1
                    0xBA,
                    0x01, 0x00, 0x00, 0x00,

                    // lea rcx,VMT_TDisableInfo
                    0x48, 0x8D, 0x0D,
                    0x00, 0x00, 0x00, 0x00,

                    // call TDisableInfo.Create
                    0xE8,
                    0x00, 0x00, 0x00, 0x00,

                    // mov [rbp+DISABLEINFO],rax
                    0x48, 0x89, 0x45, 0xD8,

                    0x90,

                    // lea rcx,"Speedhack: init1"
                    0x48, 0x8D, 0x0D,
                    0x00, 0x00, 0x00, 0x00,

                    // call OutputDebugString
                    0xE8,
                    0x00, 0x00, 0x00, 0x00,

                    // stack args
                    0x48, 0xC7, 0x44, 0x24, 0x30,
                    0x00, 0x00, 0x00, 0x00,

                    0xC6, 0x44, 0x24, 0x20, 0x00,

                    // DISABLEINFO
                    0x48, 0x8B, 0x45, 0xD8,
                    0x48, 0x89, 0x44, 0x24, 0x28,

                    // SCRIPT
                    0x48, 0x8B, 0x4D, 0xE0,

                    // r9b = false
                    0x45, 0x30, 0xC9,

                    // r8b = true
                    0x41, 0xB0, 0x01,

                    // dl = false
                    0x30, 0xD2,

                    // call AutoAssemble
                    0xE8,
                    0x00, 0x00, 0x00, 0x00
                },
                {
                    // VMT
                    8, 9, 10, 11,

                    // TDisableInfo.Create
                    13, 14, 15, 16,

                    // "Speedhack: init1"
                    25, 26, 27, 28,

                    // OutputDebugString
                    30, 31, 32, 33,

                    // AutoAssemble
                    70, 71, 72, 73
                }
            ),

                // -----------------------------------------
                // CE 7.4
                //
                // Start at the second TDisableInfo.Create
                // emitted by this build:
                //
                // 0x56BA4E .. 0x56BA8D
                // 
                // CE 7.4 contains two consecutive TDisableInfo.Create calls.
                // Start at the second one because it directly precedes the
                // argument setup for the initial AutoAssemble invocation.
                // -----------------------------------------
                maskedSignature(
                    "Speedhack initial AutoAssemble - 7.4",
                    {
                        // mov rdx,1
                        0x48, 0xC7, 0xC2,
                        0x01, 0x00, 0x00, 0x00,

                        // lea rcx,VMT_TDisableInfo
                        0x48, 0x8D, 0x0D,
                        0x00, 0x00, 0x00, 0x00,

                        // call TDisableInfo.Create
                        0xE8,
                        0x00, 0x00, 0x00, 0x00,

                        // mov [rbp+DISABLEINFO],rax
                        0x48, 0x89, 0x45, 0xD8,

                        0x90,

                        // stack args
                        0x48, 0xC7, 0x44, 0x24, 0x30,
                        0x00, 0x00, 0x00, 0x00,

                        0xC6, 0x44, 0x24, 0x20, 0x00,

                        0x48, 0x8B, 0x45, 0xD8,
                        0x48, 0x89, 0x44, 0x24, 0x28,

                        0x48, 0x8B, 0x4D, 0xE0,

                        // r9b = false
                        0x41, 0xB1, 0x00,

                        // r8b = true
                        0x41, 0xB0, 0x01,

                        // dl = false
                        0xB2, 0x00,

                        // call AutoAssemble
                        0xE8,
                        0x00, 0x00, 0x00, 0x00
                    },
                    {
                        // VMT
                        10, 11, 12, 13,

                        // TDisableInfo.Create
                        15, 16, 17, 18,

                        // AutoAssemble
                        60, 61, 62, 63
                    }
                )
            },

            64
        },

        // =================================================
        // Anchor 3
        //
        // Walk DisableInfo.allocs.
        //
        // Allocation records are 0x28 bytes.
        //
        // Compare each allocation varname against "init".
        // When found:
        //
        //     this->initaddress = allocation.address;
        //
        // i.e.:
        //
        //     [this + 0x10] = ...
        //
        // This is the strongest anchor in the family.
        // =================================================
        {
            "Capture speedhack init allocation",

            {
            // -----------------------------------------
            // CE 7.5
            //
            // 0x5539D8 .. 0x553A1D
            // -----------------------------------------
            maskedSignature(
                "Speedhack init allocation - 7.5",
                {
                    // ++I
                    0x83, 0x45, 0xEC, 0x01,

                    // DISABLEINFO
                    0x48, 0x8B, 0x45, 0xD8,
                    0x48, 0x8B, 0x50, 0x08,

                    // I
                    0x48, 0x63, 0x45, 0xEC,

                    // sizeof allocation record = 0x28
                    0x48, 0x6B, 0xC0, 0x28,

                    // varname = allocs[I].varname
                    0x48, 0x8B, 0x4C, 0x02, 0x08,

                    // lea rdx,[rip+"init"]
                    0x48, 0x8D, 0x15,
                    0x00, 0x00, 0x00, 0x00,

                    // compare
                    0xE8,
                    0x00, 0x00, 0x00, 0x00,

                    0x48, 0x85, 0xC0,

                    // branch if not equal
                    0x75, 0x1E,

                    // reload allocation
                    0x48, 0x8B, 0x45, 0xD8,
                    0x48, 0x8B, 0x50, 0x08,
                    0x48, 0x63, 0x45, 0xEC,
                    0x48, 0x6B, 0xC0, 0x28,

                    // this
                    0x48, 0x8B, 0x4D, 0xF0,

                    // allocation address
                    0x48, 0x8B, 0x04, 0x02,

                    // this->initaddress
                    0x48, 0x89, 0x41, 0x10
                },
                {
                    // "init"
                    28, 29, 30, 31,

                    // compare call
                    33, 34, 35, 36
                }
            ),

                // -----------------------------------------
                // CE 7.4
                //
                // 0x56BAB8 .. 0x56BB05
                // -----------------------------------------
                maskedSignature(
                    "Speedhack init allocation - 7.4",
                    {
                        // ++I
                        0x8B, 0x45, 0xEC,
                        0x67, 0x8D, 0x40, 0x01,
                        0x89, 0x45, 0xEC,

                        0x48, 0x8B, 0x45, 0xD8,
                        0x48, 0x8B, 0x50, 0x08,

                        0x48, 0x63, 0x45, 0xEC,

                        // record stride 0x28
                        0x48, 0x6B, 0xC0, 0x28,

                        0x48, 0x8B, 0x4C, 0x02, 0x08,

                        // "init"
                        0x48, 0x8D, 0x15,
                        0x00, 0x00, 0x00, 0x00,

                        // compare
                        0xE8,
                        0x00, 0x00, 0x00, 0x00,

                        0x48, 0x85, 0xC0,

                        // Compiler emitted:
                        // je +2
                        // jmp +0x1e
                        0x74, 0x02,
                        0xEB, 0x1E,

                        0x48, 0x8B, 0x45, 0xD8,
                        0x48, 0x8B, 0x50, 0x08,
                        0x48, 0x63, 0x45, 0xEC,

                        0x48, 0x6B, 0xC0, 0x28,

                        0x48, 0x8B, 0x4D, 0xF0,
                        0x48, 0x8B, 0x04, 0x02,

                        // [this+10h]
                        0x48, 0x89, 0x41, 0x10
                    },
                    {
                        // "init"
                        34, 35, 36, 37,

                        // FPC_ANSISTR_COMPARE_EQUAL
                        39, 40, 41, 42
                    }
                )
            },

            128
        },

        // =================================================
        // Anchor 4
        //
        // Generate QueryPerformanceCounter hook.
        //
        // Common semantic shape:
        //
        // QPCADDRESS -> IntToHex(...,8)
        // SCRIPT
        // realQueryPerformanceCounter
        // speedhackversion_QueryPerformanceCounter
        // GenerateAPIHookScript
        // AutoAssemble
        // =================================================
        {
            "Generate QueryPerformanceCounter speedhack hook",

            {
            // -----------------------------------------
            // CE 7.5
            //
            // 0x553E03 .. 0x553E42
            // -----------------------------------------
            maskedSignature(
                "Speedhack QPC hook - 7.5",
                {
                    // mov rdx,[rbp+QPCADDRESS]
                    0x48, 0x8B, 0x55, 0x90,

                    // mov r8d,8
                    0x41, 0xB8,
                    0x08, 0x00, 0x00, 0x00,

                    // lea rcx,[ADDRESSTOGOTO]
                    0x48, 0x8D, 0x8D,
                    0x08, 0xFF, 0xFF, 0xFF,

                    // call IntToHex
                    0xE8,
                    0x00, 0x00, 0x00, 0x00,

                    // mov rdx,[ADDRESSTOGOTO]
                    0x48, 0x8B, 0x95,
                    0x08, 0xFF, 0xFF, 0xFF,

                    // SCRIPT
                    0x48, 0x8B, 0x4D, 0xE0,

                    // realQueryPerformanceCounter
                    0x4C, 0x8D, 0x0D,
                    0x00, 0x00, 0x00, 0x00,

                    // speedhackversion_QueryPerformanceCounter
                    0x4C, 0x8D, 0x05,
                    0x00, 0x00, 0x00, 0x00,

                    // GenerateAPIHookScript
                    0xE8,
                    0x00, 0x00, 0x00, 0x00,

                    0x90,

                    // AutoAssemble(script,false)
                    0x48, 0x8B, 0x4D, 0xE0,
                    0x30, 0xD2,

                    0xE8,
                    0x00, 0x00, 0x00, 0x00
                },
                {
                    // IntToHex
                    18, 19, 20, 21,

                    // realQueryPerformanceCounter
                    36, 37, 38, 39,

                    // speedhackversion_QueryPerformanceCounter
                    43, 44, 45, 46,

                    // GenerateAPIHookScript
                    48, 49, 50, 51,

                    // AutoAssemble
                    60, 61, 62, 63
                }
            ),

                // -----------------------------------------
                // CE 7.4
                //
                // 0x56BD6E .. 0x56BDAD
                // -----------------------------------------
                maskedSignature(
                    "Speedhack QPC hook - 7.4",
                    {
                        // mov rdx,[rbp+QPCADDRESS]
                        0x48, 0x8B, 0x55, 0x90,

                        // mov r8d,8
                        0x41, 0xB8,
                        0x08, 0x00, 0x00, 0x00,

                        // lea rcx,[ADDRESSTOGOTO]
                        0x48, 0x8D, 0x8D,
                        0x28, 0xFF, 0xFF, 0xFF,

                        // call IntToHex
                        0xE8,
                        0x00, 0x00, 0x00, 0x00,

                        // mov rdx,[ADDRESSTOGOTO]
                        0x48, 0x8B, 0x95,
                        0x28, 0xFF, 0xFF, 0xFF,

                        // SCRIPT
                        0x48, 0x8B, 0x4D, 0xE0,

                        // realQueryPerformanceCounter
                        0x4C, 0x8D, 0x0D,
                        0x00, 0x00, 0x00, 0x00,

                        // speedhackversion_QueryPerformanceCounter
                        0x4C, 0x8D, 0x05,
                        0x00, 0x00, 0x00, 0x00,

                        // GenerateAPIHookScript
                        0xE8,
                        0x00, 0x00, 0x00, 0x00,

                        0x90,

                        // AutoAssemble(script,false)
                        0x48, 0x8B, 0x4D, 0xE0,
                        0xB2, 0x00,

                        0xE8,
                        0x00, 0x00, 0x00, 0x00
                    },
                    {
                        18, 19, 20, 21,

                        36, 37, 38, 39,

                        43, 44, 45, 46,

                        48, 49, 50, 51,

                        60, 61, 62, 63
                    }
                )
            },

            1024
        }
    },

    15
    };
}

SignatureFamily
MemorySignatureDefinitions::makeDebuggerEventLoopFamily()
{
    return SignatureFamily
    {
        "Debugger event loop",

        {
            // =================================================
            // Anchor 1
            //
            // WaitForDebugEvent(debugEvent, 100)
            //
            // followed by:
            //
            // CONTINUESTATUS = DBG_CONTINUE (0x10002)
            //
            // The two builds differ in surrounding state
            // bookkeeping and branch code generation.
            // =================================================
            {
                "Wait for debug event",

                {
            // -----------------------------------------
            // CE 7.5
            //
            // 0x74EB20 .. 0x74EB4D
            // -----------------------------------------
            maskedSignature(
                "Debugger WaitForDebugEvent - 7.5",
                {
                    // mov rax,[rbp+this]
                    0x48, 0x8B, 0x45, 0xF8,

                    // mov byte ptr [rax+0B8h],0
                    0xC6, 0x80,
                    0xB8, 0x00, 0x00, 0x00,
                    0x00,

                    // lea rcx,[rbp+debugEvent]
                    0x48, 0x8D, 0x8D,
                    0x48, 0xFF, 0xFF, 0xFF,

                    // timeout = 100 ms
                    0xBA,
                    0x64, 0x00, 0x00, 0x00,

                    // WaitForDebugEvent
                    0xE8,
                    0x00, 0x00, 0x00, 0x00,

                    // test eax,eax
                    0x85, 0xC0,

                    // jz timeout path
                    0x0F, 0x84,
                    0x00, 0x00, 0x00, 0x00,

                    // CONTINUESTATUS = DBG_CONTINUE
                    // 0x00010002
                    0xC7, 0x85,
                    0x3C, 0xFF, 0xFF, 0xFF,
                    0x02, 0x00, 0x01, 0x00
                },
                {
                    // WaitForDebugEvent rel32
                    24, 25, 26, 27,

                    // timeout-path branch displacement
                    32, 33, 34, 35
                }
            ),

                // -----------------------------------------
                // CE 7.4
                //
                // 0x7B7950 .. 0x7B7973
                // -----------------------------------------
                maskedSignature(
                    "Debugger WaitForDebugEvent - 7.4",
                    {
                        // lea rcx,[rbp+debugEvent]
                        0x48, 0x8D, 0x8D,
                        0x48, 0xFF, 0xFF, 0xFF,

                        // timeout = 100
                        0xBA,
                        0x64, 0x00, 0x00, 0x00,

                        // WaitForDebugEvent
                        0xE8,
                        0x00, 0x00, 0x00, 0x00,

                        0x85, 0xC0,

                        // jnz success
                        0x75, 0x05,

                        // jmp timeout path
                        0xE9,
                        0x00, 0x00, 0x00, 0x00,

                        // CONTINUESTATUS = DBG_CONTINUE
                        0xC7, 0x85,
                        0x3C, 0xFF, 0xFF, 0xFF,
                        0x02, 0x00, 0x01, 0x00
                    },
                    {
                        // WaitForDebugEvent
                        13, 14, 15, 16,

                        // timeout branch
                        22, 23, 24, 25
                    }
                )
            },

            0
        },

        // =================================================
        // Anchor 2
        //
        // Dispatch through CE's actual debugger event
        // handler:
        //
        // this->eventhandler->HandleDebugEvent(
        //     debugEvent,
        //     ContinueStatus
        // )
        //
        // This byte sequence is structurally IDENTICAL
        // across 7.5 and 7.4 except for the call rel32.
        // =================================================
        {
            "Dispatch debug event",

            {
                maskedSignature(
                    "Debugger HandleDebugEvent",
                    {
                        // mov rax,[rbp+this]
                        0x48, 0x8B, 0x45, 0xF8,

                        // mov rcx,[rax+48h]
                        // eventhandler
                        0x48, 0x8B, 0x48, 0x48,

                        // lea r8,[rbp+CONTINUESTATUS]
                        0x4C, 0x8D, 0x85,
                        0x3C, 0xFF, 0xFF, 0xFF,

                        // lea rdx,[rbp+debugEvent]
                        0x48, 0x8D, 0x95,
                        0x48, 0xFF, 0xFF, 0xFF,

                        // HandleDebugEvent
                        0xE8,
                        0x00, 0x00, 0x00, 0x00,

                        // DEBUGGING = result
                        0x88, 0x85,
                        0x44, 0xFF, 0xFF, 0xFF
                    },
                    {
                        23, 24, 25, 26
                    }
                )
            },

            60
        },

        // =================================================
        // Anchor 3
        //
        // CE-specific exception maintenance:
        //
        // if ContinueStatus ==
        //    DBG_EXCEPTION_NOT_HANDLED (0x80010001)
        //
        //     CleanupDeletedBreakpoints(true,true)
        //
        // State field differs:
        //
        //   7.5 -> [this+0xE8] = 4
        //   7.4 -> [this+0xC8] = 4
        // =================================================
        {
            "Handle unhandled debugger exception",

            {
            // -----------------------------------------
            // CE 7.5
            //
            // 0x74EBA9 .. 0x74EBD0
            // -----------------------------------------
            maskedSignature(
                "Debugger exception maintenance - 7.5",
                {
                    0x48, 0x8B, 0x45, 0xF8,

                    // state = 4
                    0xC7, 0x80,
                    0xE8, 0x00, 0x00, 0x00,
                    0x04, 0x00, 0x00, 0x00,

                    // ContinueStatus ==
                    // DBG_EXCEPTION_NOT_HANDLED
                    0x81, 0xBD,
                    0x3C, 0xFF, 0xFF, 0xFF,
                    0x01, 0x00, 0x01, 0x80,

                    // skip cleanup otherwise
                    0x75, 0x11,

                    0x48, 0x8B, 0x4D, 0xF8,

                    // r8b = true
                    0x41, 0xB0, 0x01,

                    // dl = true
                    0xB2, 0x01,

                    // CleanupDeletedBreakpoints
                    0xE8,
                    0x00, 0x00, 0x00, 0x00
                },
                {
                    36, 37, 38, 39
                }
            ),

                // -----------------------------------------
                // CE 7.4
                //
                // 0x7B79DC .. 0x7B7A05
                // -----------------------------------------
                maskedSignature(
                    "Debugger exception maintenance - 7.4",
                    {
                        0x48, 0x8B, 0x45, 0xF8,

                        // state = 4
                        0xC7, 0x80,
                        0xC8, 0x00, 0x00, 0x00,
                        0x04, 0x00, 0x00, 0x00,

                        // DBG_EXCEPTION_NOT_HANDLED
                        0x81, 0xBD,
                        0x3C, 0xFF, 0xFF, 0xFF,
                        0x01, 0x00, 0x01, 0x80,

                        // compiler emits:
                        // je +2
                        // jmp +0x10
                        0x74, 0x02,
                        0xEB, 0x10,

                        0x48, 0x8B, 0x4D, 0xF8,

                        0x41, 0xB0, 0x01,
                        0xB2, 0x01,

                        // CleanupDeletedBreakpoints
                        0xE8,
                        0x00, 0x00, 0x00, 0x00
                    },
                    {
                        38, 39, 40, 41
                    }
                )
            },

            11
        },

        // =================================================
        // Anchor 4
        //
        // ContinueDebugEvent(
        //     processId,
        //     threadId,
        //     ContinueStatus
        // )
        //
        // This encoding is again identical in 7.5/7.4
        // except for the call displacement.
        // =================================================
        {
            "Continue debug event",

            {
                maskedSignature(
                    "Debugger ContinueDebugEvent",
                    {
                        // thread id
                        0x8B, 0x95,
                        0x50, 0xFF, 0xFF, 0xFF,

                        // process id
                        0x8B, 0x8D,
                        0x4C, 0xFF, 0xFF, 0xFF,

                        // ContinueStatus
                        0x44, 0x8B, 0x85,
                        0x3C, 0xFF, 0xFF, 0xFF,

                        // ContinueDebugEvent
                        0xE8,
                        0x00, 0x00, 0x00, 0x00
                    },
                    {
                        20, 21, 22, 23
                    }
                )
            },

            3
        }
    },

    15
    };
}



std::vector<SignatureFamily>
MemorySignatureDefinitions::makeDefaultSignatureFamilies()
{
    return
    {
        makeFirstScanFamily(),
        makeFirstNextScanFamily(),
        makeNextNextScanFamily(),
        makeConfigureScanRoutineFamily(),
        makeAutoAssemblerExecutionFamily(),
        makeSpeedhackInitializationFamily(),
        makeDebuggerEventLoopFamily()
    };
}