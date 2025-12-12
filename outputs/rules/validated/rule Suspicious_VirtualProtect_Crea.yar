rule Suspicious_VirtualProtect_CreateThread_Memory_TLS_Combo
{
    meta:
        author = "malware-analyst"
        description = "Detects a behavioral combination seen in several malware neighbors: memory protection/modification + thread creation + dynamic API lookup + raw memory operations + TLS usage — indicative of in-memory unpacking, code-patching or injection."
        sha256_sample = "f2caf8e03be6e091da8a29850f1a373cb07721a5ff949ad2e31f12dcf2822847"
        date = "2025-12-04"
        tags = "behavioral,in-memory,unpack,code-injection"

    strings:
        /* memory protection / modification */
        $vp         = "VirtualProtect" nocase
        $vq         = "VirtualQuery" nocase
        $valloc     = "VirtualAlloc" nocase
        $vprotect_ex = "VirtualProtectEx" nocase

        /* thread/process / code-execution helpers */
        $ct         = "CreateThread" nocase
        $gp         = "GetProcAddress" nocase
        $llA        = "LoadLibraryA" nocase
        $llW        = "LoadLibraryW" nocase

        /* raw memory / copy / alloc helpers (writing shellcode / payloads) */
        $memcpy     = "memcpy" nocase
        $malloc     = "malloc" nocase
        $realloc    = "realloc" nocase
        $memmove    = "memmove" nocase
        $vfree      = "VirtualFree" nocase

        /* TLS usage (seen in malware neighbors, raises confidence) */
        $tls_alloc  = "TlsAlloc" nocase
        $tls_get    = "TlsGetValue" nocase
        $tls_set    = "TlsSetValue" nocase

    condition:
        /*
         * Core fingerprint:
         *  - memory-protection/modification API (VirtualProtect / VirtualQuery / VirtualAlloc / VirtualProtectEx)
         *  - thread creation (CreateThread)
         *  - dynamic API lookup or library load (GetProcAddress or LoadLibrary*)
         *  - raw memory write/alloc/free operations (memcpy / malloc / realloc / memmove / VirtualFree)
         *  - TLS usage (TlsAlloc / TlsGetValue / TlsSetValue)
         */
        ( any of ($vp, $vq, $valloc, $vprotect_ex) ) and
        $ct and
        any of ($gp, $llA, $llW) and
        any of ($memcpy, $malloc, $realloc, $memmove, $vfree) and
        any of ($tls_alloc, $tls_get, $tls_set)
}
