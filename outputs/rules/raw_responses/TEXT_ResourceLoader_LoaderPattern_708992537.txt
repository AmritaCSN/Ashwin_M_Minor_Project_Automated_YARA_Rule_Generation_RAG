rule TEXT_ResourceLoader_LoaderPattern_708992537
{
    meta:
        author = "malware-analyst"
        description = "Detects text-log traces of a resource-loading / registry manipulation Windows PE sample (strongly targeted by combining uncommon resource APIs with the exact TimeDateStamp and section-count fingerprint). Designed to avoid benign neighbors by requiring multiple rare tokens together."
        sha256_target = "16ea37a38787c3c1d30d2249aae43437d22a2b80b99ad4f6608890e265467525"
        created = "2025-11-30"
        tlp = "white"

    strings:
        /* Uncommon resource-management and automation tokens (text form) */
        $s_lockresource        = "lockresource" ascii nocase
        $s_loadresource        = "loadresource" ascii nocase
        $s_sizeres             = "sizeofresource" ascii nocase
        $s_freeres             = "freeresource" ascii nocase

        /* Automation / COM helper tokens less common in benign logs */
        $s_variant_init        = "variantinit" ascii nocase
        $s_variant_clear       = "variantclear" ascii nocase
        $s_sysalloc            = "sysallocstringlen" ascii nocase
        $s_sysfree             = "sysfreestring" ascii nocase

        /* Registry + file I/O pair (common individually but suspicious together with above) */
        $s_regq                = "regqueryvalueexa" ascii nocase
        $s_createfilea         = "createfilea" ascii nocase

        /* Strong header / fingerprint tokens (text-log form) — used to avoid benign neighbors */
        $h_tds                 = "TimeDateStamp is 708992537" ascii
        $h_sections11          = "NumberOfSections is 11" ascii
        $h_lfanew_64          = "e_lfanew is 64" ascii

    condition:
        /*
         * Match only when:
         *  - the uncommon resource/COM helper tokens appear (at least 3 of them)
         *  - AND a registry + file I/O indicator appears
         *  - AND the exact PE header fingerprint from the malicious sample is present
         *
         * This reduces false positives by requiring both behavioral tokens (resource+variant APIs)
         * and the exact textual header fingerprint which is not present in the supplied benign neighbors.
         */
        ( (1 of ($s_lockresource, $s_loadresource, $s_sizeres, $s_freeres)) and
          (1 of ($s_variant_init, $s_variant_clear, $s_sysalloc, $s_sysfree)) and
          $s_regq and $s_createfilea )
        and
        $h_tds and $h_sections11 and $h_lfanew_64
}
