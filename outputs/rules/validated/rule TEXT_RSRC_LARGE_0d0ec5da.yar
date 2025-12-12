rule TEXT_RSRC_LARGE_0d0ec5da
{
    meta:
        author = "malware-analyst"
        description = "Text-log detector for the large-RSRC / advapi32-backed cluster (matches header-value patterns seen in malicious neighbors but avoids benign header values)"
        sha256 = "0d0ec5da4b48240427f7df80e2d144e6eba3f4bc8527608f5f515c500f4ccc96"
        date = "2025-12-01"
        tlp = "white"

    strings:
        /* Core behavioral token (common in both positives) */
        $s_advapi         = "advapi32.dll" ascii nocase

        /* Large .text/.rsrc header fingerprints observed in malware cluster (text-log form) */
        $s_num_sections   = "NumberOfSections is 11" ascii
        $s_text_raw       = "text_SizeOfRawData is 571392" ascii
        $s_text_vs        = "text_Misc_VirtualSize is 571228" ascii
        $s_text_ptr       = "text_PointerToRawData is 1024" ascii

        $s_rsrc_ptr_big   = "rsrc_PointerToRawData is 639488" ascii
        $s_rsrc_size_big  = "rsrc_SizeOfRawData is 223232" ascii
        $s_rsrc_vs        = "rsrc_Misc_VirtualSize is 223232" ascii

        /* Large code / entrypoint indicators seen in malware neighbors */
        $s_size_of_code   = "SizeOfCode is 582656" ascii
        $s_entrypoint     = "AddressOfEntryPoint is 587760" ascii

        /* Additional supportive tokens from positive neighbors (windows/GDI usage patterns) */
        $s_sysalloc       = "sysallocstringlen" ascii nocase
        $s_lockresource   = "lockresource" ascii nocase

        /* Known small-rsrc benign values to exclude */
        $ex_rsrc_small1   = "rsrc_PointerToRawData is 42496" ascii
        $ex_rsrc_small2   = "rsrc_PointerToRawData is 41984" ascii

    condition:
        /*
         * Logic:
         *  - advapi32 present (cluster uses advapi32/oleaut32/ole32)
         *  - at least TWO large header tokens from the set (text/rsrc/code/header values)
         *  - plus at least ONE supportive token (entrypoint OR sysalloc/lockresource)
         *  - and explicitly exclude common small-rsrc benign pointers
         */
        $s_advapi and
        2 of (
            $s_text_raw, $s_text_vs, $s_text_ptr,
            $s_rsrc_ptr_big, $s_rsrc_size_big, $s_rsrc_vs,
            $s_size_of_code, $s_num_sections
        ) and
        ( $s_entrypoint or $s_sysalloc or $s_lockresource ) and
        not any of ( $ex_rsrc_small1, $ex_rsrc_small2 )
}
