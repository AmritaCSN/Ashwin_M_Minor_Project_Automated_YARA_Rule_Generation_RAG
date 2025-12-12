rule TEXT_VIRTUALALLOCEX_MFC42_5bc61504
{
    meta:
        author = "malware-analyst"
        description = "Text-log rule: detects the cluster characterized by VirtualAllocEx + mfc42.dll with specific PE header tokens (e_lfanew 248, TimeDateStamp 1559137742) — tuned to avoid provided benign neighbors."
        reference_sha256 = "5bc61504025da2754aec94a0fdedea884fef63435894cb0015565c684d5cef20"
        created = "2025-12-01"
        tlp = "white"

    strings:
        /* High-signal API / DLL markers (from positives) */
        $s_valloc         = "virtualallocex" ascii nocase
        $s_mfc42          = "mfc42.dll" ascii nocase
        $s_loadlib        = "loadlibrarya" ascii nocase

        /* Precise PE-text tokens that appear in the positive cluster (text-log form) */
        $h_lfanew_248     = "e_lfanew is 248" ascii
        $h_tstamp_1559    = "TimeDateStamp is 1559137742" ascii
        $h_numsec_4       = "NumberOfSections is 4" ascii
        $h_filealign_4096 = "FileAlignment is 4096" ascii

        /* Resource table specifics unique to this cluster (helps avoid benign overlaps) */
        $r_rsrc_ptr       = "rsrc_PointerToRawData is 274432" ascii
        $r_rsrc_size      = "rsrc_SizeOfRawData is 2560" ascii

        /* GUI/GDI usage strings (present across positives, less common in benign set) */
        $g_bitblt         = "bitblt" ascii nocase
        $g_drawtext       = "drawtexta" ascii nocase

    condition:
        /*
         * Mandatory high-confidence markers:
         *  - API/DLL pair (virtualallocex + mfc42.dll) seen in positives
         *  - exact TimeDateStamp for this cluster (prevents matching benign files)
         *  - exact e_lfanew value and 4-section layout
         *  - exact FileAlignment value for higher specificity
         *
         * Additionally require either the resource pointer/size that matches the sample
         * or one GUI/GDI token or loadlibrary token to increase confidence.
         */
        $s_valloc and $s_mfc42 and $h_tstamp_1559 and $h_lfanew_248 and $h_numsec_4 and $h_filealign_4096 and
        (
            ($r_rsrc_ptr or $r_rsrc_size) or
            ( $g_bitblt or $g_drawtext or $s_loadlib )
        )
}
