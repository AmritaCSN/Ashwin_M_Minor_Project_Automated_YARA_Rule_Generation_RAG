rule TEXT_MAL_CRTHREAD_WINHTTP_f2f15d19
{
    meta:
        author = "malware-analyst"
        description = "Text-log YARA: detects cluster with CreateRemoteThread + WinHTTP usage and strict header/data-size fingerprints to avoid benign matches."
        sha256_target = "f2f15d197990af6048c3aea6ceaf016ee80a23ee0997782e2289b524cfcac56a"
        created = "2025-11-30"
        tlp = "white"

    strings:
        /* behavior / API / DLL tokens (text-log form) */
        $s_crt            = "createremotethread" ascii nocase
        $s_winhttp_dll    = "winhttp.dll" ascii nocase
        $s_winhttp_func   = "winhttpsetdefaultproxyconfiguration" ascii nocase
        $s_updateres      = "updateresourcea" ascii nocase
        $s_alpha_blend    = "alphablend" ascii nocase

        /* precise header / PE-like text tokens seen in positives (useful in text logs) */
        $h_lfanew240      = "e_lfanew is 240" ascii
        $h_sections4      = "NumberOfSections is 4" ascii
        $h_tstamp_1602435 = "TimeDateStamp is 1602435009" ascii
        $h_sizeimage_big  = "SizeOfImage is 42070016" ascii
        $h_data_misc_big  = "data_Misc_VirtualSize is 41938532" ascii
        $h_data_raw_size  = "data_SizeOfRawData is 119808" ascii

    condition:
        /*
         * Require the uncommon combination: CreateRemoteThread present in the text log
         * together with WinHTTP (DLL or specific WinHTTP API), plus at least two strict
         * header/data-size fingerprints (including timestamp or lfanew) to reduce false positives
         * against benign neighbors that share many common APIs.
         */
        $s_crt and ($s_winhttp_dll or $s_winhttp_func) and
        (
            ( $h_tstamp_1602435 and $h_lfanew240 ) or
            ( $h_sections4 and $h_data_misc_big ) or
            ( $h_sizeimage_big and $h_data_raw_size )
        ) and
        /* require at least one corroborating uncommon token from the binary's behavior */
        ( $s_updateres or $s_alpha_blend )
}
