rule TEXT_MAL_WINMM_1f5c36da
{
    meta:
        author = "malware-analyst"
        description = "Text-log detector for a cluster using winmm.dll + playsounda combined with strict PE-header fingerprints to avoid benign matches."
        sha256_target = "1f5c36da5a61ae77cd1afebd01be90d1a875b0be7056abec586c731bdf61eff6"
        created = "2025-11-30"
        tlp = "white"

    strings:
        /* behavior / DLL signatures (text-log form) */
        $s_winmm       = "winmm.dll" ascii nocase
        $s_playsound   = "playsounda" ascii nocase

        /* precise header fingerprints that are shared across positive neighbors but differ in benigns */
        $h_tstamp      = "TimeDateStamp is 1067389871" ascii
        $h_lfanew224   = "e_lfanew is 224" ascii
        $h_text_raw    = "text_SizeOfRawData is 258560" ascii
        $h_sections3   = "NumberOfSections is 3" ascii
        $h_linker9     = "MajorLinkerVersion is 9" ascii

        /* additional corroborating header tokens (help avoid false positives) */
        $h_subsys5     = "MajorSubsystemVersion is 5" ascii
        $h_sizeimage   = "SizeOfImage is 282624" ascii

    condition:
        /*
         * Require the uncommon DLL+API pair (winmm.dll + playsounda) AND
         * at least three of the strict header fingerprints including the unique timestamp.
         * This reduces accidental matches to benign files that share common APIs.
         */
        $s_winmm and $s_playsound and
        $h_tstamp and
        ( $h_lfanew224 and $h_text_raw and ( $h_sections3 or $h_linker9 or $h_subsys5 or $h_sizeimage ) )
}
