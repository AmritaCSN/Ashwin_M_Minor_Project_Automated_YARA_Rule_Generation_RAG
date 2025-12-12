rule Win_Suspicious_Variant_CharUpper_Loadlib
{
    meta:
        author = "malware-analyst"
        description = "Behavioral text-log rule: detects samples that combine COM/automation type conversion calls with unusual string/GUI helper calls plus dynamic loader usage — seen across the provided malware neighbors. Avoids trivial hits on common runtime artifacts."
        sha256_sample = "55e79c0ae518b6440b2778a324c7874f2a689cea94d430e1b381eb4e20623261"
        date = "2025-12-04"
        tags = "behavioral, suspicious, loadlibrary, variant, charupper"

    strings:
        /* Rare/behavioral indicators observed in malware neighbors (COM/type & string manipulation) */
        $s_variantchangetypeex = "VariantChangeTypeEx" nocase
        $s_charupperbuffw     = "CharUpperBuffW" nocase
        $s_getsyscolorbrush   = "GetSysColorBrush" nocase

        /* Dynamic loader / resolution / module helpers (behavioral, not used alone) */
        $s_loadlibrarya       = "LoadLibraryA" nocase
        $s_getprocaddress     = "GetProcAddress" nocase
        $s_getmodulehandlea   = "GetModuleHandleA" nocase
        $s_raiseexception     = "RaiseException" nocase

    condition:
        /*
         * Match when:
         *  - the file/log contains the COM/type-conversion and string-manipulation indicators
         *    (these are uncommon in benign neighbors), AND
         *  - at least one dynamic loader / module-resolution API is present
         *
         * This reduces false positives from benign files that only contain generic runtime names
         * like "corexemain" or "GetProcAddress" by itself.
         */
        all of ($s_variantchangetypeex, $s_charupperbuffw, $s_getsyscolorbrush) and
        any of ($s_loadlibrarya, $s_getprocaddress, $s_getmodulehandlea, $s_raiseexception)
}
