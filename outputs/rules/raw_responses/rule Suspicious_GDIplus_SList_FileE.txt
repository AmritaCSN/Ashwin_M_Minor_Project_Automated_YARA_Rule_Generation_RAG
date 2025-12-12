rule Suspicious_GDIplus_SList_FileEnum_Combo
{
    meta:
        author = "malware-analyst"
        description = "Detects behavioral combination observed in the sample family: GDI+ image APIs used together with SList interlocked operations and file-enumeration (indicative of unusual image handling + low-level sync + enumeration behavior). Text/log rule — avoids volatile PE header fields and generic DLL-only matches."
        sha256_sample = "38cc012d2887b5122e94dd46d0e886e4ad85b2aaa36984c62d6641d5d85464e3"
        date = "2025-12-01"
        tags = "gdi+,slist,enumeration,behavioral"

    strings:
        /* GDI+ / image handling APIs observed in malicious neighbors */
        $gdip_load     = "GdipLoadImageFromFile" nocase
        $gdip_load_icm = "GdipLoadImageFromFileICM" nocase
        $gdip_height   = "GdipGetImageHeight" nocase
        $gdip_width    = "GdipGetImageWidth" nocase
        $gdip_clone    = "GdipCloneImage" nocase
        $gdip_free     = "GdipDisposeImage" nocase

        /* Low-level single-linked-list (SList) atomic ops (rare in benign apps) */
        $slist_push    = "InterlockedPushEntrySList" nocase
        $slist_flush   = "InterlockedFlushSList" nocase
        $slist_init    = "InterlockedPopEntrySList" nocase

        /* File enumeration / enumeration API often used with scanning/collection */
        $find_first_ex = "FindFirstFileExW" nocase
        $find_next     = "FindNextFileW" nocase

        /* Defensive: require at least one non-generic helper to avoid triggering on common CRT names */
        $console_mode  = "GetConsoleMode" nocase

    condition:
        /* Require a combination of behaviors (image handling + low-level sync + enumeration).
           This reduces false positives from benign tools that may call one category only. */
        ( any of ($gdip_*) ) and
        ( any of ($slist_*) ) and
        ( any of ($find_first_ex, $find_next) ) and

        /* At least one console/utility helper present in textual logs to ensure contextual runtime behavior */
        ( any of ($console_mode) )
}
