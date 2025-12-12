rule VB6_Suspicious_Memory_Resource_Interop
{
    meta:
        author = "malware-analyst"
        description = "Detects VB6 (msvbvm60) samples that combine VB runtime/event-sink symbols with memory allocation/protection and resource-loading APIs — behavioral combination to reduce false positives."
        sha256_new_sample = "5eaab373081a16275f8a096bdb725f1d9fccc3e6a93b2ca637f7b5cfe7026e2f"
        date = "2025-12-01"

    strings:
        /* runtime / loader */
        $msvbvm           = "msvbvm60.dll" nocase
        $oleaut           = "oleaut32.dll" nocase
        $shlwapi          = "shlwapi.dll" nocase

        /* memory / allocation / protection (behavioral) */
        $mem_valloc       = "virtualalloc" nocase
        $mem_vprot        = "virtualprotect" nocase
        $mem_vfree        = "virtualfree" nocase
        $mem_heapalloc    = "heapalloc" nocase
        $mem_rtlmovemem   = "rtlmovememory" nocase
        $mem_getprocessheap = "getprocessheap" nocase

        /* resource / persistence / installer-like behavior */
        $res_find         = "findresourcew" nocase
        $res_load         = "loadresource" nocase
        $res_lock         = "lockresource" nocase
        $res_sizeof       = "sizeofresource" nocase
        $sh_pathremove    = "pathremovefilespecw" nocase
        $sh_createdir     = "createdirectoryw" nocase

        /* VB-specific behavioral/event/cominterop indicators */
        $ev_qi            = "eventsinkqueryinterface" nocase
        $ev_addref        = "eventsinkaddref" nocase
        $ev_release       = "eventsinkrelease" nocase
        $vba_except       = "vbaexcepthandler" nocase
        $sysallocstr      = "sysallocstring" nocase
        $sysreallocstr    = "sysreallocstring" nocase

    condition:
        /*
         * Require:
         *  - explicit VB6 runtime import AND at least one contextual loader DLL (oleaut32 or shlwapi), AND
         *  - at least two memory/allocation/protection indicators, AND
         *  - at least one resource-handling OR VB event/cominterop indicator.
         */
        $msvbvm and ( $oleaut or $shlwapi ) and
        2 of ( $mem_valloc, $mem_vprot, $mem_vfree, $mem_heapalloc, $mem_rtlmovemem, $mem_getprocessheap ) and
        1 of ( $res_find, $res_load, $res_lock, $res_sizeof, $sh_pathremove, $sh_createdir, $ev_qi, $ev_addref, $ev_release, $vba_except, $sysallocstr, $sysreallocstr )
}
