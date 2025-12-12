rule Suspicious_Advapi_Kernel32_Combo_Impersonation
{
    meta:
        author = "malware-analyst"
        description = "Detects samples that combine advapi/kernel32 usage with impersonation, heap manipulation and job/IPC or unusual runtime helpers — behavioral combination seen in the provided malware neighbors."
        sha256_new_sample = "bedfffb784db4b18bf373195f4443f3fc10bf9f2f1eb5f2502dcc83a56919a48"
        date = "2025-12-01"

    strings:
        /* Strong behavioral indicator present in malware neighbors, not in benign set */
        $impersonate_anonymous = "impersonateanonymoustoken" nocase

        /* Heap / memory / runtime manipulation often abused for stealth */
        $heap_set_info        = "heapsetinformation" nocase
        $encode_pointer       = "encodepointer" nocase
        $decode_pointer       = "decodepointer" nocase
        $tls_alloc            = "tlsalloc" nocase

        /* Job / process control and IPC related (persistence / containment evasion) */
        $open_job_object      = "openjobobjecta" nocase
        $create_event_w       = "createeventw" nocase
        $set_handle_count     = "sethandlecount" nocase

        /* Common loader/resolution primitives (must be combined with behavioral indicators) */
        $getprocaddress       = "getprocaddress" nocase
        $loadlibrarya         = "loadlibrarya" nocase
        $advapi_dll           = "advapi32.dll" nocase
        $kernel32_dll         = "kernel32.dll" nocase

    condition:
        /*
         * Requirements:
         *  - Must contain the strong impersonation indicator (reduces false positives).
         *  - Must also show at least two other behavioral indicators from heap/runtime/job sets (includes loader helpers).
         *  - Require presence of advapi32.dll or kernel32.dll anchor (but not sufficient alone).
         */
        $impersonate_anonymous and
        ( 2 of ( $heap_set_info, $encode_pointer, $decode_pointer, $tls_alloc, $open_job_object, $create_event_w, $set_handle_count, $getprocaddress, $loadlibrarya ) ) and
        ( $advapi_dll or $kernel32_dll )
}
