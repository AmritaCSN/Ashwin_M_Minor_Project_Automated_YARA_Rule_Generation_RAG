rule Win32_Suspicious_Memory_IPC_Debug
{
    meta:
        author = "expert-malware-analyst"
        description = "Detects suspicious combination of memory-manipulation (VirtualAlloc/VirtualProtect), IPC/object APIs (OpenFileMapping/CreateIoCompletionPort/OpenWaitableTimer) and debugger-control APIs — seen across provided malware neighbors. Reduces false positives by requiring multiple behavioral indicators rather than generic kernel32 usage."
        sha256_new_sample = "4908a123314e068f7823c102f4de7c4445b62a5ca191b1c495b782da75bd1627"
        date = "2025-12-01"

    strings:
        /* Memory / code-injection related */
        $virtual_alloc      = "virtualalloc" nocase
        $virtual_protect    = "virtualprotect" nocase
        $virtual_free       = "virtualfree" nocase
        $get_thread_ctx     = "getthreadcontext" nocase

        /* IPC / synchronization / advanced object APIs (behavioral) */
        $open_file_mapping  = "openfilemappinga" nocase
        $open_wait_timer    = "openwaitabletimera" nocase
        $create_iocp        = "createiocompletionport" nocase
        $create_named_pipe  = "createnamedpipea" nocase

        /* Debug / anti-analysis indicators */
        $is_debug_present   = "isdebuggerpresent" nocase
        $debug_break        = "debugbreak" nocase
        $cont_debug_event   = "continuedebugevent" nocase
        $wait_for_debug     = "waitfordebugevent" nocase

        /* Helper: presence of many low-level Win32 runtime calls (not sufficient alone) */
        $kernel32_like      = "kernel32.dll" nocase

    condition:
        /*
         * Logic:
         *  - Require at least TWO memory-manipulation indicators (common in injection/payload unpacking)
         *    AND
         *  - At least ONE IPC/synchronization/advanced-object API (indicates inter-process interaction or advanced resource usage)
         *    AND
         *  - At least ONE debug/anti-analysis indicator (debugbreak/continuedebugevent/isdebuggerpresent/etc.)
         *  - AND a contextual kernel32.dll anchor (used here as contextual evidence)
         */
        ( (1 of ($virtual_alloc, $virtual_protect, $virtual_free, $get_thread_ctx)) and
          (2 of ($virtual_alloc, $virtual_protect, $virtual_free, $get_thread_ctx)) and
          (1 of ($open_file_mapping, $open_wait_timer, $create_iocp, $create_named_pipe)) and
          (1 of ($is_debug_present, $debug_break, $cont_debug_event, $wait_for_debug)) and
          ($kernel32_like)
        )
}
