rule Suspicious_Resource_Update_With_Memory_Protection_and_IPC_TextLog
{
    meta:
        author = "assistant"
        description = "Text-log detection: combines resource-update/enumeration APIs with memory-protection/allocation calls and uncommon IPC/replace operations. Focuses on behavioral P/Invoke indicators seen in malicious neighbors."
        reference_sha256 = "cfc94304bc6d7701b9fcbe790f55b61e648f4de7d93872bcdc2801487b31dec7"
        date = "2025-12-01"
        confidence = "90"
        tags = "resource-update, memory-protect, ipc, p/invoke, text-log"

    strings:
        /* resource enumeration / update indicators (malicious neighbors) */
        $res_enum_w         = "EnumResourceNamesW" nocase
        $res_find_ex_w      = "FindResourceExW" nocase
        $res_find_a         = "FindResourceA" nocase
        $res_begin_update_w = "BeginUpdateResourceW" nocase
        $res_begin_update_a = "BeginUpdateResourceA" nocase

        /* memory-protection / allocation APIs often used for mapping/execution */
        $mem_virtualprotect = "VirtualProtect" nocase
        $mem_virtualquery   = "VirtualQuery" nocase
        $mem_virtualalloc   = "VirtualAlloc" nocase

        /* IPC / persistence / uncommon file operations to distinguish benigns */
        $ipc_waitnamedpipe  = "WaitNamedPipeA" nocase
        $ipc_replacefile    = "ReplaceFileA" nocase
        $ipc_begin_update   = "BeginUpdateResource" nocase

    condition:
        /*
         * Require a combination of:
         *  - one resource-enumeration/update API (evidence of embedded resource manipulation)
         *  - one memory-protection/allocation API (evidence of mapping/execution)
         *  - one IPC/persistence or uncommon file operation (evidence of inter-process activity or tampering)
         */
        (1 of ($res_enum_w, $res_find_ex_w, $res_find_a, $res_begin_update_w, $res_begin_update_a))
        and (1 of ($mem_virtualprotect, $mem_virtualquery, $mem_virtualalloc))
        and (1 of ($ipc_waitnamedpipe, $ipc_replacefile, $ipc_begin_update))
}
