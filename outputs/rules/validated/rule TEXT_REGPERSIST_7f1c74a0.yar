rule TEXT_REGPERSIST_7f1c74a0
{
    meta:
        author = "malware-analyst"
        description = "Text-log rule for cluster: heavy registry API usage + large rsrc section and matching PE header tokens (tuned to avoid provided benign neighbors). Target is text logs only."
        sha256 = "7f1c74a077fa497b902e29cf16f59377faa82d688d5ed967e68ba7c748756e5a"
        date = "2025-12-01"
        tlp = "white"

    strings:
        /* Registry + persistence APIs (high-signal) */
        $reg_setvalue   = "regsetvalueexw" ascii nocase
        $reg_createkey  = "regcreatekeyexw" ascii nocase
        $reg_open       = "regopenkeyexw" ascii nocase
        $reg_query      = "regqueryvalueexw" ascii nocase
        $reg_delete     = "regdeletevaluew" ascii nocase

        /* PE header tokens (text-log form) that are consistent across malware positives */
        $h_tstamp       = "TimeDateStamp is 1632607066" ascii
        $h_lfanew       = "e_lfanew is 216" ascii
        $h_numsec       = "NumberOfSections is 5" ascii
        $h_filealign    = "FileAlignment is 512" ascii

        /* Large resource region (distinctive in positives; benigns show much smaller rsrc_SizeOfRawData) */
        $rsrc_size      = "rsrc_SizeOfRawData is 165376" ascii
        $rsrc_ptr       = "rsrc_PointerToRawData is 35328" ascii

        /* Common support calls (useful for confidence but not standalone) */
        $advapi         = "advapi32.dll" ascii nocase
        $shell_exec     = "shellexecuteexw" ascii nocase

    condition:
        /*
         * Match only when:
         *  - evidence of registry persistence APIs (at least one set/create/open/query)
         *  - AND this specific PE header fingerprint (timestamp + e_lfanew + 5 sections + file alignment)
         *  - AND the unusually large resource region (size and pointer) observed in positives
         *  - AND at least one support call for extra confidence (advapi or shellexec)
         */
        ( $reg_setvalue or $reg_createkey or $reg_open or $reg_query or $reg_delete ) and
        $h_tstamp and $h_lfanew and $h_numsec and $h_filealign and
        $rsrc_size and $rsrc_ptr and
        ( $advapi or $shell_exec )
}
