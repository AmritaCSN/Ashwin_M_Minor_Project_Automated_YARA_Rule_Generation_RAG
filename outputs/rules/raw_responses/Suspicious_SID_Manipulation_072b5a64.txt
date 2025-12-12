rule Suspicious_SID_Manipulation_072b5a64
{
    meta:
        author = "malware-analyst"
        description = "Text-log detection for sample SHA256 072b5a64... — looks for SID/ACL token manipulation + CreateProcessAsUser indicators (text-only)."
        sha256 = "072b5a642b6810ae3b13de6aa8f9044d64556e6b9c0ee373a3a00969a8dcdc82"
        family = "unknown"
        created = "2025-11-30"
        threat = "suspicious"

    strings:
        $createproc_as_user      = "createprocessasuserw" nocase
        $set_entries_in_acl      = "setentriesinaclw" nocase
        $convertstr_sid_to_sid   = "convertstringsidtosidw" nocase
        $convert_sid_to_str      = "convertsidtostringsidw" nocase
        $copy_sid                = "copysid" nocase
        $write_process_memory    = "writeprocessmemory" nocase
        $revert_to_self          = "reverttoself" nocase
        $reg_disable_predef_cache= "regdisablepredefinedcache" nocase
        $set_kernel_obj_sec      = "setkernelobjectsecurity" nocase

    condition:
        // Text-log matching: require the highly specific CreateProcessAsUser string plus at least
        // two additional SID/ACL/token manipulation or process-memory modification indicators.
        // This avoids matching benign neighbors that use common registry/UI APIs.
        $createproc_as_user and 2 of (
            $set_entries_in_acl,
            $convertstr_sid_to_sid,
            $convert_sid_to_str,
            $copy_sid,
            $write_process_memory,
            $revert_to_self,
            $reg_disable_predef_cache,
            $set_kernel_obj_sec
        )
}
