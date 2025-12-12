rule Win_PE_RegPrivilege_Persistence
{
    meta:
        author = "expert-malware-analyst"
        description = "Detects Windows PE samples that combine registry modification APIs with token/privilege manipulation and persistence/launch helpers — behavioral signature to spot installer/elevation/backdoor patterns while avoiding matches on benign files that only use generic APIs."
        sha256_new_sample = "4539d9c199b2fb7c37b08ab4ef32c6edd3e3e26f53f2289fa6ef3eb970cf8970"
        date = "2025-12-01"

    strings:
        /** Registry modification / persistence-related strings **/
        $reg_set_value      = "regsetvalueexa" nocase
        $reg_create_key     = "regcreatekeyexa" nocase
        $reg_delete_value   = "regdeletevaluea" nocase
        $reg_delete_key     = "regdeletekeya" nocase
        $reg_query_value    = "regqueryvalueexa" nocase
        $reg_open_key       = "regopenkeyexa" nocase
        $reg_enum_value     = "regenumvaluea" nocase
        $reg_enum_key       = "regenumkeya" nocase

        /** Privilege / token manipulation (elevation/impersonation) **/
        $priv_adjust        = "adjusttokenprivileges" nocase
        $priv_lookup        = "lookupprivilegevaluea" nocase
        $priv_open_token    = "openprocesstoken" nocase

        /** Process / launch / persistence helpers **/
        $proc_create        = "createprocessa" nocase
        $shellexec_exa      = "shellexecuteexa" nocase
        $set_env            = "setenvironmentvariablea" nocase
        $set_file_sec       = "setfilesecuritya" nocase
        $create_thread      = "createthread" nocase
        $create_file        = "createfilea" nocase

        /** COM / automation usage often seen in installers/persistence */
        $cocreate           = "cocreateinstance" nocase
        $iid_from_string    = "iidfromstring" nocase

        /** More lateral/advanced indicators (optional) */
        $open_proc          = "openprocess" nocase
        $set_service_like   = "setservice" nocase

    condition:
        /*
         * Logic:
         *  - Require at least one registry persistence/modification API (group A)
         *  - Require at least two privilege/token APIs (group B) to indicate elevation behavior
         *  - Require at least one persistence/launch/com/service API (group C)
         */
        ( 1 of ($reg_set_value, $reg_create_key, $reg_delete_value, $reg_delete_key, $reg_query_value, $reg_open_key, $reg_enum_value, $reg_enum_key) )
        and
        ( 2 of ($priv_adjust, $priv_lookup, $priv_open_token, $open_proc) )
        and
        ( 1 of ($proc_create, $shellexec_exa, $set_env, $set_file_sec, $create_thread, $create_file, $cocreate, $iid_from_string, $set_service_like) )
}
