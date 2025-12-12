rule DOTNET_Persistence_FileEnum_CreateProc
{
    meta:
        author = "malware-analyst"
        description = "Detects .NET samples that combine runtime presence with registry persistence, file enumeration and process creation APIs — behavioral combination observed across the malware neighbors. Text/log rule (pure string matching). Avoids volatile PE header fields."
        sha256_sample = "692597a436a6408b4213c52594e3645af83db745f36c31b6f8e9732768c63843"
        date = "2025-12-04"
        tags = "dotnet, persistence, file-enum, createprocess, behavioral"

    strings:
        /* .NET runtime / loader hints (useful to detect managed->native P/Invoke usage) */
        $s_dotnet1      = "mscoree.dll" nocase
        $s_corexe       = "corexemain" nocase

        /* Registry persistence/modification (behavioral) */
        $s_reg_set      = "RegSetValueExA" nocase
        $s_reg_create   = "RegCreateKeyExA" nocase
        $s_reg_delete   = "RegDeleteKeyA" nocase
        $s_reg_query    = "RegQueryValueExA" nocase

        /* File enumeration / collection (commonly used for reconnaissance or staging) */
        $s_find_first   = "FindFirstFileA" nocase
        $s_find_next    = "FindNextFileA" nocase

        /* Process creation / execution (behavioral) */
        $s_create_proc  = "CreateProcessA" nocase
        $s_create_thread= "CreateThread" nocase

        /* UI / shell API often used by installers/dropper-like behavior (helps reduce false positives) */
        $s_shellexec    = "ShellExecuteA" nocase
        $s_shfileop     = "SHFileOperationA" nocase

    condition:
        /*
         * Require the combination of:
         *  1) evidence of a .NET runtime / managed host (to find P/Invoke scenarios)
         *  2) a registry persistence/modification API
         *  3) file-enumeration APIs
         *  4) and at least one execution/creation or shell action API
         */
        any of ($s_dotnet1, $s_corexe) and
        any of ($s_reg_*) and
        any of ($s_find_first, $s_find_next) and
        any of ($s_create_proc, $s_create_thread, $s_shellexec, $s_shfileop)
}
