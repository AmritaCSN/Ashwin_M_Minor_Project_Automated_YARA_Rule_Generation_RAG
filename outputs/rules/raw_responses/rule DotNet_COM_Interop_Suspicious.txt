rule DotNet_COM_Interop_Suspicious
{
    meta:
        author = "malware-analyst"
        description = "Detects .NET-stubbed PE (corexemain) that also embeds native Win32/COM libraries and COM/registry/service behavior — combination reduces false positives from benign .NET-only binaries."
        sha256_new_sample = "104ff8c9a13125d6652d1dd1d9158b1612cd92bf6bf1bd4e4b73f112ece7a159"
        date = "2025-12-01"

    strings:
        /* .NET loader stub */
        $core = "corexemain" nocase

        /* Native/COM-related imported DLL names observed in malicious neighbors */
        $advapi = "advapi32.dll" nocase
        $ole32  = "ole32.dll" nocase
        $shell  = "shell32.dll" nocase
        $comctl = "comctl32.dll" nocase
        $gdi    = "gdi32.dll" nocase
        $user32 = "user32.dll" nocase

        /* Behavioral COM / persistence / registry / service indicators (text-log matches) */
        $coinit        = "CoInitialize" nocase
        $cocreate      = "CoCreateInstance" nocase
        $regcreate     = "RegCreateKeyEx" nocase
        $regset        = "RegSetValueEx" nocase
        $create_svc    = "CreateService" nocase
        $shell_exec    = "ShellExecute" nocase

    condition:
        /*
         * Avoid matching benign .NET-only files by requiring:
         *  - the .NET stub marker (corexemain) AND
         *  - at least two native/COM DLL imports (advapi32/ole32/shell32/comctl32/gdi32/user32) AND
         *  - at least one behavioral COM/registry/service API string indicating native COM usage or persistence behavior.
         */
        $core and
        2 of ($advapi, $ole32, $shell, $comctl, $gdi, $user32) and
        1 of ($coinit, $cocreate, $regcreate, $regset, $create_svc, $shell_exec)
}
