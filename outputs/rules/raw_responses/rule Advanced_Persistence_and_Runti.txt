rule Advanced_Persistence_and_Runtime_Manipulation
{
    meta:
        author = "malware-analyst"
        description = "Detects binaries that combine runtime memory manipulation with uncommon persistence/interop/debug helper APIs (e.g. DLLInstall, RealShellExecuteEx, message-pump hook, symbol/image helpers). This behavioral combination reduces false positives against benign system apps."
        sha256_new_sample = "50977f9814be39f4ebc45c3ae255f33c2ba0a25c7b626fdbd9225a2fa458f33c"
        date = "2025-12-01"

    strings:
        /* common memory manipulation (behavioral focus) */
        $virtualalloc               = "virtualalloc" nocase
        $virtualprotect             = "virtualprotect" nocase
        $virtualfree                = "virtualfree" nocase

        /* uncommon/powerful persistence / install / shell APIs observed in malicious neighbors */
        $dllinstall                 = "dllinstall" nocase
        $realshellexecuteexw        = "realshellexecuteexw" nocase
        $registermessagepumphook    = "registermessagepumphook" nocase
        $setdebugerrorlevel         = "setdebugerrorlevel" nocase
        $coreactivateobject         = "coreactivateobject" nocase
        $stgmediumusermarshal       = "stgmediumusermarshal" nocase
        $cryptsignhashw             = "cryptsignhashw" nocase

        /* symbol/image helper APIs (often abuse/analysis tooling present in malware families) */
        $symfindfileinpath          = "symfindfileinpath" nocase
        $symenumeratesymbols        = "symenumeratesymbols" nocase
        $imagehlp_dll               = "imagehlp.dll" nocase

        /* anchor: presence of common Win32 system DLLs (not sufficient alone) */
        $advapi                     = "advapi32.dll" nocase
        $shell32                    = "shell32.dll" nocase

    condition:
        /*
         * Logic:
         *  - require memory-manipulation indicator (behavioral)
         *  - require presence of at least one common Win32 system DLL (anchor)
         *  - require at least two "uncommon/powerful" indicators (persistence/interop/debug helpers)
         *  - require at least one symbol/image helper OR imagehlp.dll (signals debug/symbol usage often seen in these malware neighbors)
         *
         * This reduces false positives from benign apps that reference kernel APIs but do not combine with persistence/interop/debug behavior.
         */
        ($virtualalloc or $virtualprotect or $virtualfree) and
        ( $advapi or $shell32 ) and
        2 of ( $dllinstall, $realshellexecuteexw, $registermessagepumphook, $setdebugerrorlevel, $coreactivateobject, $stgmediumusermarshal, $cryptsignhashw ) and
        1 of ( $symfindfileinpath, $symenumeratesymbols, $imagehlp_dll )
}
