rule Detect_Oleaut_PInvoke_WindowStation_8ad619f9
{
    meta:
        description = "Detects oleaut P/Invoke usage (variantchangetypeex) combined with native API patterns (GetProcessWindowStation, RaiseException, SendNotifyMessageA, dynamic resolution) — behavioral indicator of .NET native interop/injection."
        author = "malware-analyst"
        sha256 = "8ad619f9bcff4153558b1bea48da8024c720766ff2e4a855dd839165433b6d9b"
        family = "suspected-native-interop"

    strings:
        /* Behavioral / PInvoke indicators (strong) */
        $variant          = "variantchangetypeex" nocase
        $gpws             = "getprocesswindowstation" nocase
        $raiseexc         = "raiseexception" nocase
        $sendnotify       = "sendnotifymessagea" nocase

        /* Dynamic-resolution / module helpers */
        $getproc          = "getprocaddress" nocase
        $getmod           = "getmodulehandlea" nocase
        $loadliba         = "loadlibrarya" nocase

        /* DLL anchors (useful but never sufficient alone) */
        $oleaut32         = "oleaut32.dll" nocase
        $user32           = "user32.dll" nocase
        $kernel32         = "kernel32.dll" nocase

        /* Negative-context avoidance: common benign/.NET bootstrap artifacts */
        $mscoree          = "mscoree.dll" nocase
        $corexemain       = "corexemain" nocase

    condition:
        /* never trigger on benign .NET bootstrap alone */
        not ($mscoree or $corexemain) and

        /* require an oleaut presence (matches positive context) and at least one common DLL context */
        $oleaut32 and ( $user32 or $kernel32 ) and

        /*
         * Require:
         *  - at least 2 of the strong PInvoke/behavior strings (variant, gpws, raise, sendnotify)
         *  - and at least 1 dynamic-resolution helper (GetProcAddress/GetModuleHandleA/LoadLibraryA)
         */
        2 of ($variant, $gpws, $raiseexc, $sendnotify) and
        1 of ($getproc, $getmod, $loadliba)
}
