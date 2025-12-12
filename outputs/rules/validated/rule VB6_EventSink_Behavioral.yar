rule VB6_EventSink_Behavioral
{
    meta:
        author = "malware-analyst"
        description = "Detects VB6/MSVBVM60 binaries that show behavioral VB runtime indicators (event-sink/interop, dynamic DLL-call patterns). Combines runtime import with multiple VB-specific symbols to reduce false positives."
        sha256_new_sample = "3969849500b4456d9b648eeaf3f471fcbfeea14e323d3db643fc628b9ee2a586"
        date = "2025-12-01"

    strings:
        /* VB runtime / loader anchor */
        $msvb               = "msvbvm60.dll" nocase

        /* Event-sink / COM interop and runtime behavior */
        $events_qi          = "eventsinkqueryinterface" nocase
        $events_addref      = "eventsinkaddref" nocase
        $events_release     = "eventsinkrelease" nocase
        $vba_except         = "vbaexcepthandler" nocase
        $vbafreevarlist     = "vbafreevarlist" nocase
        $vbafreeobj         = "vbafreeobj" nocase
        $dllfunccall        = "dllfunctioncall" nocase
        $vbastrtoansi       = "vbastrtoansi" nocase
        $vbarecdestruct     = "vbarecdestruct" nocase
        $vbastrcopy         = "vbastrcopy" nocase
        $vbavarmove         = "vbavarmove" nocase

    condition:
        /*
         * Require the VB runtime import AND multiple VB behavioral indicators.
         * This avoids triggering on benign files that merely reference common system DLLs.
         */
        $msvb and 3 of ($events_qi, $events_addref, $events_release, $vba_except, $vbafreevarlist, $vbafreeobj, $dllfunccall, $vbastrtoansi, $vbarecdestruct, $vbastrcopy, $vbavarmove)
}
