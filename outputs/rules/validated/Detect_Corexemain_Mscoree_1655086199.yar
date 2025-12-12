rule Detect_DotNet_Loader_Behavioral
{
    meta:
        description = "Detects .NET Malware (corexemain/mscoree) that attempts unmanaged memory manipulation or persistence. Replaces brittle metadata checks with behavioral indicators."
        author = "malware-analyst"
        date = "2025-12-01"
        confidence = "High"

    strings:
        /* 1. Context: Indicators of a .NET Executable */
        $net_marker_1 = "mscoree.dll"
        $net_marker_2 = "corexemain"

        /* 2. Suspicious APIs: Unmanaged/Native calls inside .NET are often malware loaders */
        $suspicious_1 = "virtualalloc"
        $suspicious_2 = "writeprocessmemory"
        $suspicious_3 = "createremotethread"
        $suspicious_4 = "getprocaddress"
        $suspicious_5 = "loadlibrary"
        
        /* 3. Persistence: Registry Manipulation */
        $persist_1    = "regcreatekey"
        $persist_2    = "regsetvalue"

        /* 4. Benign Filters: Strings found in safe Microsoft .NET libraries */
        $safe_1       = "Microsoft Corporation"
        $safe_2       = "Assembly Copyright"
        $safe_3       = "InternalName" // Common in legit compiled metadata

    condition:
        /* LOGIC: 
           1. Must be a .NET file ($net_marker)
           2. AND must utilize suspicious native APIs (indicating a loader/packer)
           3. AND must NOT be a signed/standard Microsoft file
        */
        
        any of ($net_marker_*)
        
        and (
            2 of ($suspicious_*) or 
            all of ($persist_*)
        )
        
        and not any of ($safe_*)
}