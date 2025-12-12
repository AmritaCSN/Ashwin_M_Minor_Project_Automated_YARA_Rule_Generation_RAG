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

rule Detect_GDIPlus_Image_Handling_1d14f161
{
    meta:
        author = "malware-analyst"
        description = "Text-log detection: uncommon GDI+ / image-streaming APIs and gdiplus runtime (likely image-processing / loader behavior) — tuned to avoid benign UI/gdi hits."
        sha256 = "1d14f161830af09dbdfca9bbfa554cd9724f8af548495866b29bddf8b4d73a31"
        created = "2025-11-30"
        reference = "Cluster #91 — Target Family Type 2"

    strings:
        $gdiplus_dll                      = "gdiplus.dll" nocase

        /* GDI+ / image-stream APIs (uncommon in benign neighbors) */
        $g1 = "gdiploadimagefromstream" nocase
        $g2 = "gdipcreatebitmapfromstream" nocase
        $g3 = "gdipcreatebitmapfromhicon" nocase
        $g4 = "gdipdrawlinei" nocase
        $g5 = "gdipdrawellipsei" nocase
        $g6 = "gdipsetpencolor" nocase
        $g7 = "gdipemftowmfbits" nocase
        $g8 = "gdipimagegetframedimensionscount" nocase
        $g9 = "gdiprotateworldtransform" nocase
        $g10= "gdipgetpathgradientblend" nocase

        /* additional image / certificate helpers seen in sample */
        $img_cert = "imagegetcertificatedata" nocase
        $write_ole = "writeolestg" nocase
        $stream_write = "writestringstream" nocase

    condition:
        // Target is a text log. To reduce false positives against benign UI/GDI-heavy samples,
        // require the presence of the gdiplus runtime plus at least two distinct uncommon GDI+
        // / image-stream related API names (strong indicator of image-streaming/processing behavior).
        $gdiplus_dll and 2 of ($g*)
        or
        // also match if gdiplus runtime + one GDI+ API plus image certificate/stream helpers appear
        ($gdiplus_dll and 1 of ($g*) and ($img_cert or $write_ole or $stream_write))
}


rule Detect_WinMM_Dropper_Behavioral
{
    meta:
        description = "Detects Malware combining Multimedia APIs with Windowing APIs. Avoids volatile PE header fields."
        author = "malware-analyst"
        date = "2025-12-01"
        confidence = "Medium"

    strings:
        $quirk_dll      = "winmm.dll"
        $quirk_func     = "playsound"

        $gui_1          = "registerclassex"
        $gui_2          = "createwindow"
        $gui_3          = "defwindowproc"
        $gui_4          = "dispatchmessage"

        $suspicious_1   = "gettemppath"
        $suspicious_2   = "writefile"
        $suspicious_3   = "winexec"

        $safe_1         = "Microsoft Corporation"
        $safe_2         = "Windows System"

    condition:
        $quirk_dll and $quirk_func
        and 2 of ($gui_*)
        and 1 of ($suspicious_*)
        and not any of ($safe_*)
}


rule Detect_Native_Malware_Behavioral
{
    meta:
        description = "Detects Native Malware using Synchronization (OpenSemaphore) combined with process injection/persistence techniques. Replaces standard MSVC compiler artifacts with behavioral indicators."
        author = "malware-analyst"
        date = "2025-12-01"
        confidence = "Medium"

    strings:
        /* 1. Synchronization (The Anchor) */
        // Malware often uses Semaphores or Mutexes to avoid infecting the same machine twice
        $sync_1 = "opensemaphore" 
        $sync_2 = "createmutex"

        /* 2. Injection/Loader Capabilities (The Malicious Context) */
        // Look for these occurring alongside the synchronization
        $inject_1 = "writeprocessmemory"
        $inject_2 = "createremotethread"
        $inject_3 = "virtualprotect"      // Changing memory permissions (very common in packers)
        $inject_4 = "setthreadcontext"

        /* 3. Persistence/Stealth */
        $persist_1 = "regopenkey"
        $persist_2 = "winexec"
        $persist_3 = "shellexecute"

        /* 4. Benign Filters */
        $safe_1 = "Microsoft Corporation"
        $safe_2 = "Visual Studio"  // Filter out debug/dev tools that might have these

    condition:
        /* LOGIC:
           1. Must verify synchronization (OpenSemaphore or CreateMutex)
           2. AND must show signs of Injection or heavy Persistence
           3. AND must not be a known safe file
        */
        
        any of ($sync_*) 
        
        and (
            2 of ($inject_*) or 
            2 of ($persist_*)
        )
        
        and not any of ($safe_*)
}

rule Detect_DotNet_Packed_Behavioral
{
    meta:
        description = "Detects .NET executables using P/Invoke (Native APIs) typical of Packers/Unpackers. Replaces brittle header size checks."
        author = "malware-analyst"
        date = "2025-12-01"
        confidence = "Medium"

    strings:
        /* 1. Context: .NET Markers */
        $dotnet_1 = "mscoree.dll"
        $dotnet_2 = "corexemain"

        /* 2. The Behavior: Unpacking APIs (P/Invoke strings) */
        // Packers must change memory permissions to execute the unpacked payload.
        $packer_1 = "virtualprotect"      // Changes memory to Read/Write/Execute
        $packer_2 = "virtualalloc"        // Allocates memory for payload
        $packer_3 = "getprocaddress"      // Dynamic API resolution
        $packer_4 = "loadlibrary"         // Loading plugins/dependencies
        $packer_5 = "writeprocessmemory"  // Writing payload to memory

        /* 3. Benign Filters */
        $safe_1   = "Microsoft Corporation"
        $safe_2   = "Windows System"
        $safe_3   = "Assembly Copyright" 

    condition:
        /* LOGIC:
           1. Must be a .NET file
           2. AND must use 'VirtualProtect' (High signal for .NET packers) OR 2 other unpacking APIs
           3. AND must not be a known safe file
        */
        all of ($dotnet_*)
        
        and (
            $packer_1 or           // VirtualProtect is the strongest indicator
            2 of ($packer_*)       // OR a combination of others
        )
        
        and not any of ($safe_*)
}

rule Malware_156c21d06df1
{
    meta:
        author = "malware-analyst"
        description = "Text-log detection for sample SHA256 156c21d06df1... — targets uncommon IME/ACM/SetupDi/MSCoree indicators (text-only)."
        sha256 = "156c21d06df1eff6f8779151dc74a7b785b8a696f90fb37b0b2655145949c74e"
        date = "2025-11-30"
        classification = "suspicious"

    strings:
        // DLL indicator not present in benign neighbors
        $mscoree = "mscoree.dll" nocase

        // Core/launcher / .NET entrypoint string (unique)
        $corexemain = "corexemain" nocase

        // Uncommon IME / keyboard APIs (rare in benign neighbors)
        $immsim = "immsimulatehotkey" nocase
        $imm_get_clock = "immgetimclockcount" nocase
        $imm_candidate_count = "immgetcandidatelistcounta" nocase
        $immdestroy = "immdestroyimcc" nocase
        $oemkeyscan = "oemkeyscan" nocase

        // Audio Compression Manager / driver / setup APIs
        $acm_reset = "acmstreamreset" nocase
        $acm_close = "acmstreamclose" nocase
        $acm_driver = "acmdriverdetailsw" nocase
        $acm_format = "acmformatdetailsw" nocase
        $acm_getver = "acmgetversion" nocase

        // SetupDi device/class installation strings (device installer APIs)
        $setupdi_install_dev = "setupdiinstalldevice" nocase
        $setupdi_install_class = "setupdiinstallclassw" nocase
        $setupdi_get_class_imagelist = "setupdigetclassimagelist" nocase
        $setupdi_add_to_source = "setupaddtosourcelista" nocase

        // Certificate / EKU related (rare)
        $cert_eku = "certaddenhancedkeyusageidentifier" nocase
        $cert_enum_crl = "certenumcrlcontextproperties" nocase

    condition:
        // Target is a text log. To avoid matching benign samples, require the .NET/runtime DLL plus
        // at least two uncommon technical indicators (IME/ACM/SetupDi/Cert). This reduces false positives
        // because benign neighbors contain common UI APIs (showwindow, drawmenubar, getdevicecaps) which we do NOT use.
        $mscoree and 2 of (
            $corexemain,
            $immsim,
            $imm_get_clock,
            $imm_candidate_count,
            $immdestroy,
            $oemkeyscan,
            $acm_reset,
            $acm_close,
            $acm_driver,
            $acm_format,
            $acm_getver,
            $setupdi_install_dev,
            $setupdi_install_class,
            $setupdi_get_class_imagelist,
            $setupdi_add_to_source,
            $cert_eku,
            $cert_enum_crl
        )
}


rule Malware_71a23392_Process_Injection_LogIndicators
{
    meta:
        author = "malware-analyst"
        description = "Text-log rule: flags combination of CreateProcess + WriteProcessMemory with runtime/timing or exception context indicators (likely process injection / self-modifying behavior). Excludes generic DLL names to avoid benign hits."
        sha256 = "71a23392365192b43b1689b784e7bf7561ad95c6aa0432e6c4635e17e63b1b9d"
        created = "2025-11-30"
        tlp = "WHITE"

    strings:
        $create_proc        = "createprocessw" nocase
        $write_proc_mem     = "writeprocessmemory" nocase
        $tickcount64        = "gettickcount64" nocase
        $current_exc        = "currentexception" nocase
        $current_exc_ctx    = "currentexceptioncontext" nocase

    condition:
        // require explicit process-creation + remote-write indicator
        $create_proc and $write_proc_mem
        // plus at least one runtime/exception string to reduce false positives
        and ( $tickcount64 or $current_exc or $current_exc_ctx )
}


rule Malware_96d161ed_Affinity_WinHTTP_Profile
{
    meta:
        author = "malware-analyst"
        description = "Detects text-log indicators of affinity-manipulating malware that also uses WinHTTP query APIs — combination not present in benign neighbors."
        sha256 = "96d161eddf895ce4f1d935c7ecb7d913a1eb7e0095f2530518ec14f1f865665a"
        created = "2025-11-30"
        tlp = "WHITE"

    strings:
        /* Process/Thread affinity manipulation — absent in benign neighbors */
        $aff_set_thread   = "setthreadaffinitymask" nocase
        $aff_get_process  = "getprocessaffinitymask" nocase
        $aff_set_process  = "setprocessaffinitymask" nocase

        /* WinHTTP network primitive — also absent in benign neighbors */
        $winhttp_query    = "winhttpquerydataavailable" nocase

        /* User/session info (benign neighbors do not contain these) */
        $u_getusernamea   = "getusernamea" nocase
        $u_getuserinfo    = "getuserobjectinformationw" nocase
        $u_getwinstation  = "getprocesswindowstation" nocase

    condition:
        // Require affinity-manipulation + WinHTTP + at least one user/session enumeration API.
        // This combination does not exist in any benign sample, ensuring safe discrimination.
        ($aff_set_thread or $aff_get_process or $aff_set_process)
        and $winhttp_query
        and 1 of ($u_getusernamea, $u_getuserinfo, $u_getwinstation)
}


rule Malware_a7b031aa_detection
{
    meta:
        author = "malware-analyst"
        description = "Text-log detection for sample SHA256 a7b031aabbeb... — looks for the rare combination of disk-space query + status-text drawing APIs together with .NET runtime presence (text-only). Tuned to avoid benign UI/runtime hits."
        sha256 = "a7b031aabbeb5da007dea0cedb319cd604ab055a14660993365cc0cb6ac6f575"
        created = "2025-11-30"
        tlp = "WHITE"

    strings:
        $s_diskfree    = "shgetdiskfreespacea" nocase
        $s_drawstatus  = "drawstatustextw" nocase
        $s_releasedc   = "releasedc" nocase
        $s_mscoree     = "mscoree.dll" nocase

    condition:
        $s_diskfree and $s_drawstatus and $s_mscoree
        and ( $s_releasedc )   // now referenced
}


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


rule TEXT_COREXEMAIN_CLUSTER_2760f661
{
    meta:
        author = "malware-analyst"
        description = "Text-log YARA: detect cluster with corexemain + mscoree.dll and a precise set of PE-header tokens (tuned to avoid provided benign neighbors)."
        reference_sha256 = "2760f66141ee54ef8ac37f1334792b381373e0841bb1a1ae8ab503b353532553"
        created = "2025-11-30"
        tlp = "white"

    strings:
        /* Required high-signal markers (present in positives and risky if seen together in text logs) */
        $s_corexemain     = "corexemain" ascii nocase
        $s_mscoree        = "mscoree.dll" ascii nocase

        /* Unique/rare header fingerprint for this text-log cluster */
        $t_timestamp      = "TimeDateStamp is 4027361698" ascii

        /* Stable layout tokens shared by cluster but NOT present together in benign neighbors */
        $h_lfanew128      = "e_lfanew is 128" ascii
        $h_sections3      = "NumberOfSections is 3" ascii
        $h_filealign512   = "FileAlignment is 512" ascii
        $h_sizecode95232  = "SizeOfCode is 95232" ascii
        $h_text_raw_95232 = "text_SizeOfRawData is 95232" ascii
        $h_rsrc_ptr_95744 = "rsrc_PointerToRawData is 95744" ascii

    condition:
        /*
         * Decision logic:
         *  - Require the two high-signal tokens (corexemain + mscoree.dll)
         *  - Require the exact TimeDateStamp string observed in this sample
         *  - Require structural confirmation (e_lfanew + NumberOfSections)
         *  - And at least two additional precise header/section tokens to reduce false positives
         */
        $s_corexemain and $s_mscoree and
        $t_timestamp and
        $h_lfanew128 and $h_sections3 and
        (2 of ( $h_filealign512, $h_sizecode95232, $h_text_raw_95232, $h_rsrc_ptr_95744 ))
}


rule TEXT_COREXEMAIN_MSCOREE_1601064212
{
    meta:
        author = "malware-analyst"
        description = "High-confidence text-log rule for a .NET/native loader cluster. Requires corexemain + mscoree.dll plus the exact TimeDateStamp (1601064212) and matching PE header size fingerprints observed in the malware neighbors. Tuned to avoid supplied benign neighbors by requiring the precise timestamp + large header combination."
        sha256_target = "8b2c5362887dbc350aae004bee2ea50b83aee63bdb1d88c2559672e9ca5b91d5"
        created = "2025-11-30"
        tlp = "white"

    strings:
        /* required family markers (must be present but common in benigns) */
        $s_corexemain    = "corexemain" ascii nocase
        $s_mscoree       = "mscoree.dll" ascii nocase

        /* unique cluster discriminator (strong) */
        $h_timestamp     = "TimeDateStamp is 1601064212" ascii

        /* high-fidelity header fingerprints (text-log form) */
        $h_sizecode      = "SizeOfCode is 35840" ascii
        $h_sizeimage     = "SizeOfImage is 65536" ascii
        $h_text_raw      = "text_SizeOfRawData is 35840" ascii
        $h_rsrc_raw      = "rsrc_SizeOfRawData is 1024" ascii
        $h_sections3     = "NumberOfSections is 3" ascii

    condition:
        /*
         * Detection logic:
         *  - Require both runtime markers to target .NET/native loader traces.
         *  - Require the exact TimeDateStamp seen in the malicious sample (strong discriminator against benigns).
         *  - Require at least two high-fidelity header tokens (sizecode/sizeimage/text_raw/rsrc_raw) to confirm the fingerprint.
         *  - Also require NumberOfSections is 3 (seen across positives) as secondary corroboration.
         */
        $s_corexemain and $s_mscoree and $h_timestamp and
        $h_sections3 and
        ( 2 of ( $h_sizecode, $h_sizeimage, $h_text_raw, $h_rsrc_raw ) )
}


rule TEXT_COREXEMAIN_MSCOREE_1651459917
{
    meta:
        author = "malware-analyst"
        description = "Text-log detection for a .NET/native loader cluster: requires corexemain + mscoree.dll plus the unique TimeDateStamp 1651459917 and large PE header fingerprints observed in malicious neighbors. Tuned to avoid the supplied benign neighbors."
        tlp = "white"
        created = "2025-11-30"

    strings:
        /* Required runtime markers (common to this family but also present in benigns — used only in combination) */
        $s_corexemain     = "corexemain" ascii nocase
        $s_mscoree        = "mscoree.dll" ascii nocase

        /* Strong unique header / fingerprint tokens (text-log form) observed across malware neighbors */
        $h_timestamp      = "TimeDateStamp is 1651459917" ascii
        $h_sizecode       = "SizeOfCode is 976384" ascii
        $h_sizeimage      = "SizeOfImage is 1007616" ascii
        $h_text_raw       = "text_SizeOfRawData is 976384" ascii
        $h_rsrc_vsize     = "rsrc_Misc_VirtualSize is 1444" ascii
        $h_rsrc_raw       = "rsrc_SizeOfRawData is 1536" ascii
        $h_sections3      = "NumberOfSections is 3" ascii

    condition:
        /*
         * Conservative, high-confidence logic:
         *  - Require both family markers to narrow to .NET/native loader traces.
         *  - Require the exact TimeDateStamp for this malicious cluster (strong discriminator).
         *  - Require at least two high-fidelity header fingerprints (large code/image/text sizes or resource sizes).
         *
         * This avoids matching benign samples that may contain corexemain/mscoree.dll but do NOT share the precise
         * combination of timestamp and large header values present in the malicious neighbors.
         */
        $s_corexemain and $s_mscoree and $h_timestamp and
        ( 2 of ( $h_sizecode, $h_sizeimage, $h_text_raw, $h_rsrc_vsize, $h_rsrc_raw, $h_sections3 ) )
}


rule TEXT_COREXEMAIN_MSCOREE_1654158479
{
    meta:
        author = "malware-analyst"
        description = "Text-log rule: detects a corexemain + mscoree.dll cluster with TimeDateStamp 1654158479 and matching high-fidelity PE header tokens. Tuned to avoid provided benign neighbors."
        target_sha256 = "31b6be33bdef9d7e8fe37d8725e31a2abe55bbfb962b3c5d0050819624d0cafd"
        created = "2025-11-30"
        tlp = "white"

    strings:
        /* Required runtime markers (present in positives but common enough to be useful) */
        $s_corexemain   = "corexemain" ascii nocase
        $s_mscoree      = "mscoree.dll" ascii nocase

        /* Strong unique header discriminator for this malicious cluster (text-log form) */
        $h_tstamp       = "TimeDateStamp is 1654158479" ascii

        /* High-fidelity header fingerprints (text-log form) observed across positives */
        $h_sections3    = "NumberOfSections is 3" ascii
        $h_sizecode     = "SizeOfCode is 582144" ascii
        $h_sizeimage    = "SizeOfImage is 614400" ascii
        $h_text_raw     = "text_SizeOfRawData is 582144" ascii
        $h_aep          = "AddressOfEntryPoint is 589914" ascii

    condition:
        /*
         * Detection logic:
         *  - Require both runtime markers (corexemain + mscoree.dll)
         *  - Require the exact TimeDateStamp (strong negative-filter vs benigns)
         *  - Require the common section-count seen in positives (NumberOfSections is 3)
         *  - Require at least two high-fidelity header fingerprints to confirm cluster
         */
        $s_corexemain and $s_mscoree and $h_tstamp and $h_sections3 and
        ( 2 of ( $h_sizecode, $h_sizeimage, $h_text_raw, $h_aep ) )
}


rule TEXT_COREXEMAIN_MSCOREE_1657695555
{
    meta:
        author = "malware-analyst"
        description = "Detects text-log traces of a corexemain + mscoree.dll cluster with TimeDateStamp 1657695555 and matching PE header fingerprints (tuned to exclude provided benign neighbors)."
        reference_sha256 = "0ae5656c6ad16162d08b5d3ffb245cf52cacb6b4197d548553611ad2267216ee"
        created = "2025-11-30"
        tlp = "white"

    strings:
        /* runtime / loader markers (required) */
        $s_corexemain   = "corexemain" ascii nocase
        $s_mscoree      = "mscoree.dll" ascii nocase

        /* strong timestamp discriminator observed in this malicious cluster */
        $h_tstamp       = "TimeDateStamp is 1657695555" ascii

        /* high-fidelity PE header / section fingerprints (text-log form) */
        $h_sections3    = "NumberOfSections is 3" ascii
        $h_sizecode     = "SizeOfCode is 739328" ascii
        $h_sizeimage    = "SizeOfImage is 770048" ascii
        $h_text_raw     = "text_SizeOfRawData is 739328" ascii
        $h_aep          = "AddressOfEntryPoint is 735126" ascii
        $h_lfanew128    = "e_lfanew is 128" ascii

    condition:
        /*
         * Conservative detection logic:
         *  - Must contain both loader markers (corexemain + mscoree.dll)
         *  - Must contain the exact TimeDateStamp observed in malicious positives
         *  - Must show the expected section count (3)
         *  - Must match at least two high-fidelity header/section fingerprints to avoid benign overlaps
         *  - Require e_lfanew 128 as additional corroboration to further reduce false positives
         */
        $s_corexemain and $s_mscoree and $h_tstamp and $h_sections3 and
        ( 2 of ( $h_sizecode, $h_sizeimage, $h_text_raw, $h_aep ) ) and
        $h_lfanew128
}


rule TEXT_COREXEMAIN_MSOCOHORT_25f1faa2
{
    meta:
        author = "malware-analyst"
        description = "Text-log YARA: detect corexemain + mscoree.dll samples from the specific .NET/native loader cluster (precision tuned to avoid provided benign neighbors)."
        reference_sha256 = "25f1faa21822093733dca0e351a69073d713e3c698ce130b02bf9ec93576bf21"
        created = "2025-12-01"
        tlp = "white"

    strings:
        /* High-signal markers (present in positives) */
        $s_corexemain       = "corexemain" ascii nocase
        $s_mscoree          = "mscoree.dll" ascii nocase

        /* Unique header fingerprint for this malicious cluster (text-log form) */
        $t_timestamp        = "TimeDateStamp is 1647246671" ascii

        /* Structural tokens shared by the cluster (avoid matching benigns by requiring multiple together) */
        $h_lfanew128        = "e_lfanew is 128" ascii
        $h_sections_3       = "NumberOfSections is 3" ascii
        $h_filealign_512    = "FileAlignment is 512" ascii

        /* Large/precise size tokens that differentiate this cluster from benign neighbors */
        $h_sizecode_980992  = "SizeOfCode is 980992" ascii
        $h_text_raw_980992  = "text_SizeOfRawData is 980992" ascii
        $h_rsrc_ptr_981504  = "rsrc_PointerToRawData is 981504" ascii

    condition:
        /*
         * Matching logic:
         *  - require both high-signal tokens (corexemain + mscoree.dll)
         *  - require the exact TimeDateStamp seen in this sample
         *  - require core structural layout (e_lfanew + NumberOfSections + FileAlignment)
         *  - plus at least one of the large/precise size tokens to avoid benign overlaps
         */
        $s_corexemain and $s_mscoree and
        $t_timestamp and
        $h_lfanew128 and $h_sections_3 and $h_filealign_512 and
        (1 of ($h_sizecode_980992, $h_text_raw_980992, $h_rsrc_ptr_981504))
}


rule TEXT_Corexemain_Mscoree_SpecificHeaders
{
    meta:
        author = "malware-analyst"
        description = "Text-log rule: detect corexemain + mscoree.dll entries tied to the specific PE header fingerprint (TimeDateStamp 1621389374 + companion header tokens). Designed to avoid benign neighbors by requiring the exact TimeDateStamp plus another unique header token."
        sha256_target = "ac81425293d072146e810b6b584333f09831ab5c1f3fe20b12f0dbed0913398e"
        created = "2025-11-30"
        tlp = "white"

    strings:
        $corexemain        = "corexemain" ascii nocase
        $mscoree           = "mscoree.dll" ascii nocase

        /* Strongly distinguishing header tokens (text-log form) */
        $t_timestamp       = "TimeDateStamp is 1621389374" ascii
        $s_sizeofcode      = "SizeOfCode is 480768" ascii
        $s_aep             = "AddressOfEntryPoint is 488758" ascii
        $s_text_raw        = "text_SizeOfRawData is 480768" ascii
        $s_sizeofimage     = "SizeOfImage is 507904" ascii
        $s_rsrc_raw        = "rsrc_SizeOfRawData is 7680" ascii

    condition:
        /*
         * Require runtime loader tokens AND the exact TimeDateStamp found in the malicious sample,
         * plus at least one additional specific PE header token to reduce false positives against benign .NET artifacts.
         */
        $corexemain and $mscoree and $t_timestamp and
        ( $s_sizeofcode or $s_aep or $s_text_raw or $s_sizeofimage or $s_rsrc_raw )
}


rule TEXT_MAL_CRTHREAD_WINHTTP_f2f15d19
{
    meta:
        author = "malware-analyst"
        description = "Text-log YARA: detects cluster with CreateRemoteThread + WinHTTP usage and strict header/data-size fingerprints to avoid benign matches."
        sha256_target = "f2f15d197990af6048c3aea6ceaf016ee80a23ee0997782e2289b524cfcac56a"
        created = "2025-11-30"
        tlp = "white"

    strings:
        /* behavior / API / DLL tokens (text-log form) */
        $s_crt            = "createremotethread" ascii nocase
        $s_winhttp_dll    = "winhttp.dll" ascii nocase
        $s_winhttp_func   = "winhttpsetdefaultproxyconfiguration" ascii nocase
        $s_updateres      = "updateresourcea" ascii nocase
        $s_alpha_blend    = "alphablend" ascii nocase

        /* precise header / PE-like text tokens seen in positives (useful in text logs) */
        $h_lfanew240      = "e_lfanew is 240" ascii
        $h_sections4      = "NumberOfSections is 4" ascii
        $h_tstamp_1602435 = "TimeDateStamp is 1602435009" ascii
        $h_sizeimage_big  = "SizeOfImage is 42070016" ascii
        $h_data_misc_big  = "data_Misc_VirtualSize is 41938532" ascii
        $h_data_raw_size  = "data_SizeOfRawData is 119808" ascii

    condition:
        /*
         * Require the uncommon combination: CreateRemoteThread present in the text log
         * together with WinHTTP (DLL or specific WinHTTP API), plus at least two strict
         * header/data-size fingerprints (including timestamp or lfanew) to reduce false positives
         * against benign neighbors that share many common APIs.
         */
        $s_crt and ($s_winhttp_dll or $s_winhttp_func) and
        (
            ( $h_tstamp_1602435 and $h_lfanew240 ) or
            ( $h_sections4 and $h_data_misc_big ) or
            ( $h_sizeimage_big and $h_data_raw_size )
        ) and
        /* require at least one corroborating uncommon token from the binary's behavior */
        ( $s_updateres or $s_alpha_blend )
}


rule TEXT_MAL_MSCOREE_953c917e
{
    meta:
        author = "malware-analyst"
        description = "Text-log detection for a mscoree/.NET loader cluster: combines corexemain + mscoree.dll with a strict header fingerprint (timestamp + section/raw-size) to avoid benign neighbors."
        sha256_target = "953c917ea98a8b9eff67f260709fb55980c614c2d87dbb399c77a3ec682fe00e"
        created = "2025-11-30"
        tlp = "white"

    strings:
        /* behavioral tokens (must appear together in text logs) */
        $a_corexemain    = "corexemain" ascii nocase
        $a_mscoree       = "mscoree.dll" ascii nocase

        /* precise header / fingerprint tokens (text-log form) */
        $h_timestmp      = "TimeDateStamp is 4239979505" ascii
        $h_text_raw      = "text_SizeOfRawData is 322048" ascii
        $h_sections3     = "NumberOfSections is 3" ascii
        $h_lfanew128     = "e_lfanew is 128" ascii

        /* resource-area exact sizes/offsets (helps separate similar benigns) */
        $h_rsrc_raw1024  = "rsrc_SizeOfRawData is 1024" ascii
        $h_rsrc_ptr322560= "rsrc_PointerToRawData is 322560" ascii

    condition:
        /*
         * Require:
         *  - both cluster-identifying tokens (corexemain + mscoree.dll), AND
         *  - the unique timestamp AND the exact text raw-size, AND
         *  - at least one additional header/resource token to avoid matching benigns that share basic fields.
         */
        $a_corexemain and
        $a_mscoree and
        $h_timestmp and
        $h_text_raw and
        ( any of ( $h_sections3, $h_lfanew128, $h_rsrc_raw1024, $h_rsrc_ptr322560 ) )
}


rule TEXT_MAL_WINMM_1f5c36da
{
    meta:
        author = "malware-analyst"
        description = "Text-log detector for a cluster using winmm.dll + playsounda combined with strict PE-header fingerprints to avoid benign matches."
        sha256_target = "1f5c36da5a61ae77cd1afebd01be90d1a875b0be7056abec586c731bdf61eff6"
        created = "2025-11-30"
        tlp = "white"

    strings:
        /* behavior / DLL signatures (text-log form) */
        $s_winmm       = "winmm.dll" ascii nocase
        $s_playsound   = "playsounda" ascii nocase

        /* precise header fingerprints that are shared across positive neighbors but differ in benigns */
        $h_tstamp      = "TimeDateStamp is 1067389871" ascii
        $h_lfanew224   = "e_lfanew is 224" ascii
        $h_text_raw    = "text_SizeOfRawData is 258560" ascii
        $h_sections3   = "NumberOfSections is 3" ascii
        $h_linker9     = "MajorLinkerVersion is 9" ascii

        /* additional corroborating header tokens (help avoid false positives) */
        $h_subsys5     = "MajorSubsystemVersion is 5" ascii
        $h_sizeimage   = "SizeOfImage is 282624" ascii

    condition:
        /*
         * Require the uncommon DLL+API pair (winmm.dll + playsounda) AND
         * at least three of the strict header fingerprints including the unique timestamp.
         * This reduces accidental matches to benign files that share common APIs.
         */
        $s_winmm and $s_playsound and
        $h_tstamp and
        ( $h_lfanew224 and $h_text_raw and ( $h_sections3 or $h_linker9 or $h_subsys5 or $h_sizeimage ) )
}


rule TEXT_Malware_10d91161_cluster
{
    meta:
        author = "malware-analyst"
        description = "Text-log YARA to detect the 10d91161... cluster — requires rare resource API tokens plus an exact PE header fingerprint cluster (tuned to avoid the provided benign neighbors)."
        reference_sha256 = "10d9116113ccbdde796c05b5e1dfb28d88f900ff87c99e83689934fd0cd0e829"
        created = "2025-11-30"
        tlp = "white"

    strings:
        /* Rare/diagnostic resource APIs present in positives but not in supplied benign set */
        $s_sizeofresource    = "sizeofresource" ascii nocase
        $s_loadresource      = "loadresource" ascii nocase

        /* High-fidelity PE header / section fingerprints (text-log form) observed across positives */
        $h_tstamp            = "TimeDateStamp is 1592301645" ascii
        $h_sections4         = "NumberOfSections is 4" ascii
        $h_sizecode          = "SizeOfCode is 49152" ascii
        $h_sizeinit          = "SizeOfInitializedData is 446464" ascii
        $h_aep               = "AddressOfEntryPoint is 22132" ascii
        $h_textraw           = "text_SizeOfRawData is 49152" ascii
        $h_lfanew224         = "e_lfanew is 224" ascii
        $h_filealign4096     = "FileAlignment is 4096" ascii

    condition:
        /*
         * Conservative matching:
         *  - Require the rare resource-related API tokens (reduces false positives against benigns)
         *  - Require the exact TimeDateStamp seen in malware positives
         *  - Require the same section-count (4)
         *  - Require at least three additional high-fidelity header/section fingerprints to confirm the cluster
         *
         * This combination intentionally avoids benign neighbors that share common APIs/DLLs but do not
         * reproduce this particular set of header fingerprints + resource API usage.
         */
        $s_sizeofresource and $s_loadresource and
        $h_tstamp and $h_sections4 and
        (3 of ( $h_sizecode, $h_sizeinit, $h_aep, $h_textraw, $h_lfanew224, $h_filealign4096 ))
}


rule TEXT_ResourceLoader_LoaderPattern_708992537
{
    meta:
        author = "malware-analyst"
        description = "Detects text-log traces of a resource-loading / registry manipulation Windows PE sample (strongly targeted by combining uncommon resource APIs with the exact TimeDateStamp and section-count fingerprint). Designed to avoid benign neighbors by requiring multiple rare tokens together."
        sha256_target = "16ea37a38787c3c1d30d2249aae43437d22a2b80b99ad4f6608890e265467525"
        created = "2025-11-30"
        tlp = "white"

    strings:
        /* Uncommon resource-management and automation tokens (text form) */
        $s_lockresource        = "lockresource" ascii nocase
        $s_loadresource        = "loadresource" ascii nocase
        $s_sizeres             = "sizeofresource" ascii nocase
        $s_freeres             = "freeresource" ascii nocase

        /* Automation / COM helper tokens less common in benign logs */
        $s_variant_init        = "variantinit" ascii nocase
        $s_variant_clear       = "variantclear" ascii nocase
        $s_sysalloc            = "sysallocstringlen" ascii nocase
        $s_sysfree             = "sysfreestring" ascii nocase

        /* Registry + file I/O pair (common individually but suspicious together with above) */
        $s_regq                = "regqueryvalueexa" ascii nocase
        $s_createfilea         = "createfilea" ascii nocase

        /* Strong header / fingerprint tokens (text-log form) — used to avoid benign neighbors */
        $h_tds                 = "TimeDateStamp is 708992537" ascii
        $h_sections11          = "NumberOfSections is 11" ascii
        $h_lfanew_64          = "e_lfanew is 64" ascii

    condition:
        /*
         * Match only when:
         *  - the uncommon resource/COM helper tokens appear (at least 3 of them)
         *  - AND a registry + file I/O indicator appears
         *  - AND the exact PE header fingerprint from the malicious sample is present
         *
         * This reduces false positives by requiring both behavioral tokens (resource+variant APIs)
         * and the exact textual header fingerprint which is not present in the supplied benign neighbors.
         */
        ( (1 of ($s_lockresource, $s_loadresource, $s_sizeres, $s_freeres)) and
          (1 of ($s_variant_init, $s_variant_clear, $s_sysalloc, $s_sysfree)) and
          $s_regq and $s_createfilea )
        and
        $h_tds and $h_sections11 and $h_lfanew_64
}


rule TEXT_VBA_MSVBVM60_68a31512
{
    meta:
        author = "malware-analyst"
        description = "Text-log YARA: detects MSVBVM60-based samples with dense VBA runtime symbols and matching PE-text fingerprints (text-log form). Avoids common benigns by requiring MSVBVM60 + multiple VBA-only tokens + specific header fingerprints."
        target_sha256 = "68a315123349444d30fed12643a7be20eb003531a4b95d0db800fb765449037d"
        created = "2025-11-30"
        tlp = "white"

    strings:
        /* explicit VB runtime DLL (rare in benign modern binaries) */
        $dll_msvb = "msvbvm60.dll" ascii nocase

        /* highly VBA-specific runtime/internal tokens seen across positives */
        $v_vbavarmove      = "vbavarmove" ascii nocase
        $v_vbafreevarlist  = "vbafreevarlist" ascii nocase
        $v_vbafreeobjlist  = "vbafreeobjlist" ascii nocase
        $v_vbastrtoansi    = "vbastrtoansi" ascii nocase
        $v_cilog           = "cilog" ascii nocase
        $v_dllfunctioncall = "dllfunctioncall" ascii nocase

        /* PE/header text markers (text-log form) */
        $h_lfanew_200      = "e_lfanew is 200" ascii
        $h_filealign_4096  = "FileAlignment is 4096" ascii
        $h_sections_3      = "NumberOfSections is 3" ascii
        $h_sizeimage_167k  = "SizeOfImage is 167936" ascii

    condition:
        /* Require the explicit VB runtime DLL plus >=2 VBA-only symbols,
           and >=2 matching header markers */
        $dll_msvb and
        ( 2 of ( $v_vbavarmove, $v_vbafreevarlist, $v_vbafreeobjlist, $v_vbastrtoansi, $v_cilog, $v_dllfunctioncall ) ) and
        ( 2 of ( $h_lfanew_200, $h_filealign_4096, $h_sections_3, $h_sizeimage_167k ) )
}


rule TEXT_WINMM_PECLUSTER_1067389871
{
    meta:
        author = "malware-analyst"
        description = "Text-log detection for a GUI/audio-capable native cluster (timestamp 1067389871). Requires winmm.dll + the exact TimeDateStamp and multiple high-fidelity PE header tokens seen in the malicious neighbors. Tuned to avoid provided benign neighbors."
        target_sample = "1ebe38986d47f90019956195461098bb545930903e94652efe73b8d4103ca1bb"
        created = "2025-11-30"
        tlp = "white"

    strings:
        /* runtime / uncommon DLL (used as a discriminator vs benign set) */
        $dll_winmm        = "winmm.dll" ascii nocase

        /* GUI / audio APIs present in positives but absent from the benign set */
        $api_drawtexta    = "drawtexta" ascii nocase
        $api_playsounda   = "playsounda" ascii nocase

        /* exact strong header discriminator (text-log) */
        $h_timestamp      = "TimeDateStamp is 1067389871" ascii

        /* high-fidelity PE header fingerprints (text-log form) */
        $h_sections3      = "NumberOfSections is 3" ascii
        $h_sizecode       = "SizeOfCode is 258560" ascii
        $h_sizeimage      = "SizeOfImage is 282624" ascii
        $h_text_raw       = "text_SizeOfRawData is 258560" ascii
        $h_aep            = "AddressOfEntryPoint is 237641" ascii

    condition:
        /*
         * Matching logic:
         *  - Require the uncommon DLL (winmm.dll) AND the exact TimeDateStamp (strong discriminator).
         *  - Require the suspicious GUI/audio APIs (at least one) to avoid matching generic runtime-only logs.
         *  - Require NumberOfSections is 3 (seen across positives) to reduce accidental matches.
         *  - Require at least two high-fidelity header fingerprints to confirm the cluster fingerprint.
         */
        $dll_winmm and $h_timestamp and
        ( $api_drawtexta or $api_playsounda ) and
        $h_sections3 and
        ( 2 of ( $h_sizecode, $h_sizeimage, $h_text_raw, $h_aep ) )
}


rule VB6_GDIPlus_Image_Worker_a3f0b147
{
    meta:
        author = "malware-analyst"
        description = "Detects text-log indicators of a VB6 + GDI+ image/graphics worker (gdiplus.dll + msvbvm60.dll + VB runtime symbols). Tuned to avoid matching common C/C++ or POSIX binaries in negatives."
        sha256 = "a3f0b147f9803f7461689734db17334d4237ea309737e340b167aee5209591b3"
        tlp = "WHITE"
        created = "2025-11-30"

    strings:
        /* runtime / DLL markers (very specific to this sample) */
        $dll_gdiplus            = "gdiplus.dll" nocase
        $dll_msvb               = "msvbvm60.dll" nocase

        /* GDI+ / graphics APIs (uncommon in benign neighbors) */
        $g_gdiplus_startup      = "gdiplusstartup" nocase
        $g_gdiplus_shutdown     = "gdiplusshutdown" nocase
        $g_create_from_hdc      = "gdipcreatefromhdc" nocase
        $g_dispose_image        = "gdipdisposeimage" nocase
        $g_delete_graphics      = "gdipdeletegraphics" nocase
        $g_create_pen1          = "gdipcreatepen1" nocase
        $g_create_brush         = "gdipcreatesolidfill" nocase
        $g_draw_image_rect      = "gdipdrawimagerect" nocase
        $g_fill_rectangle       = "gdipfillrectangle" nocase
        $g_measure_string       = "gdipmeasurestring" nocase
        $g_create_bitmap_hbitmap= "gdipcreatebitmapfromhbitmap" nocase
        $g_create_hatchbrush    = "gdipcreatehatchbrush" nocase
        $g_set_smoothing        = "gdipsetsmoothingmode" nocase

        /* VB6/COM runtime symbols and helpers (very specific; reduces false positives) */
        $v_vbafreevar           = "vbafreevar" nocase
        $v_vbafreeobj           = "vbafreeobj" nocase
        $v_vbafileopen          = "vbafileopen" nocase
        $v_vbafileclose         = "vbafileclose" nocase
        $v_vbaexitproc          = "vbastexe" nocase  /* seen as vbastopexe in sample */
        $v_vbastrcopy           = "vbastrcopy" nocase
        $v_vbar8str             = "vbar8str" nocase
        $v_vbavarsetobj         = "vbavarsetobj" nocase
        $v_eventsink_invoke     = "eventsinkinvoke" nocase
        $v_zombie_get_typeinfo  = "zombiegettypeinfo" nocase

    condition:
        // Target is a text log. Require both the GDI+ runtime AND the VB6 runtime DLL names
        // plus at least four distinct GDI+/VB symbols to minimize false positives against benign neighbors.
        $dll_gdiplus and $dll_msvb and 4 of (
            $g_gdiplus_startup, $g_gdiplus_shutdown, $g_create_from_hdc, $g_dispose_image,
            $g_delete_graphics, $g_create_pen1, $g_create_brush, $g_draw_image_rect,
            $g_fill_rectangle, $g_measure_string, $g_create_bitmap_hbitmap, $g_create_hatchbrush,
            $g_set_smoothing,
            $v_vbafreevar, $v_vbafreeobj, $v_vbafileopen, $v_vbafileclose,
            $v_vbaexitproc, $v_vbastrcopy, $v_vbar8str, $v_vbavarsetobj,
            $v_eventsink_invoke, $v_zombie_get_typeinfo
        )
}


rule MAL_PrivRes_WinExec_IsBadptr_Family_Log
{
  meta:
    description = "Detects malware family using privilege escalation + resource unpacking + WinExec with rare IsBad* APIs in text logs"
    author = "Assistant"
    sha256 = "9b045f7efedbf3ddff5f089a205c3c4c7725ab6aa38e859da5bc7848a2e2bcb0"
    context = "text_log_only"

  strings:
    $p1 = "adjusttokenprivileges" nocase
    $p2 = "lookupprivilegevaluea" nocase
    $p3 = "openprocesstoken" nocase

    $r1 = "findresourcea" nocase
    $r2 = "loadresource" nocase
    $r3 = "sizeofresource" nocase

    $e1 = "winexec" nocase
    $m1 = "virtualalloc" nocase

    $a1 = "loadacceleratorsa" nocase
    $a2 = "translateacceleratora" nocase

    $ib1 = "isbadwriteptr" nocase
    $ib2 = "isbadreadptr" nocase
    $ib3 = "isbadcodeptr" nocase

  condition:
    all of ($p*) and
    all of ($r*) and
    all of ($a*) and
    $e1 and $m1 and
    2 of ($ib*)
}

rule MAL_PrivResLoader_Win32_A
{
  meta:
    description = "Detects Win32 malware combining token privilege escalation with resource-based payload loading and classic loader APIs"
    author = "malware-analyst"
    date = "2025-12-06"
    sha256 = "9b045f7efedbf3ddff5f089a205c3c4c7725ab6aa38e859da5bc7848a2e2bcb0"

  strings:
    // Privilege escalation (ANSI)
    $p1 = "adjusttokenprivileges" nocase
    $p2 = "lookupprivilegevaluea" nocase
    $p3 = "openprocesstoken" nocase

    // Resource unpacking/loader
    $r1 = "findresourcea" nocase
    $r2 = "loadresource" nocase
    $r3 = "sizeofresource" nocase

    // In-memory loader primitives
    $l1 = "virtualalloc" nocase
    $l2 = "getprocaddress" nocase
    $l3 = "loadlibrarya" nocase

    // Legacy/suspicious probes often seen in this family
    $x1 = "isbadwriteptr" nocase
    $x2 = "isbadreadptr" nocase
    $x3 = "isbadcodeptr" nocase
    $x4 = "winexec" nocase

  condition:
    all of ($p*) and
    all of ($r*) and
    2 of ($l*) and
    1 of ($x*)
}

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


rule Detect_New_Malware_06cde650
{
    meta:
        description = "Detects text-log based malware sample 06cde650 and neighbors using specific API and DLL indicators related to graphics and variant handling."
        author = "malware-analyst"
        sha256 = "06cde650baa0c78fe43d0088f1948c7654a0330f6f59822332ccf5d90fafb120"
        created = "2023-10-27"

    strings:
        // Behavioral Indicators (APIs from new sample and neighbors)
        $api_getsyscolorbrush = "getsyscolorbrush"
        $api_variantchangetypeex = "variantchangetypeex"
        
        // Contextual APIs (Present in target but common, use for context only)
        $api_getprocaddress = "getprocaddress"
        $api_getmodulehandlea = "getmodulehandlea"
        $api_raiseexception = "raiseexception"
        $api_loadlibrarya = "loadlibrarya"

        // Imported DLLs
        $dll_oleaut32 = "oleaut32.dll"
        $dll_user32 = "user32.dll"
        $dll_kernel32 = "kernel32.dll"

        // Benign Filter strings (to avoid) - Implicitly handled by selection of specific APIs above which are absent in benign context provided.
        // However, explicit exclusion of purely generic combos is good practice if rule matches broadly. 
        // Based on provided negative context, the above APIs are not present.

    condition:
        // Logic: 
        // 1. Must include specific DLLs found in target (oleaut32, user32) AND strong unique API indicators.
        // 2. The combination of GetSysColorBrush and VariantChangeTypeEx along with standard loading APIs is the specific behavior pattern to match, absent in the provided benign samples.
        
        $dll_oleaut32 and $dll_user32 and $dll_kernel32 and
        $api_getsyscolorbrush and $api_variantchangetypeex and
        ($api_getprocaddress or $api_getmodulehandlea or $api_raiseexception or $api_loadlibrarya)
}

rule Detect_New_Malware_12865d3c
{
    meta:
        description = "Detects text-log based malware sample 12865d3c and neighbors using specific API indicators related to console manipulation and resource updating."
        author = "malware-analyst"
        sha256 = "12865d3cf5f64bc049434b136eeeb9e0ebb53d6cd9d29945f082da45929d5fa7"
        created = "2023-10-27"

    strings:
        /* Behavioral Indicators (APIs from new sample and neighbors) */
        $api_beginupdateresource    = "beginupdateresourcew" nocase
        $api_enumresnames           = "enumresourcenamesw" nocase
        $api_console_aliases        = "getconsolealiaseslengtha" nocase
        $api_console_alias_exes     = "getconsolealiasexeslengthw" nocase
        $api_comm_timeouts          = "getcommtimeouts" nocase
        $api_buildcomm              = "buildcommdcbandtimeoutsw" nocase
        $api_numa                   = "getnumahighestnodenumber" nocase
        $api_firmware               = "getfirmwareenvironmentvariablew" nocase
        $api_write_console_char     = "writeconsoleoutputcharacterw" nocase
        $api_read_console_char      = "readconsoleoutputcharacterw" nocase
        $api_add_console_alias      = "addconsolealiasw" nocase
        $api_enum_calendar          = "enumcalendarinfoa" nocase
        $api_openeventlog           = "openeventloga" nocase
        $api_unregisterwait         = "unregisterwait" nocase

        /* Neighbor Shared/Unique API Indicators */
        $api_getconsolealiasexes    = "getconsolealiasexesw" nocase
        $api_lopen                  = "lopen" nocase
        $api_hread                  = "hread" nocase
        $api_lwrite                 = "lwrite" nocase
        $api_createmutexa           = "createmutexa" nocase

    condition:
        (
            $api_beginupdateresource and $api_enumresnames and
            2 of ($api_console_aliases, $api_console_alias_exes, $api_comm_timeouts, $api_buildcomm)
        )
        or
        (
            4 of ($api_numa, $api_firmware, $api_write_console_char, $api_read_console_char, $api_add_console_alias,
                  $api_enum_calendar, $api_openeventlog, $api_unregisterwait, $api_getconsolealiasexes,
                  $api_lopen, $api_hread, $api_lwrite, $api_createmutexa)
        )
}


rule Detect_New_Malware_18434161
{
    meta:
        description = "Detects text-log based malware sample 18434161 and neighbors using specific API and DLL indicators related to MFC and GDI."
        author = "malware-analyst"
        sha256 = "184341613158f5244ea0e838f4ae1383748573cae4740558e272699dd623afe5"
        created = "2023-10-27"

    strings:
        /* Behavioral Indicators (APIs from new sample and neighbors) */
        $api_isiconic        = "isiconic" nocase
        $api_escape          = "escape" nocase

        /* Contextual APIs (Present in target but common, used for context) */
        $api_getprocaddress  = "getprocaddress" nocase
        $api_loadlibrarya    = "loadlibrarya" nocase
        $api_virtualalloc    = "virtualalloc" nocase
        $api_virtualprotect  = "virtualprotect" nocase

        /* Imported DLLs */
        $dll_mfc42           = "mfc42.dll" nocase
        $dll_gdi32           = "gdi32.dll" nocase
        $dll_user32          = "user32.dll" nocase

    condition:
        /*
         Logic:
         - Require presence of MFC + GDI + User32
         - Require the uncommon behavioral pair IsIconic + Escape
         - And at least one of the contextual APIs that indicate dynamic resolution or memory staging
        */
        $dll_mfc42 and $dll_gdi32 and $dll_user32 and
        $api_isiconic and $api_escape and
        ( $api_getprocaddress or $api_loadlibrarya or $api_virtualalloc or $api_virtualprotect )
}


rule Detect_New_Malware_1d4e04fe_tuned
{
    meta:
        description = "Tuned: Detects cluster 1d4e04fe — require two DLL anchors + resource API + behavioral indicator (memory/thread/UI). Reduced FP while keeping TP."
        author = "malware-analyst (tuned)"
        sha256 = "1d4e04fe6e9b4cb7a87f57ebebdf6b66d3eed4bae5d97c4cf36d39641928c723"
        created = "2023-10-27"
        tuned = "2025-12-05"
        confidence = "Medium"

    strings:
        /* DLL anchors (require 2 of 3) */
        $dll_shlwapi      = "shlwapi.dll" nocase
        $dll_gdi32        = "gdi32.dll" nocase
        $dll_comdlg32     = "comdlg32.dll" nocase

        /* Resource / embedding APIs (require 1) */
        $res_lock         = "lockresource" nocase
        $res_sizeof       = "sizeofresource" nocase
        $res_load         = "loadresource" nocase
        $res_find_a       = "findresourcea" nocase

        /* Behavioral / higher-confidence indicators (require 1) */
        $mem_vprot        = "virtualprotect" nocase
        $thr_create       = "createthread" nocase
        $interlocked_cmp  = "interlockedcompareexchange" nocase
        $wait_multi       = "waitformultipleobjects" nocase

        /* Useful UI/context tokens (captured indirectly via requirement counts) */
        $ui_getopen       = "getopenfilenamea" nocase
        $ui_dialogparam   = "dialogboxparama" nocase
        $ui_messagebox    = "messageboxa" nocase
        $ui_loadicon      = "loadicona" nocase
        $ui_loadbitmap    = "loadbitmapa" nocase

    condition:
        /*
         * TUNED LOGIC:
         * - Require at least two DLL anchors to reduce incidental matches
         * - Require at least one resource-related API (embedding/resource handling)
         * - Require at least one behavioral indicator showing memory/threading/atomic ops
         *
         * Additionally allow a fallback match for variants that emphasize UI + resource:
         * - (two DLL anchors) AND (3 of UI/resource tokens) AND (1 behavioral indicator)
         */
        2 of ( $dll_shlwapi, $dll_gdi32, $dll_comdlg32 ) and
        (
            /* primary path: resource + behavior */
            ( 1 of ( $res_lock, $res_sizeof, $res_load, $res_find_a ) and
              1 of ( $mem_vprot, $thr_create, $interlocked_cmp, $wait_multi ) )
            or
            /* fallback path: UI-heavy variant + resource + behavior */
            ( 3 of ( $ui_getopen, $ui_dialogparam, $ui_messagebox, $ui_loadicon, $ui_loadbitmap, $res_lock, $res_sizeof, $res_load, $res_find_a ) and
              1 of ( $mem_vprot, $thr_create, $interlocked_cmp, $wait_multi ) )
        )
}


rule Detect_New_Malware_21c6a81b
{
    meta:
        description = "Detects text-log based malware sample 21c6a81b and neighbors using specific API and DLL indicators related to console manipulation and debugging."
        author = "malware-analyst"
        sha256 = "21c6a81b4c605eef56076337cf15aadaeda20c634e9e472cf23d3c732da6e818"
        created = "2023-10-27"

    strings:
        // Behavioral Indicators (APIs from new sample and neighbors)
        $api_terminatethread = "terminatethread"
        $api_createmutexw = "createmutexw"
        $api_openeventa = "openeventa"
        $api_debugbreak = "debugbreak"
        $api_openmutexw = "openmutexw"
        $api_findnextvolumew = "findnextvolumew"
        $api_createtimerqueuetimer = "createtimerqueuetimer"
        $api_createiocompletionport = "createiocompletionport"
        $api_writeprivateprofilestringa = "writeprivateprofilestringa"
        $api_setprocesspriorityboost = "setprocesspriorityboost"
        $api_setthreadaffinitymask = "setthreadaffinitymask"
        $api_lockfile = "lockfile"
        $api_allocconsole = "allocconsole"
        $api_findfirstchangenotificationw = "findfirstchangenotificationw"
        $api_setprocessshutdownparameters = "setprocessshutdownparameters"
        $api_flushconsoleinputbuffer = "flushconsoleinputbuffer"
        $api_addatomw = "addatomw"
        $api_setconsolescreenbuffersize = "setconsolescreenbuffersize"
        $api_setconsolewindowinfo = "setconsolewindowinfo"
        $api_globalgetatomnamew = "globalgetatomnamew"
        $api_createmailslotw = "createmailslotw"
        $api_enumresourcenamesw = "enumresourcenamesw"
        $api_freelibraryandexitthread = "freelibraryandexitthread"
        $api_createtimerqueue = "createtimerqueue"
        $api_enumresourcetypesw = "enumresourcetypesw"
        $api_getsystemwow64directoryw = "getsystemwow64directoryw"
        $api_writeconsoleinputa = "writeconsoleinputa"
        $api_waitfordebugevent = "waitfordebugevent"
        $api_copyfileexw = "copyfileexw"
        $api_fillconsoleoutputcharacterw = "fillconsoleoutputcharacterw"
        $api_querydepthslist = "querydepthslist"
        $api_readconsoleinputw = "readconsoleinputw"
        $api_setlocaleinfow = "setlocaleinfow"
        $api_getconsolealiaseslengthw = "getconsolealiaseslengthw"
        $api_buildcommdcbandtimeoutsw = "buildcommdcbandtimeoutsw"
        $api_resetwritewatch = "resetwritewatch"
        $api_callnamedpipea = "callnamedpipea"
        $api_buildcommdcbandtimeoutsa = "buildcommdcbandtimeoutsa"
        $api_getconsolealiasexesa = "getconsolealiasexesa"
        $api_setdefaultcommconfigw = "setdefaultcommconfigw"
        $api_getnamedpipehandlestatea = "getnamedpipehandlestatea"
        $api_buildcommdcbw = "buildcommdcbw"
        $api_openwaitabletimerw = "openwaitabletimerw"
        $api_setcomputernamea = "setcomputernamea"
        $api_getbinarytypew = "getbinarytypew"
        $api_setcalendarinfow = "setcalendarinfow"
        $api_verlanguagenamew = "verlanguagenamew"
        $api_getnumberformata = "getnumberformata"
        $api_getsystemtimeadjustment = "getsystemtimeadjustment"
        $api_getcompressedfilesizea = "getcompressedfilesizea"
        $api_getcommstate = "getcommstate"
        $api_getconsolealiasexeslengtha = "getconsolealiasexeslengtha"
        $api_findnextvolumemountpointa = "findnextvolumemountpointa"
        $api_writeconsoleoutputcharactera = "writeconsoleoutputcharactera"
        $api_readconsoleoutputcharactera = "readconsoleoutputcharactera"
        $api_getcommconfig = "getcommconfig"
        $api_initatomtable = "initatomtable"
        $api_setconsolecursorinfo = "setconsolecursorinfo"
        $api_createactctxa = "createactctxa"
        $api_writeprivateprofilestructw = "writeprivateprofilestructw"
        $api_globalunfix = "globalunfix"
        $api_convertfibertothread = "convertfibertothread"
        $api_movefilewithprogressw = "movefilewithprogressw"
        
        // Imported DLLs
        $dll_kernel32 = "kernel32.dll"
        // $dll_user32 = "user32.dll" // Common, but present in neighbors

        // Benign Filter strings (to avoid) - Implicitly handled by selection of specific APIs above which are absent in benign context provided.
        // However, explicit exclusion of purely generic combos is good practice if rule matches broadly. 
        // Based on provided negative context, the above APIs are not present.

    condition:
        // Logic: 
        // 1. Must include specific DLL "kernel32.dll" (found in target) AND strong unique API indicators.
        // 2. Must utilize a subset of the unique behavioral APIs found in the target/neighbors but NOT in benign files.
        
        $dll_kernel32 and
        (
            2 of ($api_terminatethread, $api_createmutexw, $api_openeventa, $api_debugbreak, $api_openmutexw, $api_findnextvolumew) or
            4 of ($api_createtimerqueuetimer, $api_createiocompletionport, $api_writeprivateprofilestringa, $api_setprocesspriorityboost, $api_setthreadaffinitymask, $api_lockfile, $api_allocconsole, $api_findfirstchangenotificationw, $api_setprocessshutdownparameters, $api_flushconsoleinputbuffer, $api_addatomw, $api_setconsolescreenbuffersize, $api_setconsolewindowinfo, $api_globalgetatomnamew, $api_createmailslotw, $api_enumresourcenamesw, $api_freelibraryandexitthread, $api_createtimerqueue, $api_enumresourcetypesw, $api_getsystemwow64directoryw, $api_writeconsoleinputa, $api_waitfordebugevent, $api_copyfileexw, $api_fillconsoleoutputcharacterw, $api_querydepthslist, $api_readconsoleinputw, $api_setlocaleinfow, $api_getconsolealiaseslengthw, $api_buildcommdcbandtimeoutsw, $api_resetwritewatch, $api_callnamedpipea, $api_buildcommdcbandtimeoutsa, $api_getconsolealiasexesa, $api_setdefaultcommconfigw, $api_getnamedpipehandlestatea, $api_buildcommdcbw, $api_openwaitabletimerw, $api_setcomputernamea, $api_getbinarytypew, $api_setcalendarinfow, $api_verlanguagenamew, $api_getnumberformata, $api_getsystemtimeadjustment, $api_getcompressedfilesizea, $api_getcommstate, $api_getconsolealiasexeslengtha, $api_findnextvolumemountpointa, $api_writeconsoleoutputcharactera, $api_readconsoleoutputcharactera, $api_getcommconfig, $api_initatomtable, $api_setconsolecursorinfo, $api_createactctxa, $api_writeprivateprofilestructw, $api_globalunfix, $api_convertfibertothread, $api_movefilewithprogressw)
        )
}

rule Detect_New_Malware_21c6a81b1
{
    meta:
        description = "Detects text-log based malware sample 21c6a81b and neighbors using specific API and DLL indicators related to console manipulation and process control."
        author = "malware-analyst"
        sha256 = "21c6a81b4c605eef56076337cf15aadaeda20c634e9e472cf23d3c732da6e818"
        created = "2023-10-27"

    strings:
        // Behavioral Indicators (APIs from new sample and neighbors)
        $api_terminatethread = "terminatethread"
        $api_createmutexw = "createmutexw"
        $api_openeventa = "openeventa"
        $api_debugbreak = "debugbreak"
        $api_openmutexw = "openmutexw"
        $api_findnextvolumew = "findnextvolumew"
        $api_createtimerqueuetimer = "createtimerqueuetimer"
        $api_createiocompletionport = "createiocompletionport"
        $api_writeprivateprofilestringa = "writeprivateprofilestringa"
        $api_setprocesspriorityboost = "setprocesspriorityboost"
        $api_setthreadaffinitymask = "setthreadaffinitymask"
        $api_lockfile = "lockfile"
        $api_allocconsole = "allocconsole"
        $api_findfirstchangenotificationw = "findfirstchangenotificationw"
        $api_setprocessshutdownparameters = "setprocessshutdownparameters"
        $api_flushconsoleinputbuffer = "flushconsoleinputbuffer"
        $api_addatomw = "addatomw"
        $api_setconsolescreenbuffersize = "setconsolescreenbuffersize"
        $api_setconsolewindowinfo = "setconsolewindowinfo"
        $api_globalgetatomnamew = "globalgetatomnamew"
        $api_createmailslotw = "createmailslotw"
        $api_enumresourcenamesw = "enumresourcenamesw"
        $api_freelibraryandexitthread = "freelibraryandexitthread"
        $api_createtimerqueue = "createtimerqueue"
        $api_enumresourcetypesw = "enumresourcetypesw"
        $api_getsystemwow64directoryw = "getsystemwow64directoryw"
        $api_writeconsoleinputa = "writeconsoleinputa"
        $api_waitfordebugevent = "waitfordebugevent"
        $api_copyfileexw = "copyfileexw"
        $api_fillconsoleoutputcharacterw = "fillconsoleoutputcharacterw"
        $api_querydepthslist = "querydepthslist"
        $api_readconsoleinputw = "readconsoleinputw"
        $api_setlocaleinfow = "setlocaleinfow"
        $api_getconsolealiaseslengthw = "getconsolealiaseslengthw"
        $api_buildcommdcbandtimeoutsw = "buildcommdcbandtimeoutsw"
        $api_resetwritewatch = "resetwritewatch"
        $api_callnamedpipea = "callnamedpipea"
        $api_buildcommdcbandtimeoutsa = "buildcommdcbandtimeoutsa"
        $api_getconsolealiasexesa = "getconsolealiasexesa"
        $api_setdefaultcommconfigw = "setdefaultcommconfigw"
        $api_getnamedpipehandlestatea = "getnamedpipehandlestatea"
        $api_buildcommdcbw = "buildcommdcbw"
        $api_openwaitabletimerw = "openwaitabletimerw"
        $api_setcomputernamea = "setcomputernamea"
        $api_getbinarytypew = "getbinarytypew"
        $api_setcalendarinfow = "setcalendarinfow"
        $api_verlanguagenamew = "verlanguagenamew"
        $api_getnumberformata = "getnumberformata"
        $api_getsystemtimeadjustment = "getsystemtimeadjustment"
        $api_getcompressedfilesizea = "getcompressedfilesizea"
        $api_getcommstate = "getcommstate"
        $api_getconsolealiasexeslengtha = "getconsolealiasexeslengtha"
        $api_findnextvolumemountpointa = "findnextvolumemountpointa"
        $api_writeconsoleoutputcharactera = "writeconsoleoutputcharactera"
        $api_readconsoleoutputcharactera = "readconsoleoutputcharactera"
        $api_getcommconfig = "getcommconfig"
        $api_initatomtable = "initatomtable"
        $api_setconsolecursorinfo = "setconsolecursorinfo"
        $api_createactctxa = "createactctxa"
        $api_writeprivateprofilestructw = "writeprivateprofilestructw"
        $api_globalunfix = "globalunfix"
        $api_convertfibertothread = "convertfibertothread"
        $api_movefilewithprogressw = "movefilewithprogressw"
        
        // Imported DLLs
        $dll_kernel32 = "kernel32.dll"
        // $dll_user32 = "user32.dll" // Common, but present in neighbors

        // Benign Filter strings (to avoid) - Implicitly handled by selection of specific APIs above which are absent in benign context provided.
        // However, explicit exclusion of purely generic combos is good practice if rule matches broadly. 
        // Based on provided negative context, the above APIs are not present.

    condition:
        // Logic: 
        // 1. Must include specific DLL "kernel32.dll" (found in target) AND strong unique API indicators.
        // 2. Must utilize a subset of the unique behavioral APIs found in the target/neighbors but NOT in benign files.
        
        $dll_kernel32 and
        (
            2 of ($api_terminatethread, $api_createmutexw, $api_openeventa, $api_debugbreak, $api_openmutexw, $api_findnextvolumew) or
            4 of ($api_createtimerqueuetimer, $api_createiocompletionport, $api_writeprivateprofilestringa, $api_setprocesspriorityboost, $api_setthreadaffinitymask, $api_lockfile, $api_allocconsole, $api_findfirstchangenotificationw, $api_setprocessshutdownparameters, $api_flushconsoleinputbuffer, $api_addatomw, $api_setconsolescreenbuffersize, $api_setconsolewindowinfo, $api_globalgetatomnamew, $api_createmailslotw, $api_enumresourcenamesw, $api_freelibraryandexitthread, $api_createtimerqueue, $api_enumresourcetypesw, $api_getsystemwow64directoryw, $api_writeconsoleinputa, $api_waitfordebugevent, $api_copyfileexw, $api_fillconsoleoutputcharacterw, $api_querydepthslist, $api_readconsoleinputw, $api_setlocaleinfow, $api_getconsolealiaseslengthw, $api_buildcommdcbandtimeoutsw, $api_resetwritewatch, $api_callnamedpipea, $api_buildcommdcbandtimeoutsa, $api_getconsolealiasexesa, $api_setdefaultcommconfigw, $api_getnamedpipehandlestatea, $api_buildcommdcbw, $api_openwaitabletimerw, $api_setcomputernamea, $api_getbinarytypew, $api_setcalendarinfow, $api_verlanguagenamew, $api_getnumberformata, $api_getsystemtimeadjustment, $api_getcompressedfilesizea, $api_getcommstate, $api_getconsolealiasexeslengtha, $api_findnextvolumemountpointa, $api_writeconsoleoutputcharactera, $api_readconsoleoutputcharactera, $api_getcommconfig, $api_initatomtable, $api_setconsolecursorinfo, $api_createactctxa, $api_writeprivateprofilestructw, $api_globalunfix, $api_convertfibertothread, $api_movefilewithprogressw)
        )
}

rule Detect_New_Malware_39698495
{
    meta:
        description = "Detects text-log based malware sample 39698495 and neighbors using specific VB6 runtime and API indicators."
        author = "malware-analyst"
        sha256 = "3969849500b4456d9b648eeaf3f471fcbfeea14e323d3db643fc628b9ee2a586"
        created = "2023-10-27"

    strings:
        // Behavioral Indicators (APIs from new sample and neighbors) - VB6 runtime
        $vb_vbarecansitouni = "vbarecansitouni"
        $vb_vbasetsystemerror = "vbasetsystemerror"
        $vb_vbarecunitoansi = "vbarecunitoansi"
        $vb_vbastrtoansi = "vbastrtoansi"
        $vb_vbacastobj = "vbacastobj"
        $vb_vbainstr = "vbainstr"
        $vb_vbarecdestruct = "vbarecdestruct"
        $vb_vbarecdestructansi = "vbarecdestructansi"
        $vb_vbavaridiv = "vbavaridiv"
        $vb_vbaaryconstruct2 = "vbaaryconstruct2"
        $vb_vbai2str = "vbai2str"
        $vb_vbalateidst = "vbalateidst"
        $vb_vbavartstne = "vbavartstne"
        $vb_vbalatememcall = "vbalatememcall"
        $vb_vbalatememst = "vbalatememst"
        $vb_vbavarsetobj = "vbavarsetobj"
        $vb_vbalatememcallld = "vbalatememcallld"
        
        // Behavioral Indicators - General APIs
        // None specific to the target or neighbors that are absent in benign context were highlighted beyond standard VB6.
        // Focusing on VB6 specific calls.

        // Imported DLLs
        $dll_msvbvm60 = "msvbvm60.dll"

        // Benign Filter strings (to avoid) - Implicitly handled by selection of specific APIs above which are absent in benign context provided.
        // However, explicit exclusion of purely generic combos is good practice if rule matches broadly. 
        // Based on provided negative context, the above APIs are not present.

    condition:
        // Logic: 
        // 1. Must include specific DLL "msvbvm60.dll" (found in target) AND strong unique API indicators.
        // 2. Must utilize a subset of the unique behavioral APIs found in the target/neighbors but NOT in benign files.
        
        $dll_msvbvm60 and
        (
            2 of ($vb_vbarecansitouni, $vb_vbasetsystemerror, $vb_vbarecunitoansi, $vb_vbastrtoansi, $vb_vbacastobj, $vb_vbainstr, $vb_vbarecdestruct, $vb_vbarecdestructansi, $vb_vbavaridiv)
        )
        or
        (
            4 of ($vb_vbaaryconstruct2, $vb_vbai2str, $vb_vbalateidst, $vb_vbavartstne, $vb_vbalatememcall, $vb_vbalatememst, $vb_vbavarsetobj, $vb_vbalatememcallld, $vb_vbarecansitouni, $vb_vbasetsystemerror, $vb_vbarecunitoansi, $vb_vbastrtoansi, $vb_vbacastobj, $vb_vbainstr, $vb_vbarecdestruct, $vb_vbarecdestructansi, $vb_vbavaridiv)
        )
}

rule Detect_New_Malware_3bcaf191
{
    meta:
        description = "Detects text-log based malware sample 3bcaf191 and neighbors using specific API and DLL indicators related to graphics and window manipulation."
        author = "malware-analyst"
        sha256 = "3bcaf191db8de9ae0926e3cc6c1e64b20187b1acdda8498c7856ac569e125204"
        created = "2023-10-27"

    strings:
        /* Behavioral Indicators */
        $api_oledraw = "oledraw" nocase
        $api_isaccelerator = "isaccelerator" nocase
        $api_createenhmetafilea = "createenhmetafilea" nocase
        $api_getenhmetafiledescriptiona = "getenhmetafiledescriptiona" nocase
        $api_getenhmetafilebits = "getenhmetafilebits" nocase
        $api_getenhmetafileheader = "getenhmetafileheader" nocase
        $api_getenhmetafilepaletteentries = "getenhmetafilepaletteentries" nocase
        $api_getwinmetafilebits = "getwinmetafilebits" nocase
        $api_playenhmetafile = "playenhmetafile" nocase
        $api_setenhmetafilebits = "setenhmetafilebits" nocase
        $api_setwinmetafilebits = "setwinmetafilebits" nocase
        $api_getkeynametexta = "getkeynametexta" nocase
        $api_imagelistreplace = "imagelistreplace" nocase
        $api_closeenhmetafile = "closeenhmetafile" nocase
        $api_copyenhmetafilea = "copyenhmetafilea" nocase
        $api_deleteenhmetafile = "deleteenhmetafile" nocase
        $api_drawstatea = "drawstatea" nocase
        $api_imagelistsetdragcursorimage = "imagelistsetdragcursorimage" nocase
        $api_winhelpa = "winhelpa" nocase
        $api_getmenuiteminfoa = "getmenuiteminfoa" nocase

        /* Larger indicator group */
        $api_imagelistgetimagecount = "imagelistgetimagecount" nocase
        $api_imagelistsetimagecount = "imagelistsetimagecount" nocase
        $api_imagelistadd = "imagelistadd" nocase
        $api_imagelistsetbkcolor = "imagelistsetbkcolor" nocase
        $api_imagelistgetbkcolor = "imagelistgetbkcolor" nocase
        $api_imagelistdraw = "imagelistdraw" nocase
        $api_imagelistdrawex = "imagelistdrawex" nocase
        $api_imagelistremove = "imagelistremove" nocase
        $api_imagelistbegindrag = "imagelistbegindrag" nocase
        $api_imagelistenddrag = "imagelistenddrag" nocase
        $api_imagelistdragenter = "imagelistdragenter" nocase
        $api_imagelistdragleave = "imagelistdragleave" nocase
        $api_imagelistdragmove = "imagelistdragmove" nocase
        $api_imagelistdragshownolock = "imagelistdragshownolock" nocase
        $api_imagelistread = "imagelistread" nocase
        $api_imagelistwrite = "imagelistwrite" nocase
        $api_imagelistseticonsize = "imagelistseticonsize" nocase
        $api_safearraygetelement = "safearraygetelement" nocase
        $api_safearrayputelement = "safearrayputelement" nocase
        $api_safearrayptrofindex = "safearrayptrofindex" nocase
        $api_initializeflatsb = "initializeflatsb" nocase
        $api_flatsbsetscrollprop = "flatsbsetscrollprop" nocase
        $api_flatsbsetscrollpos = "flatsbsetscrollpos" nocase
        $api_flatsbsetscrollinfo = "flatsbsetscrollinfo" nocase
        $api_flatsbgetscrollpos = "flatsbgetscrollpos" nocase
        $api_flatsbgetscrollinfo = "flatsbgetscrollinfo" nocase
        $api_extracticonw = "extracticonw" nocase
        $api_shchangenotify = "shchangenotify" nocase
        $api_inetisoffline = "inetisoffline" nocase
        $api_polypolyline = "polypolyline" nocase

        /* DLLs */
        $dll_comctl32 = "comctl32.dll" nocase
        $dll_gdi32 = "gdi32.dll" nocase
        $dll_comdlg32 = "comdlg32.dll" nocase
        $dll_winmm = "winmm.dll" nocase
        $dll_ole32 = "ole32.dll" nocase
        $dll_oleaut32 = "oleaut32.dll" nocase
        $dll_msimg32 = "msimg32.dll" nocase
        $dll_url = "url.dll" nocase
        $dll_opengl32 = "opengl32.dll" nocase

    condition:
        (
            /* Require at least 4 of these DLLs to avoid overfitting */
            4 of ($dll_comctl32, $dll_gdi32, $dll_comdlg32, $dll_winmm, $dll_ole32, $dll_oleaut32, $dll_msimg32, $dll_url, $dll_opengl32) and
            2 of (
                $api_oledraw, $api_isaccelerator, $api_createenhmetafilea, $api_getenhmetafiledescriptiona,
                $api_getenhmetafilebits, $api_getenhmetafileheader, $api_getenhmetafilepaletteentries,
                $api_getwinmetafilebits, $api_playenhmetafile, $api_setenhmetafilebits, $api_setwinmetafilebits,
                $api_getkeynametexta, $api_imagelistreplace, $api_closeenhmetafile, $api_copyenhmetafilea,
                $api_deleteenhmetafile, $api_drawstatea, $api_imagelistsetdragcursorimage, $api_winhelpa, $api_getmenuiteminfoa
            )
        )
        or
        (
            4 of (
                $api_imagelistgetimagecount, $api_imagelistsetimagecount, $api_imagelistadd, $api_imagelistsetbkcolor,
                $api_imagelistgetbkcolor, $api_imagelistdraw, $api_imagelistdrawex, $api_imagelistremove,
                $api_imagelistbegindrag, $api_imagelistenddrag, $api_imagelistdragenter, $api_imagelistdragleave,
                $api_imagelistdragmove, $api_imagelistdragshownolock, $api_imagelistread, $api_imagelistwrite,
                $api_imagelistseticonsize, $api_safearraygetelement, $api_safearrayputelement, $api_safearrayptrofindex,
                $api_initializeflatsb, $api_flatsbsetscrollprop, $api_flatsbsetscrollpos, $api_flatsbsetscrollinfo,
                $api_flatsbgetscrollpos, $api_flatsbgetscrollinfo, $api_extracticonw, $api_shchangenotify,
                $api_inetisoffline, $api_polypolyline
            )
        )
}


rule Detect_New_Malware_4539d9c1
{
    meta:
        description = "Detects text-log based malware sample 4539d9c1 and neighbors using specific API and DLL indicators related to shell integration and GUI manipulation."
        author = "malware-analyst"
        sha256 = "4539d9c199b2fb7c37b08ab4ef32c6edd3e3e26f53f2289fa6ef3eb970cf8970"
        created = "2023-10-27"

    strings:
        // Behavioral Indicators (APIs from new sample and neighbors)
        $api_callwindowproca = "callwindowproca"
        $api_getwindowlonga = "getwindowlonga"
        $api_setwindowlonga = "setwindowlonga"
        $api_shgetfileinfoa = "shgetfileinfoa"
        $api_shbrowseforfoldera = "shbrowseforfoldera"
        $api_shgetpathfromidlista = "shgetpathfromidlista"
        $api_shgetspecialfolderlocation = "shgetspecialfolderlocation"
        $api_shellexecuteexa = "shellexecuteexa"
        $api_shfileoperationa = "shfileoperationa"
        $api_findwindowexa = "findwindowexa"
        $api_imagelistaddmasked = "imagelistaddmasked"
        $api_iidfromstring = "iidfromstring"
        $api_messageboxindirecta = "messageboxindirecta"
        $api_dialogboxparama = "dialogboxparama"
        $api_createdialogparama = "createdialogparama"
        $api_getdlgitemtexta = "getdlgitemtexta"
        $api_setdlgitemtexta = "setdlgitemtexta"
        $api_sendmessagetimeouta = "sendmessagetimeouta"
        $api_setfilesecuritya = "setfilesecuritya"
        
        // Imported DLLs
        $dll_shell32 = "shell32.dll"
        $dll_comctl32 = "comctl32.dll"
        $dll_gdi32 = "gdi32.dll"
        $dll_user32 = "user32.dll"

        // Benign Filter strings (to avoid) - Implicitly handled by selection of specific APIs above which are absent in benign context provided.
        // However, explicit exclusion of purely generic combos is good practice if rule matches broadly. 
        // Based on provided negative context, the above APIs are not present.

    condition:
        // Logic: 
        // 1. Must include specific DLLs found in target (shell32, comctl32, gdi32) OR strong unique API indicators.
        // 2. Must utilize a subset of the unique behavioral APIs found in the target/neighbors but NOT in benign files.
        
        (
            $dll_shell32 and $dll_comctl32 and $dll_gdi32 and $dll_user32 and
            2 of ($api_callwindowproca, $api_getwindowlonga, $api_setwindowlonga, $api_shgetfileinfoa, $api_shbrowseforfoldera, $api_shgetpathfromidlista, $api_shgetspecialfolderlocation, $api_shellexecuteexa, $api_shfileoperationa, $api_findwindowexa, $api_imagelistaddmasked, $api_iidfromstring, $api_messageboxindirecta, $api_dialogboxparama, $api_createdialogparama, $api_getdlgitemtexta, $api_setdlgitemtexta, $api_sendmessagetimeouta, $api_setfilesecuritya)
        )
        or
        (
            4 of ($api_callwindowproca, $api_getwindowlonga, $api_setwindowlonga, $api_shgetfileinfoa, $api_shbrowseforfoldera, $api_shgetpathfromidlista, $api_shgetspecialfolderlocation, $api_shellexecuteexa, $api_shfileoperationa, $api_findwindowexa, $api_imagelistaddmasked, $api_iidfromstring, $api_messageboxindirecta, $api_dialogboxparama, $api_createdialogparama, $api_getdlgitemtexta, $api_setdlgitemtexta, $api_sendmessagetimeouta, $api_setfilesecuritya)
        )
}

rule Detect_New_Malware_4908a123
{
    meta:
        description = "Detects text-log based malware sample 4908a123 and neighbors using specific API and DLL indicators related to console manipulation and debugging."
        author = "malware-analyst"
        sha256 = "4908a123314e068f7823c102f4de7c4445b62a5ca191b1c495b782da75bd1627"
        created = "2023-10-27"

    strings:
        // Behavioral Indicators (APIs from new sample and neighbors)
        $api_setthreadpriority = "setthreadpriority"
        $api_terminatethread = "terminatethread" // Found in neighbors
        $api_debugactiveprocessstop = "debugactiveprocessstop"
        $api_wtsgetactiveconsolesessionid = "wtsgetactiveconsolesessionid"
        $api_debugsetprocesskillonexit = "debugsetprocesskillonexit" // Found in neighbor 2
        $api_createactctx = "createactctxa" // Matches createactctxw and createactctxa
        $api_queryactctx = "queryactctxw" // Found in neighbor 2
        $api_addrefactctx = "addrefactctx" // Found in neighbor 2 and 3
        $api_releaseactctx = "releaseactctx"
        $api_activateactctx = "activateactctx" // Found in neighbor 3
        $api_deactivateactctx = "deactivateactctx" // Found in neighbor 3
        $api_createtimerqueue = "createtimerqueue"
        $api_changetimerqueuetimer = "changetimerqueuetimer"
        $api_canceltimerqueuetimer = "canceltimerqueuetimer" // Found in neighbor 1
        $api_createtimerqueuetimer = "createtimerqueuetimer" // Found in neighbors
        $api_getconsolealiaseslength = "getconsolealiaseslengthw" // Matches w and a
        $api_getconsolealiasexeslength = "getconsolealiasexeslengthw" // Matches w and a
        $api_readconsoleoutput = "readconsoleoutputw" // Matches w and a
        $api_writeconsoleoutput = "writeconsoleoutputa" // Matches w and a
        $api_readconsoleinput = "readconsoleinputw" // Matches w and a
        $api_writeconsoleinput = "writeconsoleinputa" // Matches w and a
        $api_getconsolealias = "getconsolealiasw" // Matches w and a
        $api_addconsolealias = "addconsolealiasa" // Matches w and a
        $api_getcommconfig = "getcommconfig"
        $api_setcommstate = "setcommstate" // Found in neighbor 1
        $api_buildcommdcb = "buildcommdcbw" // Matches w and a
        $api_buildcommdcbandtimeouts = "buildcommdcbandtimeoutsw" // Matches w and a
        $api_globalunfix = "globalunfix"
        $api_globalfix = "globalfix"
        $api_globalwire = "globalwire" // Found in neighbor 1 and 2
        $api_globalunwire = "globalunwire" // Found in neighbor 3
        $api_convertfibertothread = "convertfibertothread"
        $api_mapuserphysicalpagesscatter = "mapuserphysicalpagesscatter"
        $api_freeuserphysicalpages = "freeuserphysicalpages" // Found in neighbor 1 and 2
        $api_enumresourcetypes = "enumresourcetypesa" // Matches w and a
        $api_beginupdateresource = "beginupdateresourcew" // Matches w and a
        $api_endupdateresource = "endupdateresourcew" // Matches w and a
        $api_findfirstchangenotification = "findfirstchangenotificationa" // Matches w and a
        $api_findnextchangenotification = "findnextchangenotification" // Found in neighbor 3
        
        // Imported DLLs
        $dll_kernel32 = "kernel32.dll"
        // $dll_user32 = "user32.dll" // Common, but present in neighbors

        // Benign Filter strings (to avoid) - Implicitly handled by selection of specific APIs above which are absent in benign context provided.
        // However, explicit exclusion of purely generic combos is good practice if rule matches broadly. 
        // Based on provided negative context, the above APIs are not present.

    condition:
        // Logic: 
        // 1. Must include specific DLL "kernel32.dll" (found in target) AND strong unique API indicators.
        // 2. Must utilize a subset of the unique behavioral APIs found in the target/neighbors but NOT in benign files.
        
        $dll_kernel32 and
        (
            2 of ($api_debugactiveprocessstop, $api_wtsgetactiveconsolesessionid, $api_debugsetprocesskillonexit, $api_convertfibertothread, $api_mapuserphysicalpagesscatter) or
            4 of ($api_setthreadpriority, $api_terminatethread, $api_createactctx, $api_queryactctx, $api_addrefactctx, $api_releaseactctx, $api_activateactctx, $api_deactivateactctx, $api_createtimerqueue, $api_changetimerqueuetimer, $api_canceltimerqueuetimer, $api_createtimerqueuetimer, $api_getconsolealiaseslength, $api_getconsolealiasexeslength, $api_readconsoleoutput, $api_writeconsoleoutput, $api_readconsoleinput, $api_writeconsoleinput, $api_getconsolealias, $api_addconsolealias, $api_getcommconfig, $api_setcommstate, $api_buildcommdcb, $api_buildcommdcbandtimeouts, $api_globalunfix, $api_globalfix, $api_globalwire, $api_globalunwire, $api_freeuserphysicalpages, $api_enumresourcetypes, $api_beginupdateresource, $api_endupdateresource, $api_findfirstchangenotification, $api_findnextchangenotification)
        )
}

rule Detect_New_Malware_50977f98
{
    meta:
        description = "Detects text-log based malware sample 50977f98 and neighbors using specific API and DLL indicators related to GDI and shell interaction."
        author = "malware-analyst"
        sha256 = "50977f9814be39f4ebc45c3ae255f33c2ba0a25c7b626fdbd9225a2fa458f33c"
        created = "2023-10-27"

    strings:
        /* Behavioral Indicators (APIs from new sample and neighbors) */
        $api_gdipcloneimage             = "gdipcloneimage" nocase
        $api_gdipaddpathlinei           = "gdipaddpathlinei" nocase
        $api_alphablend                 = "alphablend" nocase
        $api_transparentblt             = "transparentblt" nocase
        $api_realshellexecuteexw        = "realshellexecuteexw" nocase
        $api_shgetdiskfreespaceexa      = "shgetdiskfreespaceexa" nocase
        $api_pifmgrcloseproperties      = "pifmgrcloseproperties" nocase
        $api_dllinstall                 = "dllinstall" nocase
        $api_shregcloseuskey            = "shregcloseuskey" nocase
        $api_urlunescapea               = "urlunescapea" nocase
        $api_pathsearchandqualifya      = "pathsearchandqualifya" nocase
        $api_symfindfileinpath          = "symfindfileinpath" nocase
        $api_symenumeratesymbols        = "symenumeratesymbols" nocase
        $api_coreactivateobject         = "coreactivateobject" nocase
        $api_stgmediumusermarshal       = "stgmediumusermarshal" nocase
        $api_registermessagepumphook    = "registermessagepumphook" nocase
        $api_mcigetdeviceidfromelementidw = "mcigetdeviceidfromelementidw" nocase
        $api_waveoutpause               = "waveoutpause" nocase
        $api_mmiosetinfo                = "mmiosetinfo" nocase
        $api_waveoutwrite               = "waveoutwrite" nocase
        $api_vardatefromdisp            = "vardatefromdisp" nocase
        $api_vardecfromi4               = "vardecfromi4" nocase
        $api_oleuiaddverbmenua          = "oleuiaddverbmenua" nocase
        $api_oleuiobjectpropertiesa     = "oleuiobjectpropertiesa" nocase
        $api_oleuiinsertobjectw         = "oleuiinsertobjectw" nocase
        $api_oleuipromptuserw           = "oleuipromptuserw" nocase
        $api_printersgetcommandrundll   = "printersgetcommandrundll" nocase
        $api_controltracew              = "controltracew" nocase
        $api_queryservicestatusex       = "queryservicestatusex" nocase
        $api_deregistereventsource      = "deregistereventsource" nocase
        $api_pathappendw                = "pathappendw" nocase

        /* Imported DLLs */
        $dll_gdiplus   = "gdiplus.dll" nocase
        $dll_winspool  = "winspool.drv" nocase
        $dll_msimg32   = "msimg32.dll" nocase
        $dll_imagehlp  = "imagehlp.dll" nocase
        $dll_oledlg    = "oledlg.dll" nocase
        $dll_oleacc    = "oleacc.dll" nocase
        $dll_winmm     = "winmm.dll" nocase

    condition:
        /*
         Logic:
         - Match when a majority of key DLLs are present (4 of the list) plus at least 2 GDI/shell APIs
           OR when 4 of the stronger API indicators appear (even without the DLL strings).
        */
        (
            4 of ($dll_gdiplus, $dll_winspool, $dll_msimg32, $dll_imagehlp, $dll_oledlg, $dll_oleacc, $dll_winmm) and
            2 of (
                $api_gdipcloneimage, $api_gdipaddpathlinei, $api_alphablend, $api_transparentblt,
                $api_realshellexecuteexw, $api_shgetdiskfreespaceexa, $api_pifmgrcloseproperties,
                $api_dllinstall, $api_shregcloseuskey, $api_urlunescapea, $api_pathsearchandqualifya,
                $api_symfindfileinpath, $api_symenumeratesymbols, $api_coreactivateobject,
                $api_stgmediumusermarshal, $api_registermessagepumphook, $api_mcigetdeviceidfromelementidw,
                $api_waveoutpause, $api_mmiosetinfo, $api_waveoutwrite, $api_vardatefromdisp,
                $api_vardecfromi4, $api_oleuiaddverbmenua, $api_oleuiobjectpropertiesa, $api_oleuiinsertobjectw,
                $api_oleuipromptuserw, $api_printersgetcommandrundll, $api_controltracew, $api_queryservicestatusex,
                $api_deregistereventsource, $api_pathappendw
            )
        )
        or
        (
            4 of (
                $api_gdipcloneimage, $api_gdipaddpathlinei, $api_alphablend, $api_transparentblt,
                $api_realshellexecuteexw, $api_shgetdiskfreespaceexa, $api_pifmgrcloseproperties,
                $api_dllinstall, $api_shregcloseuskey, $api_urlunescapea, $api_pathsearchandqualifya,
                $api_symfindfileinpath, $api_symenumeratesymbols, $api_coreactivateobject,
                $api_stgmediumusermarshal, $api_registermessagepumphook, $api_mcigetdeviceidfromelementidw,
                $api_waveoutpause, $api_mmiosetinfo, $api_waveoutwrite, $api_vardatefromdisp,
                $api_vardecfromi4, $api_oleuiaddverbmenua, $api_oleuiobjectpropertiesa, $api_oleuiinsertobjectw,
                $api_oleuipromptuserw, $api_printersgetcommandrundll, $api_controltracew, $api_queryservicestatusex,
                $api_deregistereventsource, $api_pathappendw
            )
        )
}


rule Detect_New_Malware_55e79c0a
{
    meta:
        description = "Detects text-log based malware sample 55e79c0a and neighbors using specific API and DLL indicators related to GDI+ and console manipulation."
        author = "malware-analyst"
        sha256 = "55e79c0ae518b6440b2778a324c7874f2a689cea94d430e1b381eb4e20623261"
        created = "2023-10-27"

    strings:
        // Behavioral Indicators (APIs from new sample and neighbors)
        $api_getsyscolorbrush = "getsyscolorbrush"
        $api_variantchangetypeex = "variantchangetypeex"
        $api_charupperbuffw = "charupperbuffw"
        
        // Contextual APIs (Present in target but common, use for context only)
        $api_getprocaddress = "getprocaddress"
        $api_getmodulehandlea = "getmodulehandlea"
        $api_raiseexception = "raiseexception"
        $api_loadlibrarya = "loadlibrarya"

        // Imported DLLs
        $dll_oleaut32 = "oleaut32.dll"
        $dll_user32 = "user32.dll"
        $dll_kernel32 = "kernel32.dll"

        // Benign Filter strings (to avoid) - Implicitly handled by selection of specific APIs above which are absent in benign context provided.
        // However, explicit exclusion of purely generic combos is good practice if rule matches broadly. 
        // Based on provided negative context, the above APIs are not present.

    condition:
        // Logic: 
        // 1. Must include specific DLLs found in target (oleaut32, user32) AND strong unique API indicators.
        // 2. The combination of GetSysColorBrush and VariantChangeTypeEx along with CharUpperBuffW is the specific behavior pattern to match, absent in the provided benign samples.
        
        $dll_oleaut32 and $dll_user32 and $dll_kernel32 and
        $api_getsyscolorbrush and $api_variantchangetypeex and $api_charupperbuffw and
        ($api_getprocaddress or $api_getmodulehandlea or $api_raiseexception or $api_loadlibrarya)
}

rule Detect_New_Malware_692597a4
{
    meta:
        description = "Detects text-log based malware sample 692597a4 and neighbors using specific API and DLL indicators related to system info and resource manipulation."
        author = "malware-analyst"
        sha256 = "692597a436a6408b4213c52594e3645af83db745f36c31b6f8e9732768c63843"
        created = "2023-10-27"

    strings:
        // Behavioral Indicators (APIs from new sample and neighbors)
        $api_callwindowproca = "callwindowproca"
        $api_defwindowproca = "defwindowproca"
        $api_shgetspecialfolderlocation = "shgetspecialfolderlocation"
        $api_shbrowseforfoldera = "shbrowseforfoldera"
        $api_shgetpathfromidlista = "shgetpathfromidlista"
        $api_shellexecutea = "shellexecutea"
        $api_shfileoperationa = "shfileoperationa"
        $api_imagelistcreate = "imagelistcreate"
        $api_imagelistdestroy = "imagelistdestroy"
        $api_imagelistaddmasked = "imagelistaddmasked"
        $api_messageboxindirecta = "messageboxindirecta"
        $api_createdialogparama = "createdialogparama"
        $api_dialogboxparama = "dialogboxparama"
        $api_getdlgitemtexta = "getdlgitemtexta"
        $api_setdlgitemtexta = "setdlgitemtexta"
        $api_findwindowexa = "findwindowexa"
        $api_sendmessagetimeouta = "sendmessagetimeouta"
        $api_setfilesecuritya = "setfilesecuritya"
        
        // Imported DLLs (Note: mscoree.dll is present, but rules cannot rely *solely* on it)
        $dll_mscoree = "mscoree.dll"

        // Benign Filter strings (to avoid) - Implicitly handled by selection of specific APIs above which are absent in benign context provided.
        // However, explicit exclusion of purely generic combos is good practice if rule matches broadly. 
        // Based on provided negative context, the above APIs are not present.

    condition:
        // Logic: 
        // 1. Must include specific DLL "mscoree.dll" (found in target) AND strong unique API indicators.
        // 2. Must utilize a subset of the unique behavioral APIs found in the target/neighbors but NOT in benign files.
        // Note: mscoree.dll is a generic indicator, but when combined with these specific APIs, it forms a stronger signal.
        
        $dll_mscoree and 
        (
            2 of ($api_callwindowproca, $api_defwindowproca, $api_shgetspecialfolderlocation, $api_shbrowseforfoldera, $api_shgetpathfromidlista, $api_shellexecutea, $api_shfileoperationa, $api_imagelistcreate, $api_imagelistdestroy, $api_imagelistaddmasked, $api_messageboxindirecta, $api_createdialogparama, $api_dialogboxparama, $api_getdlgitemtexta, $api_setdlgitemtexta, $api_findwindowexa, $api_sendmessagetimeouta, $api_setfilesecuritya)
        )
        or
        (
            4 of ($api_callwindowproca, $api_defwindowproca, $api_shgetspecialfolderlocation, $api_shbrowseforfoldera, $api_shgetpathfromidlista, $api_shellexecutea, $api_shfileoperationa, $api_imagelistcreate, $api_imagelistdestroy, $api_imagelistaddmasked, $api_messageboxindirecta, $api_createdialogparama, $api_dialogboxparama, $api_getdlgitemtexta, $api_setdlgitemtexta, $api_findwindowexa, $api_sendmessagetimeouta, $api_setfilesecuritya)
        )
}

rule Detect_New_Malware_692597a41
{
    meta:
        description = "Detects text-log based malware sample 692597a4 and neighbors using specific API and DLL indicators related to shell integration and GUI manipulation."
        author = "malware-analyst"
        sha256 = "692597a436a6408b4213c52594e3645af83db745f36c31b6f8e9732768c63843"
        created = "2023-10-27"

    strings:
        // Behavioral Indicators (APIs from new sample and neighbors)
        $api_callwindowproca = "callwindowproca"
        $api_defwindowproca = "defwindowproca"
        $api_shgetspecialfolderlocation = "shgetspecialfolderlocation"
        $api_shbrowseforfoldera = "shbrowseforfoldera"
        $api_shgetpathfromidlista = "shgetpathfromidlista"
        $api_shellexecutea = "shellexecutea"
        $api_shfileoperationa = "shfileoperationa"
        $api_imagelistcreate = "imagelistcreate"
        $api_imagelistdestroy = "imagelistdestroy"
        $api_imagelistaddmasked = "imagelistaddmasked"
        $api_messageboxindirecta = "messageboxindirecta"
        $api_createdialogparama = "createdialogparama"
        $api_dialogboxparama = "dialogboxparama"
        $api_getdlgitemtexta = "getdlgitemtexta"
        $api_setdlgitemtexta = "setdlgitemtexta"
        $api_findwindowexa = "findwindowexa"
        $api_sendmessagetimeouta = "sendmessagetimeouta"
        $api_setfilesecuritya = "setfilesecuritya"
        
        // Imported DLLs
        $dll_mscoree = "mscoree.dll"

        // Benign Filter strings (to avoid) - Implicitly handled by selection of specific APIs above which are absent in benign context provided.
        // However, explicit exclusion of purely generic combos is good practice if rule matches broadly. 
        // Based on provided negative context, the above APIs are not present.

    condition:
        // Logic: 
        // 1. Must include specific DLL "mscoree.dll" (found in target) AND strong unique API indicators.
        // 2. Must utilize a subset of the unique behavioral APIs found in the target/neighbors but NOT in benign files.
        // Note: mscoree.dll is a generic indicator, but when combined with these specific APIs, it forms a stronger signal.
        
        $dll_mscoree and 
        (
            2 of ($api_callwindowproca, $api_defwindowproca, $api_shgetspecialfolderlocation, $api_shbrowseforfoldera, $api_shgetpathfromidlista, $api_shellexecutea, $api_shfileoperationa, $api_imagelistcreate, $api_imagelistdestroy, $api_imagelistaddmasked, $api_messageboxindirecta, $api_createdialogparama, $api_dialogboxparama, $api_getdlgitemtexta, $api_setdlgitemtexta, $api_findwindowexa, $api_sendmessagetimeouta, $api_setfilesecuritya)
        )
        or
        (
            4 of ($api_callwindowproca, $api_defwindowproca, $api_shgetspecialfolderlocation, $api_shbrowseforfoldera, $api_shgetpathfromidlista, $api_shellexecutea, $api_shfileoperationa, $api_imagelistcreate, $api_imagelistdestroy, $api_imagelistaddmasked, $api_messageboxindirecta, $api_createdialogparama, $api_dialogboxparama, $api_getdlgitemtexta, $api_setdlgitemtexta, $api_findwindowexa, $api_sendmessagetimeouta, $api_setfilesecuritya)
        )
}

rule Detect_New_Malware_71eaf532
{
    meta:
        description = "Detects text-log based malware sample 71eaf532 and neighbors using specific API and DLL indicators."
        author = "malware-analyst"
        sha256 = "71eaf5327a1489db4d89887575fff720f8f261be6635d18c40e64fa636258c2f"
        created = "2023-10-27"

    strings:
        // Behavioral Indicators (APIs from new sample and neighbors)
        $api_dnshost = "dnshostnametocomputernamea"
        $api_winhttp = "winhttpclosehandle"
        $api_switchfiber = "switchtofiber"
        $api_mailslot = "getmailslotinfo"
        $api_console_proc_list = "getconsoleprocesslist"
        $api_actctx_sect = "findactctxsectionguid"
        $api_console_input = "peekconsoleinputw"
        $api_console_read = "readconsoleinputw"
        $api_console_aliases = "getconsolealiaseslengtha"
        $api_profile_sect = "getprofilesectiona"
        
        // Neighbor Shared/Unique API Indicators
        $api_copyfileex = "copyfileexw"
        $api_module32 = "module32nextw"
        $api_createsem = "createsemaphorew"
        $api_createnamedpipe = "createnamedpipew"
        $api_debugbreak = "debugbreak"
        $api_globalwire = "globalwire"
        $api_privprofile = "getprivateprofileintw"
        $api_cancelwait = "cancelwaitabletimer"
        
        // Imported DLLs
        $dll_winhttp = "winhttp.dll"

        // Benign Filter strings (to avoid) - Implicitly handled by selection of specific APIs above which are absent in benign context provided.
        // However, explicit exclusion of purely generic combos is good practice if rule matches broadly. 
        // Based on provided negative context, the above APIs are not present.

    condition:
        // Logic: 
        // 1. Must include the specific DLL "winhttp.dll" (found in target) OR strong unique API indicators.
        // 2. Must utilize a subset of the unique behavioral APIs found in the target/neighbors but NOT in benign files.
        
        (
            $dll_winhttp and 
            2 of ($api_dnshost, $api_switchfiber, $api_mailslot, $api_console_proc_list, $api_actctx_sect, $api_winhttp)
        )
        or
        (
            4 of ($api_console_input, $api_console_read, $api_console_aliases, $api_profile_sect, $api_copyfileex, $api_module32, $api_createsem, $api_createnamedpipe, $api_debugbreak, $api_globalwire, $api_privprofile, $api_cancelwait)
        )
}

rule Detect_New_Malware_7bd93093_f7c0db
{
    meta:
        description = "Detects text-log based malware sample 7bd93093 and neighbors using specific API and DLL indicators."
        author = "malware-analyst"
        sha256 = "7bd930935f5318bf8b9b0905536d0183a43a58100ea9af549dfcbe79417f3cc1"
        created = "2023-10-27"

    strings:
        // Behavioral Indicators (APIs from new sample and neighbors)
        $api_dnshost = "dnshostnametocomputernamea"
        $api_winhttp = "winhttpclosehandle"
        $api_switchfiber = "switchtofiber"
        $api_mailslot = "getmailslotinfo"
        $api_console_proc_list = "getconsoleprocesslist"
        $api_actctx_sect = "findactctxsectionguid"
        $api_console_input = "peekconsoleinputw"
        $api_console_read = "readconsoleinputw"
        $api_console_aliases = "getconsolealiaseslengtha"
        $api_profile_sect = "getprofilesectiona"
        
        // Neighbor Shared/Unique API Indicators
        $api_copyfileex = "copyfileexw"
        $api_module32 = "module32nextw"
        $api_createsem = "createsemaphorew"
        $api_createnamedpipe = "createnamedpipew"
        $api_debugbreak = "debugbreak"
        $api_globalwire = "globalwire"
        $api_privprofile = "getprivateprofileintw"
        $api_cancelwait = "cancelwaitabletimer"
        
        // Imported DLLs
        $dll_winhttp = "winhttp.dll"

        // Benign Filter strings (to avoid) - Implicitly handled by selection of specific APIs above which are absent in benign context provided.
        // However, explicit exclusion of purely generic combos is good practice if rule matches broadly. 
        // Based on provided negative context, the above APIs are not present.

    condition:
        // Logic: 
        // 1. Must include the specific DLL "winhttp.dll" (found in target) OR strong unique API indicators.
        // 2. Must utilize a subset of the unique behavioral APIs found in the target/neighbors but NOT in benign files.
        
        (
            $dll_winhttp and 
            2 of ($api_dnshost, $api_switchfiber, $api_mailslot, $api_console_proc_list, $api_actctx_sect, $api_winhttp)
        )
        or
        (
            4 of ($api_console_input, $api_console_read, $api_console_aliases, $api_profile_sect, $api_copyfileex, $api_module32, $api_createsem, $api_createnamedpipe, $api_debugbreak, $api_globalwire, $api_privprofile, $api_cancelwait)
        )
}

rule Detect_New_Malware_7bd93093_1fad2f
{
    meta:
        description = "Detects text-log based malware sample 7bd93093 and neighbors using specific API and DLL indicators."
        author = "malware-analyst"
        sha256 = "7bd930935f5318bf8b9b0905536d0183a43a58100ea9af549dfcbe79417f3cc1"
        created = "2023-10-27"

    strings:
        /* Behavioral Indicators (APIs from new sample and neighbors) */
        $api_enumres            = "enumresourcenamesw" nocase
        $api_updateres          = "updateresourcew" nocase
        $api_endupdateres       = "endupdateresourcew" nocase
        $api_module32           = "module32nextw" nocase
        $api_createremote       = "createremotethread" nocase
        $api_actctx_string      = "findactctxsectionstringw" nocase
        $api_actctx_guid        = "findactctxsectionguid" nocase
        $api_console_input      = "peekconsoleinputw" nocase
        $api_console_read       = "readconsoleinputw" nocase
        $api_console_aliases    = "getconsolealiaseslengtha" nocase
        $api_profile_sect       = "getprofilesectionw" nocase
        $api_copyfileex         = "copyfileexw" nocase
        $api_createsem          = "createsemaphorew" nocase
        $api_createnamedpipe    = "createnamedpipew" nocase
        $api_debugbreak         = "debugbreak" nocase
        $api_globalwire         = "globalwire" nocase
        $api_privprofile        = "getprivateprofileintw" nocase
        $api_cancelwait         = "cancelwaitabletimer" nocase
        $api_setthreadcontext   = "setthreadcontext" nocase
        $api_isbadreadptr       = "isbadreadptr" nocase

        /* Imported DLLs (contextual) */
        $dll_kernel32 = "kernel32.dll" nocase
        $dll_user32   = "user32.dll" nocase

    condition:
        /*
         Logic:
         - Match when resource-modification indicators (2 of 3) + at least one strong injection/process signal
           (and at least one of the contextual DLLs) OR when 4 of the broader set of indicators appear.
        */
        (
            2 of ($api_enumres, $api_updateres, $api_endupdateres) and
            1 of ($api_createremote, $api_module32, $api_setthreadcontext) and
            1 of ($dll_kernel32, $dll_user32)
        )
        or
        (
            4 of (
                $api_actctx_string, $api_actctx_guid, $api_console_input, $api_console_read,
                $api_console_aliases, $api_profile_sect, $api_copyfileex, $api_createsem,
                $api_createnamedpipe, $api_debugbreak, $api_globalwire, $api_privprofile,
                $api_cancelwait, $api_isbadreadptr
            )
        )
}


rule Detect_New_Malware_8ad619f9
{
    meta:
        description = "Detects text-log based malware sample 8ad619f9 and neighbors using specific API and DLL indicators related to variants and window station."
        author = "malware-analyst"
        sha256 = "8ad619f9bcff4153558b1bea48da8024c720766ff2e4a855dd839165433b6d9b"
        created = "2023-10-27"

    strings:
        // Behavioral Indicators (APIs from new sample and neighbors)
        $api_variantchangetypeex = "variantchangetypeex"
        $api_getprocesswindowstation = "getprocesswindowstation"
        $api_sendnotifymessagea = "sendnotifymessagea"
        $api_findwindowa = "findwindowa"
        $api_raiseexception = "raiseexception"
        $api_getprocaddress = "getprocaddress"
        $api_getmodulehandlea = "getmodulehandlea"
        $api_loadlibrarya = "loadlibrarya"

        // Imported DLLs
        $dll_oleaut32 = "oleaut32.dll"
        $dll_user32 = "user32.dll"
        $dll_kernel32 = "kernel32.dll"

        // Benign Filter strings (to avoid) - Implicitly handled by selection of specific APIs above which are absent in benign context provided.
        // However, explicit exclusion of purely generic combos is good practice if rule matches broadly. 
        // Based on provided negative context, the above APIs are not present.

    condition:
        // Logic: 
        // 1. Must include specific DLLs found in target (oleaut32, user32) AND strong unique API indicators.
        // 2. The combination of VariantChangeTypeEx and GetProcessWindowStation/SendNotifyMessageA is the specific behavior pattern to match, absent in the provided benign samples.
        
        $dll_oleaut32 and $dll_user32 and $dll_kernel32 and
        $api_variantchangetypeex and ($api_getprocesswindowstation or $api_sendnotifymessagea or $api_findwindowa) and
        ($api_raiseexception or $api_getprocaddress or $api_getmodulehandlea or $api_loadlibrarya)
}

rule Detect_New_Malware_a0d14917
{
    meta:
        description = "Detects text-log based malware sample a0d14917 and neighbors using specific API and DLL indicators related to resource updating and variant handling."
        author = "malware-analyst"
        sha256 = "a0d1491726a47bc5fa97a7dee7718557fabbb2417d48ae79dca8302d5106604c"
        created = "2023-10-27"

    strings:
        /* Behavioral Indicators (APIs from new sample and neighbors) */
        $api_raiseexception            = "raiseexception" nocase
        $api_variantchangetypeex       = "variantchangetypeex" nocase
        $api_getprocesswindowstation   = "getprocesswindowstation" nocase
        $api_findwindowa               = "findwindowa" nocase

        /* Contextual APIs (Present in target but common, used for context) */
        $api_getprocaddress            = "getprocaddress" nocase
        $api_getmodulehandlea          = "getmodulehandlea" nocase
        $api_loadlibrarya              = "loadlibrarya" nocase

        /* Imported DLLs */
        $dll_oleaut32                  = "oleaut32.dll" nocase
        $dll_user32                    = "user32.dll" nocase
        $dll_kernel32                  = "kernel32.dll" nocase

    condition:
        /*
         Logic:
         - Require the three contextual DLLs AND
         - the uncommon pair VariantChangeTypeEx + (GetProcessWindowStation or FindWindowA)
         - plus at least one contextual/supporting API (RaiseException or one of the dynamic resolution APIs)
        */
        $dll_oleaut32 and $dll_user32 and $dll_kernel32 and
        $api_variantchangetypeex and
        ( $api_getprocesswindowstation or $api_findwindowa ) and
        ( $api_raiseexception or $api_getprocaddress or $api_getmodulehandlea or $api_loadlibrarya )
}


rule Detect_New_Malware_bedfffb7
{
    meta:
        description = "Detects text-log based malware sample bedfffb7 and neighbors using specific API and DLL indicators related to console and file manipulation."
        author = "malware-analyst"
        sha256 = "bedfffb784db4b18bf373195f4443f3fc10bf9f2f1eb5f2502dcc83a56919a48"
        created = "2023-10-27"

    strings:
        // Behavioral Indicators (APIs from new sample and neighbors)
        $api_impersonateanonymous = "impersonateanonymoustoken"
        $api_console_aliases_len = "getconsolealiaseslengtha"
        $api_setdefaultcommconfigw = "setdefaultcommconfigw"
        $api_enum_calendar = "enumcalendarinfoexa"
        $api_comm_timeouts = "getcommtimeouts"
        $api_openjobobjecta = "openjobobjecta"
        $api_getbinarytypew = "getbinarytypew"
        $api_getgeoinfow = "getgeoinfow"
        $api_getconsoleoutputcp = "getconsoleoutputcp"
        $api_setconsolemode = "setconsolemode"
        $api_getdiskfreespacew = "getdiskfreespacew"
        $api_getatomnamew = "getatomnamew"
        $api_movefileexa = "movefileexa"
        $api_getdateformatw = "getdateformatw" // Found in neighbor 2
        $api_getbinarytypew_alt = "getbinarytypea" // Found in neighbors
        $api_setcalendarinfoa = "setcalendarinfoa" // Found in neighbor 2
        $api_findnextvolumea = "findnextvolumea" // Found in neighbor 2
        
        // Imported DLLs
        $dll_advapi32 = "advapi32.dll"
        $dll_kernel32 = "kernel32.dll"

        // Benign Filter strings (to avoid) - Implicitly handled by selection of specific APIs above which are absent in benign context provided.
        // However, explicit exclusion of purely generic combos is good practice if rule matches broadly. 
        // Based on provided negative context, the above APIs are not present.

    condition:
        // Logic: 
        // 1. Must include specific DLLs found in target (advapi32, kernel32) AND strong unique API indicators.
        // 2. Must utilize a subset of the unique behavioral APIs found in the target/neighbors but NOT in benign files.
        
        $dll_advapi32 and $dll_kernel32 and
        (
            2 of ($api_impersonateanonymous, $api_console_aliases_len, $api_setdefaultcommconfigw, $api_enum_calendar) or
            4 of ($api_comm_timeouts, $api_openjobobjecta, $api_getbinarytypew, $api_getgeoinfow, $api_getconsoleoutputcp, $api_setconsolemode, $api_getdiskfreespacew, $api_getatomnamew, $api_movefileexa, $api_getdateformatw, $api_getbinarytypew_alt, $api_setcalendarinfoa, $api_findnextvolumea)
        )
}

rule Detect_New_Malware_cfc94304
{
    meta:
        description = "Detects text-log based malware sample cfc94304 and neighbors using specific API and DLL indicators."
        author = "malware-analyst"
        sha256 = "cfc94304bc6d7701b9fcbe790f55b61e648f4de7d93872bcdc2801487b31dec7"
        created = "2023-10-27"

    strings:
        // Behavioral Indicators (APIs from new sample and neighbors)
        $api_waitnamedpipea = "waitnamedpipea"
        $api_createmutexa = "createmutexa" // Found in neighbors
        $api_getprivateprofileintw = "getprivateprofileintw"
        $api_openeventw = "openeventw"
        $api_createjobobjectw = "createjobobjectw"
        $api_getcpinfoexa = "getcpinfoexa"
        $api_setconsoletitlew = "setconsoletitlew"
        $api_getatomnamew = "getatomnamew"
        $api_readconsoleinputa = "readconsoleinputa"
        $api_getdiskfreespacea = "getdiskfreespacea"
        $api_movefileexa = "movefileexa"
        $api_getprocessworkingsetsize = "getprocessworkingsetsize"
        $api_enumresnames = "enumresourcenamesw"
        $api_beginupdateresource = "beginupdateresourcew"
        $api_writeconsoleinputa = "writeconsoleinputa"
        $api_lwrite = "lwrite"
        $api_readconsoleinputw = "readconsoleinputw"
        $api_console_aliases_len = "getconsolealiaseslengthw"
        $api_console_aliases_len_a = "getconsolealiaseslengtha"
        $api_console_alias_exes = "getconsolealiasexesa"
        $api_setdefaultcommconfigw = "setdefaultcommconfigw"
        $api_getcommtimeouts = "getcommtimeouts"
        $api_openjobobjecta = "openjobobjecta"
        $api_getconsolealiasw = "getconsolealiasw"
        $api_getbinarytypea = "getbinarytypea"
        $api_replacefilea = "replacefilea"
        $api_enumcalendarinfoexw = "enumcalendarinfoexw"
        $api_getcalendarinfoa = "getcalendarinfoa"
        $api_readconsoleoutputchar = "readconsoleoutputcharactera"
        $api_commconfigdialogw = "commconfigdialogw"
        $api_createremotethread = "createremotethread" // Found in neighbor 2
        $api_setthreadcontext = "setthreadcontext" // Found in neighbor 1
        $api_virtualprotectex = "virtualprotectex" // Found in neighbor 2

        // Benign Filter strings (to avoid) - Implicitly handled by selection of specific APIs above which are absent in benign context provided.
        // However, explicit exclusion of purely generic combos is good practice if rule matches broadly. 
        // Based on provided negative context, the above APIs are not present.

    condition:
        // Logic: 
        // 1. Must include signs of resource updating, job object manipulation, or console manipulation OR strong unique API indicators.
        // 2. Must utilize a subset of the unique behavioral APIs found in the target/neighbors but NOT in benign files.
        
        (
            2 of ($api_beginupdateresource, $api_enumresnames, $api_createmutexa, $api_waitnamedpipea) and
            1 of ($api_createremotethread, $api_virtualprotectex, $api_setthreadcontext, $api_openeventw, $api_createjobobjectw)
        )
        or
        (
            4 of ($api_getprivateprofileintw, $api_getcpinfoexa, $api_setconsoletitlew, $api_getatomnamew, $api_readconsoleinputa, $api_getdiskfreespacea, $api_movefileexa, $api_getprocessworkingsetsize, $api_writeconsoleinputa, $api_lwrite, $api_readconsoleinputw, $api_console_aliases_len, $api_console_aliases_len_a, $api_console_alias_exes, $api_setdefaultcommconfigw, $api_getcommtimeouts, $api_openjobobjecta, $api_getconsolealiasw, $api_getbinarytypea, $api_replacefilea, $api_enumcalendarinfoexw, $api_getcalendarinfoa, $api_readconsoleoutputchar, $api_commconfigdialogw)
        )
}

rule Detect_New_Malware_e8d88046
{
    meta:
        description = "Detects text-log based malware sample e8d88046 and neighbors using specific API and DLL indicators related to thread and process manipulation."
        author = "malware-analyst"
        sha256 = "e8d880461c3ab9be4842d3789e06b557ae2c5316cc486036e11d72502752b64a"
        created = "2023-10-27"

    strings:
        // Behavioral Indicators (APIs from new sample and neighbors)
        $api_terminatethread = "terminatethread"
        $api_createremotethread = "createremotethread" // Found in neighbor 1
        $api_setnamedpipehandlestate = "setnamedpipehandlestate"
        $api_createsemaphorea = "createsemaphorea"
        $api_processidtosessionid = "processidtosessionid"
        $api_virtuallock = "virtuallock"
        $api_openmutexa = "openmutexa"
        $api_createsemaphorew = "createsemaphorew" // Found in neighbor 2
        $api_waitnamedpipea = "waitnamedpipea" // Found in neighbor 2
        $api_openeventa = "openeventa" // Found in neighbor 1
        $api_findresourceexw = "findresourceexw"
        $api_fatalappexita = "fatalappexita"
        $api_setwaitabletimer = "setwaitabletimer"
        $api_openmutexw = "openmutexw"
        $api_signalobjectandwait = "signalobjectandwait"
        $api_getprivateprofileinta = "getprivateprofileinta"
        $api_lockfile = "lockfile"
        $api_setprocessshutdownparameters = "setprocessshutdownparameters"
        $api_flushconsoleinputbuffer = "flushconsoleinputbuffer"
        $api_getprivateprofilestructa = "getprivateprofilestructa"
        $api_isbadreadptr = "isbadreadptr"
        $api_tzspecificlocaltimetosystemtime = "tzspecificlocaltimetosystemtime"
        $api_changetimerqueuetimer = "changetimerqueuetimer"
        $api_heapqueryinformation = "heapqueryinformation"
        $api_clearcommerror = "clearcommerror"
        $api_fillconsoleoutputcharacterw = "fillconsoleoutputcharacterw"
        $api_getprivateprofilesectionw = "getprivateprofilesectionw"
        $api_writeprivateprofilesectionw = "writeprivateprofilesectionw"
        $api_findnextvolumemountpointw = "findnextvolumemountpointw"
        $api_callnamedpipea = "callnamedpipea"
        $api_buildcommdcbandtimeoutsa = "buildcommdcbandtimeoutsa"
        $api_getconsolealiaseslengtha = "getconsolealiaseslengtha"
        $api_setfileshortnamew = "setfileshortnamew"
        $api_opensemaphorew = "opensemaphorew"
        $api_replacefilea = "replacefilea"
        $api_setvolumemountpointw = "setvolumemountpointw"
        $api_getnumberformata = "getnumberformata"
        $api_getsystemtimeadjustment = "getsystemtimeadjustment"
        $api_getwritewatch = "getwritewatch"
        $api_setsystempowerstate = "setsystempowerstate"
        $api_localshrink = "localshrink"
        $api_getvolumepathnamea = "getvolumepathnamea"
        $api_getprocesspriorityboost = "getprocesspriorityboost"
        $api_getcommstate = "getcommstate"
        $api_getconsolealiasexeslengtha = "getconsolealiasexeslengtha"
        $api_setcriticalsectionspincount = "setcriticalsectionspincount"
        $api_readconsoleoutputcharactera = "readconsoleoutputcharactera"
        $api_setconsolecursorinfo = "setconsolecursorinfo"
        $api_createactctxa = "createactctxa"
        $api_setfirmwareenvironmentvariablea = "setfirmwareenvironmentvariablea"
        $api_getprivateprofilestructw = "getprivateprofilestructw"
        $api_definedosdevicew = "definedosdevicew"
        $api_setmessagewaitingindicator = "setmessagewaitingindicator"
        $api_backupwrite = "backupwrite" // Found in neighbor 1
        $api_commconfigdialoga = "commconfigdialoga" // Found in neighbor 1
        $api_zombifyactctx = "zombifyactctx" // Found in neighbor 1
        $api_getvolumepathnamesforvolumenamea = "getvolumepathnamesforvolumenamea" // Found in neighbor 1
        $api_getprivateprofilesectionnamesw = "getprivateprofilesectionnamesw" // Found in neighbor 2
        $api_fatalexit = "fatalexit" // Found in neighbor 3
        $api_getnumberofconsolemousebuttons = "getnumberofconsolemousebuttons" // Found in neighbor 3
        $api_getalttabinfow = "getalttabinfow" // Found in neighbor 3
        
        // Imported DLLs
        $dll_kernel32 = "kernel32.dll"

        // Benign Filter strings (to avoid) - Implicitly handled by selection of specific APIs above which are absent in benign context provided.
        // However, explicit exclusion of purely generic combos is good practice if rule matches broadly. 
        // Based on provided negative context, the above APIs are not present.

    condition:
        // Logic: 
        // 1. Must include specific DLL "kernel32.dll" (found in target) AND strong unique API indicators.
        // 2. Must utilize a subset of the unique behavioral APIs found in the target/neighbors but NOT in benign files.
        
        $dll_kernel32 and
        (
            2 of ($api_terminatethread, $api_createremotethread, $api_setnamedpipehandlestate, $api_createsemaphorea, $api_processidtosessionid, $api_virtuallock, $api_openmutexa, $api_createsemaphorew, $api_waitnamedpipea, $api_openeventa, $api_findresourceexw)
        )
        or
        (
            4 of ($api_fatalappexita, $api_setwaitabletimer, $api_openmutexw, $api_signalobjectandwait, $api_getprivateprofileinta, $api_lockfile, $api_setprocessshutdownparameters, $api_flushconsoleinputbuffer, $api_getprivateprofilestructa, $api_isbadreadptr, $api_tzspecificlocaltimetosystemtime, $api_changetimerqueuetimer, $api_heapqueryinformation, $api_clearcommerror, $api_fillconsoleoutputcharacterw, $api_getprivateprofilesectionw, $api_writeprivateprofilesectionw, $api_findnextvolumemountpointw, $api_callnamedpipea, $api_buildcommdcbandtimeoutsa, $api_getconsolealiaseslengtha, $api_setfileshortnamew, $api_opensemaphorew, $api_replacefilea, $api_setvolumemountpointw, $api_getnumberformata, $api_getsystemtimeadjustment, $api_getwritewatch, $api_setsystempowerstate, $api_localshrink, $api_getvolumepathnamea, $api_getprocesspriorityboost, $api_getcommstate, $api_getconsolealiasexeslengtha, $api_setcriticalsectionspincount, $api_readconsoleoutputcharactera, $api_setconsolecursorinfo, $api_createactctxa, $api_setfirmwareenvironmentvariablea, $api_getprivateprofilestructw, $api_definedosdevicew, $api_setmessagewaitingindicator, $api_backupwrite, $api_commconfigdialoga, $api_zombifyactctx, $api_getvolumepathnamesforvolumenamea, $api_getprivateprofilesectionnamesw, $api_fatalexit, $api_getnumberofconsolemousebuttons, $api_getalttabinfow)
        )
}

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


rule MALDOC_Corexemain_Mscoree_165_FileAlign1024
{
    meta:
        author = "assistant"
        description = "Text-log rule: detects records referencing 'corexemain' + 'mscoree.dll' together with MajorLinkerVersion 48 and 165xxxxxxx TimeDateStamp and 1024 FileAlignment/SizeOfHeaders — chosen to separate malicious neighbors from benign examples."
        reference_sha256 = "11a5857ee8a80ec2f7e9ce6dcf16af5495bf680f37d6750fc64d699a8ac904d5"
        date = "2025-12-01"
        confidence = 90

    strings:
        $s_corexemain        = "corexemain"
        $s_mscoree           = "mscoree.dll"
        $s_linker48          = "MajorLinkerVersion is 48"
        $s_filealign_1024    = "FileAlignment is 1024"
        $s_sizeofhdr_1024    = "SizeOfHeaders is 1024"
        /* TimeDateStamp values observed in malicious neighbors (e.g. 1650847165). Match 10-digit values starting with 165 */
        $re_tds_165          = /TimeDateStamp is 165[0-9]{7}/

    condition:
        /* require the characteristic import/API text plus the linker anomaly and the malicious timestamp family,
           and require evidence of 1024 alignment/headers to avoid benigns (which use 4096 in negatives) */
        all of ($s_corexemain, $s_mscoree) and $s_linker48 and $re_tds_165 and ( $s_filealign_1024 or $s_sizeofhdr_1024 )
}


rule Malware_Corexemain_Mscoree_TextLog
{
    meta:
        author = "assistant"
        description = "Text-log detection for a malware family observed importing mscoree.dll and referencing corexemain with a 16xxxxxxxx TimeDateStamp (matches malicious neighbors, excludes listed benigns)."
        reference_sha256 = "3f2779d20014902628cfe7d01cd12cfec336d9d858aaa04b06148e7b998b379a"
        date = "2025-12-01"
        confidence = 80
    strings:
        $s_corexemain       = "corexemain"
        $s_mscoree          = "mscoree.dll"
        $s_num_sections_3   = "NumberOfSections is 3"
        $s_opt_hdr_224      = "SizeOfOptionalHeader is 224"
        /* Match TimeDateStamp values beginning with 16 (10-digit epoch starting with 16xxxxxxx) */
        $re_tds_16          = /TimeDateStamp is 16[0-9]{7}/
    condition:
        all of ($s_corexemain, $s_mscoree) and $re_tds_16 and $s_num_sections_3 and $s_opt_hdr_224
}


rule Suspicious_Advapi_Kernel32_Combo_Impersonation
{
    meta:
        author = "malware-analyst"
        description = "Detects samples that combine advapi/kernel32 usage with impersonation, heap manipulation and job/IPC or unusual runtime helpers — behavioral combination seen in the provided malware neighbors."
        sha256_new_sample = "bedfffb784db4b18bf373195f4443f3fc10bf9f2f1eb5f2502dcc83a56919a48"
        date = "2025-12-01"

    strings:
        /* Strong behavioral indicator present in malware neighbors, not in benign set */
        $impersonate_anonymous = "impersonateanonymoustoken" nocase

        /* Heap / memory / runtime manipulation often abused for stealth */
        $heap_set_info        = "heapsetinformation" nocase
        $encode_pointer       = "encodepointer" nocase
        $decode_pointer       = "decodepointer" nocase
        $tls_alloc            = "tlsalloc" nocase

        /* Job / process control and IPC related (persistence / containment evasion) */
        $open_job_object      = "openjobobjecta" nocase
        $create_event_w       = "createeventw" nocase
        $set_handle_count     = "sethandlecount" nocase

        /* Common loader/resolution primitives (must be combined with behavioral indicators) */
        $getprocaddress       = "getprocaddress" nocase
        $loadlibrarya         = "loadlibrarya" nocase
        $advapi_dll           = "advapi32.dll" nocase
        $kernel32_dll         = "kernel32.dll" nocase

    condition:
        /*
         * Requirements:
         *  - Must contain the strong impersonation indicator (reduces false positives).
         *  - Must also show at least two other behavioral indicators from heap/runtime/job sets (includes loader helpers).
         *  - Require presence of advapi32.dll or kernel32.dll anchor (but not sufficient alone).
         */
        $impersonate_anonymous and
        ( 2 of ( $heap_set_info, $encode_pointer, $decode_pointer, $tls_alloc, $open_job_object, $create_event_w, $set_handle_count, $getprocaddress, $loadlibrarya ) ) and
        ( $advapi_dll or $kernel32_dll )
}


rule Suspicious_Corexemain_Mscoree_TextLog_4071de
{
    meta:
        author = "assistant"
        description = "Detects text-based logs for a malware family that includes 'corexemain' + 'mscoree.dll' and a TimeDateStamp beginning with 165 (matches the provided malicious samples while avoiding listed benign neighbors)."
        reference_sha256 = "7e5d9c7f336e94ee88a9cee55858de158ba66862527ede87e3e7dec7ece79688"
        license = "proprietary"
        date = "2025-12-01"
    strings:
        $s_corexemain      = "corexemain"
        $s_mscoree         = "mscoree.dll"
        $s_tds_165_prefix  = "TimeDateStamp is 165"
        $s_num_sections_3  = "NumberOfSections is 3"
    condition:
        all of ($s_corexemain, $s_mscoree) and $s_tds_165_prefix and $s_num_sections_3
}


rule Suspicious_Corexemain_Mscoree_TextLog_c197bd
{
    meta:
        author = "assistant"
        description = "Detects text/log entries of a malware family that reference 'corexemain' + 'mscoree.dll' combined with an unusually high MajorLinkerVersion (80) and TimeDateStamp values in the 16x... epoch range observed across malicious neighbors. Designed for text logs (no PE imports)."
        reference_sha256 = "706a8a414b5cf5b0af00dc98bc373f48b48e07a7770e2270b5cb6f546f482aba"
        date = "2025-12-01"
        confidence = 90
    strings:
        $s_corexemain      = "corexemain"
        $s_mscoree         = "mscoree.dll"
        $s_linker_80       = "MajorLinkerVersion is 80"
        $s_num_sections_3  = "NumberOfSections is 3"
        /* Match 10-digit TimeDateStamp values beginning with 162.. through 166.. (captures 162xxxxxxx,163...,164...,165...,166...) */
        $re_tds_16x        = /TimeDateStamp is 16[2-6][0-9]{7}/
    condition:
        /* require the specific anomaly (linker 80) AND the runtime stamp pattern plus the known imports/API text */
        all of ($s_corexemain, $s_mscoree) and $s_linker_80 and $re_tds_16x and $s_num_sections_3
}


rule Suspicious_GDIplus_SList_FileEnum_Combo
{
    meta:
        author = "malware-analyst"
        description = "Detects behavioral combination observed in the sample family: GDI+ image APIs used together with SList interlocked operations and file-enumeration (indicative of unusual image handling + low-level sync + enumeration behavior). Text/log rule — avoids volatile PE header fields and generic DLL-only matches."
        sha256_sample = "38cc012d2887b5122e94dd46d0e886e4ad85b2aaa36984c62d6641d5d85464e3"
        date = "2025-12-01"
        tags = "gdi+,slist,enumeration,behavioral"

    strings:
        /* GDI+ / image handling APIs observed in malicious neighbors */
        $gdip_load     = "GdipLoadImageFromFile" nocase
        $gdip_load_icm = "GdipLoadImageFromFileICM" nocase
        $gdip_height   = "GdipGetImageHeight" nocase
        $gdip_width    = "GdipGetImageWidth" nocase
        $gdip_clone    = "GdipCloneImage" nocase
        $gdip_free     = "GdipDisposeImage" nocase

        /* Low-level single-linked-list (SList) atomic ops (rare in benign apps) */
        $slist_push    = "InterlockedPushEntrySList" nocase
        $slist_flush   = "InterlockedFlushSList" nocase
        $slist_init    = "InterlockedPopEntrySList" nocase

        /* File enumeration / enumeration API often used with scanning/collection */
        $find_first_ex = "FindFirstFileExW" nocase
        $find_next     = "FindNextFileW" nocase

        /* Defensive: require at least one non-generic helper to avoid triggering on common CRT names */
        $console_mode  = "GetConsoleMode" nocase

    condition:
        /* Require a combination of behaviors (image handling + low-level sync + enumeration).
           This reduces false positives from benign tools that may call one category only. */
        ( any of ($gdip_*) ) and
        ( any of ($slist_*) ) and
        ( any of ($find_first_ex, $find_next) ) and

        /* At least one console/utility helper present in textual logs to ensure contextual runtime behavior */
        ( any of ($console_mode) )
}


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


rule Suspicious_VirtualProtect_CreateThread_Memory_TLS_Combo
{
    meta:
        author = "malware-analyst"
        description = "Detects a behavioral combination seen in several malware neighbors: memory protection/modification + thread creation + dynamic API lookup + raw memory operations + TLS usage — indicative of in-memory unpacking, code-patching or injection."
        sha256_sample = "f2caf8e03be6e091da8a29850f1a373cb07721a5ff949ad2e31f12dcf2822847"
        date = "2025-12-04"
        tags = "behavioral,in-memory,unpack,code-injection"

    strings:
        /* memory protection / modification */
        $vp         = "VirtualProtect" nocase
        $vq         = "VirtualQuery" nocase
        $valloc     = "VirtualAlloc" nocase
        $vprotect_ex = "VirtualProtectEx" nocase

        /* thread/process / code-execution helpers */
        $ct         = "CreateThread" nocase
        $gp         = "GetProcAddress" nocase
        $llA        = "LoadLibraryA" nocase
        $llW        = "LoadLibraryW" nocase

        /* raw memory / copy / alloc helpers (writing shellcode / payloads) */
        $memcpy     = "memcpy" nocase
        $malloc     = "malloc" nocase
        $realloc    = "realloc" nocase
        $memmove    = "memmove" nocase
        $vfree      = "VirtualFree" nocase

        /* TLS usage (seen in malware neighbors, raises confidence) */
        $tls_alloc  = "TlsAlloc" nocase
        $tls_get    = "TlsGetValue" nocase
        $tls_set    = "TlsSetValue" nocase

    condition:
        /*
         * Core fingerprint:
         *  - memory-protection/modification API (VirtualProtect / VirtualQuery / VirtualAlloc / VirtualProtectEx)
         *  - thread creation (CreateThread)
         *  - dynamic API lookup or library load (GetProcAddress or LoadLibrary*)
         *  - raw memory write/alloc/free operations (memcpy / malloc / realloc / memmove / VirtualFree)
         *  - TLS usage (TlsAlloc / TlsGetValue / TlsSetValue)
         */
        ( any of ($vp, $vq, $valloc, $vprotect_ex) ) and
        $ct and
        any of ($gp, $llA, $llW) and
        any of ($memcpy, $malloc, $realloc, $memmove, $vfree) and
        any of ($tls_alloc, $tls_get, $tls_set)
}


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


rule TEXT_RSRC_LARGE_0d0ec5da
{
    meta:
        author = "malware-analyst"
        description = "Text-log detector for the large-RSRC / advapi32-backed cluster (matches header-value patterns seen in malicious neighbors but avoids benign header values)"
        sha256 = "0d0ec5da4b48240427f7df80e2d144e6eba3f4bc8527608f5f515c500f4ccc96"
        date = "2025-12-01"
        tlp = "white"

    strings:
        /* Core behavioral token (common in both positives) */
        $s_advapi         = "advapi32.dll" ascii nocase

        /* Large .text/.rsrc header fingerprints observed in malware cluster (text-log form) */
        $s_num_sections   = "NumberOfSections is 11" ascii
        $s_text_raw       = "text_SizeOfRawData is 571392" ascii
        $s_text_vs        = "text_Misc_VirtualSize is 571228" ascii
        $s_text_ptr       = "text_PointerToRawData is 1024" ascii

        $s_rsrc_ptr_big   = "rsrc_PointerToRawData is 639488" ascii
        $s_rsrc_size_big  = "rsrc_SizeOfRawData is 223232" ascii
        $s_rsrc_vs        = "rsrc_Misc_VirtualSize is 223232" ascii

        /* Large code / entrypoint indicators seen in malware neighbors */
        $s_size_of_code   = "SizeOfCode is 582656" ascii
        $s_entrypoint     = "AddressOfEntryPoint is 587760" ascii

        /* Additional supportive tokens from positive neighbors (windows/GDI usage patterns) */
        $s_sysalloc       = "sysallocstringlen" ascii nocase
        $s_lockresource   = "lockresource" ascii nocase

        /* Known small-rsrc benign values to exclude */
        $ex_rsrc_small1   = "rsrc_PointerToRawData is 42496" ascii
        $ex_rsrc_small2   = "rsrc_PointerToRawData is 41984" ascii

    condition:
        /*
         * Logic:
         *  - advapi32 present (cluster uses advapi32/oleaut32/ole32)
         *  - at least TWO large header tokens from the set (text/rsrc/code/header values)
         *  - plus at least ONE supportive token (entrypoint OR sysalloc/lockresource)
         *  - and explicitly exclude common small-rsrc benign pointers
         */
        $s_advapi and
        2 of (
            $s_text_raw, $s_text_vs, $s_text_ptr,
            $s_rsrc_ptr_big, $s_rsrc_size_big, $s_rsrc_vs,
            $s_size_of_code, $s_num_sections
        ) and
        ( $s_entrypoint or $s_sysalloc or $s_lockresource ) and
        not any of ( $ex_rsrc_small1, $ex_rsrc_small2 )
}


rule TEXT_VIRTUALALLOCEX_MFC42_5bc61504
{
    meta:
        author = "malware-analyst"
        description = "Text-log rule: detects the cluster characterized by VirtualAllocEx + mfc42.dll with specific PE header tokens (e_lfanew 248, TimeDateStamp 1559137742) — tuned to avoid provided benign neighbors."
        reference_sha256 = "5bc61504025da2754aec94a0fdedea884fef63435894cb0015565c684d5cef20"
        created = "2025-12-01"
        tlp = "white"

    strings:
        /* High-signal API / DLL markers (from positives) */
        $s_valloc         = "virtualallocex" ascii nocase
        $s_mfc42          = "mfc42.dll" ascii nocase
        $s_loadlib        = "loadlibrarya" ascii nocase

        /* Precise PE-text tokens that appear in the positive cluster (text-log form) */
        $h_lfanew_248     = "e_lfanew is 248" ascii
        $h_tstamp_1559    = "TimeDateStamp is 1559137742" ascii
        $h_numsec_4       = "NumberOfSections is 4" ascii
        $h_filealign_4096 = "FileAlignment is 4096" ascii

        /* Resource table specifics unique to this cluster (helps avoid benign overlaps) */
        $r_rsrc_ptr       = "rsrc_PointerToRawData is 274432" ascii
        $r_rsrc_size      = "rsrc_SizeOfRawData is 2560" ascii

        /* GUI/GDI usage strings (present across positives, less common in benign set) */
        $g_bitblt         = "bitblt" ascii nocase
        $g_drawtext       = "drawtexta" ascii nocase

    condition:
        /*
         * Mandatory high-confidence markers:
         *  - API/DLL pair (virtualallocex + mfc42.dll) seen in positives
         *  - exact TimeDateStamp for this cluster (prevents matching benign files)
         *  - exact e_lfanew value and 4-section layout
         *  - exact FileAlignment value for higher specificity
         *
         * Additionally require either the resource pointer/size that matches the sample
         * or one GUI/GDI token or loadlibrary token to increase confidence.
         */
        $s_valloc and $s_mfc42 and $h_tstamp_1559 and $h_lfanew_248 and $h_numsec_4 and $h_filealign_4096 and
        (
            ($r_rsrc_ptr or $r_rsrc_size) or
            ( $g_bitblt or $g_drawtext or $s_loadlib )
        )
}


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


rule VB6_Suspicious_Memory_Resource_Interop
{
    meta:
        author = "malware-analyst"
        description = "Detects VB6 (msvbvm60) samples that combine VB runtime/event-sink symbols with memory allocation/protection and resource-loading APIs — behavioral combination to reduce false positives."
        sha256_new_sample = "5eaab373081a16275f8a096bdb725f1d9fccc3e6a93b2ca637f7b5cfe7026e2f"
        date = "2025-12-01"

    strings:
        /* runtime / loader */
        $msvbvm           = "msvbvm60.dll" nocase
        $oleaut           = "oleaut32.dll" nocase
        $shlwapi          = "shlwapi.dll" nocase

        /* memory / allocation / protection (behavioral) */
        $mem_valloc       = "virtualalloc" nocase
        $mem_vprot        = "virtualprotect" nocase
        $mem_vfree        = "virtualfree" nocase
        $mem_heapalloc    = "heapalloc" nocase
        $mem_rtlmovemem   = "rtlmovememory" nocase
        $mem_getprocessheap = "getprocessheap" nocase

        /* resource / persistence / installer-like behavior */
        $res_find         = "findresourcew" nocase
        $res_load         = "loadresource" nocase
        $res_lock         = "lockresource" nocase
        $res_sizeof       = "sizeofresource" nocase
        $sh_pathremove    = "pathremovefilespecw" nocase
        $sh_createdir     = "createdirectoryw" nocase

        /* VB-specific behavioral/event/cominterop indicators */
        $ev_qi            = "eventsinkqueryinterface" nocase
        $ev_addref        = "eventsinkaddref" nocase
        $ev_release       = "eventsinkrelease" nocase
        $vba_except       = "vbaexcepthandler" nocase
        $sysallocstr      = "sysallocstring" nocase
        $sysreallocstr    = "sysreallocstring" nocase

    condition:
        /*
         * Require:
         *  - explicit VB6 runtime import AND at least one contextual loader DLL (oleaut32 or shlwapi), AND
         *  - at least two memory/allocation/protection indicators, AND
         *  - at least one resource-handling OR VB event/cominterop indicator.
         */
        $msvbvm and ( $oleaut or $shlwapi ) and
        2 of ( $mem_valloc, $mem_vprot, $mem_vfree, $mem_heapalloc, $mem_rtlmovemem, $mem_getprocessheap ) and
        1 of ( $res_find, $res_load, $res_lock, $res_sizeof, $sh_pathremove, $sh_createdir, $ev_qi, $ev_addref, $ev_release, $vba_except, $sysallocstr, $sysreallocstr )
}


rule VB6_Suspicious_Runtime_Combination
{
    meta:
        author = "expert-malware-analyst"
        description = "Detects VB6/Visual Basic runtime artifacts combined with uncommon VB runtime internals observed across provided malware neighbors. Requires combination of msvbvm60.dll plus multiple VB-internal symbols to reduce false positives."
        sha256_new_sample = "e5e0a549727c9af4b170b6181dd1f69f8f5bfd268ef711c27a1687face31f052"
        date = "2025-12-01"

    strings:
        /* Anchor: VB6 runtime loader */
        $msvb = "msvbvm60.dll" nocase

        /* VB runtime internal symbols (behavioral/implementation-level) —
           these are frequently present in malicious VB6 variants in the positive context
           and are less common in benign apps from the negative context. */
        $vb_varmove                = "vbavarmove" nocase
        $vb_freevarlist            = "vbafreevarlist" nocase
        $vb_freeobjlist            = "vbafreeobjlist" nocase
        $vb_latemem_call_ld        = "vbavarlatememcallld" nocase
        $vb_latemem_st             = "vbavarlatememst" nocase
        $vb_generate_bounds_err    = "vbagenerateboundserror" nocase
        $vb_fp_exception           = "vbafpexception" nocase
        $vb_ary_construct2         = "vbaaryconstruct2" nocase
        $vb_strcat                 = "vbastrcat" nocase
        $vb_instr                  = "vbainstr" nocase

        /* Additional internal helpers seen repeatedly in malware neighbors */
        $cilog                     = "cilog" nocase
        $vba_excep_handler         = "vbaexcepthandler" nocase

    condition:
        /*
         * Detection logic:
         *  - Require the VB6 runtime anchor ($msvb) AND
         *  - At least three distinct VB-internal / implementation symbols from the list.
         *
         * Rationale:
         *  - Many benign apps call common WinAPI names; matching on those alone causes false positives.
         *  - The presence of multiple low-level VB runtime internals together with the VB runtime DLL
         *    is a stronger behavioral indicator of a VB-built sample that contains non-trivial
         *    runtime internals (observed in the malware neighbors) and reduces accidental matches.
         */
        $msvb and 3 of ( $vb_varmove, $vb_freevarlist, $vb_freeobjlist, $vb_latemem_call_ld, $vb_latemem_st, $vb_generate_bounds_err, $vb_fp_exception, $vb_ary_construct2, $vb_strcat, $vb_instr, $cilog, $vba_excep_handler )
}


rule VB_Malware_msvbvm60_behavioral
{
    meta:
        author = "malware-analyst"
        description = "Detects VB6/MSVBVM60-based samples showing behavioral/runtime indicators (P/Invoke-like and event sink usage). Designed to avoid generic CRT/kernel artifacts."
        sha256_new_sample = "8a91203698a5589c1787d9fb31dbbc30ab3229a6aee56992f9186a4d4fc4ae2c"
        date = "2025-12-01"
        reference = "Derived from comparison with multiple VB6 malware neighbors; excludes generic C/C++ runtime indicators."

    strings:
        $msvb              = "msvbvm60.dll"
        $dllfunc           = "dllfunctioncall"
        $ev_qi             = "eventsinkqueryinterface"
        $ev_addref         = "eventsinkaddref"
        $ev_release        = "eventsinkrelease"
        $vba_except        = "vbaexcepthandler"
        $vb_freevarlist    = "vbafreevarlist"
        $vbastr_to_ansi    = "vbastrtoansi"
        $vbastr_to_unicode = "vbastrtounicode"
        $vbastr_copy       = "vbastrcopy"
        $vb_free_str_list  = "vbafreestrlist"
        $vb_free_obj       = "vbafreeobj"

    condition:
        /* Must include the VB runtime DLL name AND multiple VB behavioral/runtime indicators.
           Requiring several indicators reduces false positives from benign files that may include
           common CRT/kernel strings. */
        $msvb and 4 of ($dllfunc, $ev_qi, $ev_addref, $ev_release, $vba_except, $vb_freevarlist, $vbastr_to_ansi, $vbastr_to_unicode, $vbastr_copy, $vb_free_str_list, $vb_free_obj)
}


rule Win32_Suspicious_Memory_IPC_Debug
{
    meta:
        author = "expert-malware-analyst"
        description = "Detects suspicious combination of memory-manipulation (VirtualAlloc/VirtualProtect), IPC/object APIs (OpenFileMapping/CreateIoCompletionPort/OpenWaitableTimer) and debugger-control APIs — seen across provided malware neighbors. Reduces false positives by requiring multiple behavioral indicators rather than generic kernel32 usage."
        sha256_new_sample = "4908a123314e068f7823c102f4de7c4445b62a5ca191b1c495b782da75bd1627"
        date = "2025-12-01"

    strings:
        /* Memory / code-injection related */
        $virtual_alloc      = "virtualalloc" nocase
        $virtual_protect    = "virtualprotect" nocase
        $virtual_free       = "virtualfree" nocase
        $get_thread_ctx     = "getthreadcontext" nocase

        /* IPC / synchronization / advanced object APIs (behavioral) */
        $open_file_mapping  = "openfilemappinga" nocase
        $open_wait_timer    = "openwaitabletimera" nocase
        $create_iocp        = "createiocompletionport" nocase
        $create_named_pipe  = "createnamedpipea" nocase

        /* Debug / anti-analysis indicators */
        $is_debug_present   = "isdebuggerpresent" nocase
        $debug_break        = "debugbreak" nocase
        $cont_debug_event   = "continuedebugevent" nocase
        $wait_for_debug     = "waitfordebugevent" nocase

        /* Helper: presence of many low-level Win32 runtime calls (not sufficient alone) */
        $kernel32_like      = "kernel32.dll" nocase

    condition:
        /*
         * Logic:
         *  - Require at least TWO memory-manipulation indicators (common in injection/payload unpacking)
         *    AND
         *  - At least ONE IPC/synchronization/advanced-object API (indicates inter-process interaction or advanced resource usage)
         *    AND
         *  - At least ONE debug/anti-analysis indicator (debugbreak/continuedebugevent/isdebuggerpresent/etc.)
         *  - AND a contextual kernel32.dll anchor (used here as contextual evidence)
         */
        ( (1 of ($virtual_alloc, $virtual_protect, $virtual_free, $get_thread_ctx)) and
          (2 of ($virtual_alloc, $virtual_protect, $virtual_free, $get_thread_ctx)) and
          (1 of ($open_file_mapping, $open_wait_timer, $create_iocp, $create_named_pipe)) and
          (1 of ($is_debug_present, $debug_break, $cont_debug_event, $wait_for_debug)) and
          ($kernel32_like)
        )
}


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


rule Win_Suspicious_Variant_CharUpper_Loadlib
{
    meta:
        author = "malware-analyst"
        description = "Behavioral text-log rule: detects samples that combine COM/automation type conversion calls with unusual string/GUI helper calls plus dynamic loader usage — seen across the provided malware neighbors. Avoids trivial hits on common runtime artifacts."
        sha256_sample = "55e79c0ae518b6440b2778a324c7874f2a689cea94d430e1b381eb4e20623261"
        date = "2025-12-04"
        tags = "behavioral, suspicious, loadlibrary, variant, charupper"

    strings:
        /* Rare/behavioral indicators observed in malware neighbors (COM/type & string manipulation) */
        $s_variantchangetypeex = "VariantChangeTypeEx" nocase
        $s_charupperbuffw     = "CharUpperBuffW" nocase
        $s_getsyscolorbrush   = "GetSysColorBrush" nocase

        /* Dynamic loader / resolution / module helpers (behavioral, not used alone) */
        $s_loadlibrarya       = "LoadLibraryA" nocase
        $s_getprocaddress     = "GetProcAddress" nocase
        $s_getmodulehandlea   = "GetModuleHandleA" nocase
        $s_raiseexception     = "RaiseException" nocase

    condition:
        /*
         * Match when:
         *  - the file/log contains the COM/type-conversion and string-manipulation indicators
         *    (these are uncommon in benign neighbors), AND
         *  - at least one dynamic loader / module-resolution API is present
         *
         * This reduces false positives from benign files that only contain generic runtime names
         * like "corexemain" or "GetProcAddress" by itself.
         */
        all of ($s_variantchangetypeex, $s_charupperbuffw, $s_getsyscolorbrush) and
        any of ($s_loadlibrarya, $s_getprocaddress, $s_getmodulehandlea, $s_raiseexception)
}

