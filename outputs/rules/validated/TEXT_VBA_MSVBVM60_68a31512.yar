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
