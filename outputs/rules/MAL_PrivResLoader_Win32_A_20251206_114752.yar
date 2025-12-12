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
