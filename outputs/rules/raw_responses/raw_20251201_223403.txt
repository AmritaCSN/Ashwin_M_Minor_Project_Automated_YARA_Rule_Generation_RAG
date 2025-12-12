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