rule Suspicious_Command_Launcher {
    meta:
        description = "Detects hidden invocation of process launch and download primitives"
        author = "VindexAV Core Engine"
        severity = "suspicious"
    strings:
        $cmd1 = "cmd.exe /c" nocase
        $cmd2 = "powershell -enc" nocase
        $cmd3 = "powershell.exe -ExecutionPolicy Bypass" nocase
        $cmd4 = "WScript.Shell" nocase
        $cmd5 = "certutil -urlcache -split -f" nocase
        $cmd6 = "bitsadmin /transfer" nocase
        $sh1  = "/bin/bash -i >& /dev/tcp/" ascii
        $sh2  = "curl -s http" ascii
    condition:
        2 of ($cmd*) or 1 of ($sh*)
}