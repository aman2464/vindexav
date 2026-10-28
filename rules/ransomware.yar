rule Ransomware_Note_Keywords {
    meta:
        description = "Identifies ransom note indicators and extortion instructions"
        author = "VindexAV Core Engine"
        severity = "malicious"
    strings:
        $r1 = "YOUR FILES ARE ENCRYPTED" nocase wide ascii
        $r2 = "All your important files have been encrypted" nocase wide ascii
        $r3 = "send bitcoin to the following address" nocase wide ascii
        $r4 = ".onion" ascii
        $r5 = "decrypt your files" nocase wide ascii
        $r6 = "pay the ransom" nocase wide ascii
    condition:
        2 of ($r*)
}