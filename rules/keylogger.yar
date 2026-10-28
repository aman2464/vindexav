rule Keylogger_API_Artifacts {
    meta:
        description = "Detects typical Windows API strings used for keystroke logging and hooks"
        author = "VindexAV Core Engine"
        severity = "suspicious"
    strings:
        $api1 = "GetAsyncKeyState" ascii
        $api2 = "GetKeyboardState" ascii
        $api3 = "SetWindowsHookEx" ascii
        $api4 = "GetForegroundWindow" ascii
        $api5 = "MapVirtualKey" ascii
    condition:
        3 of ($api*)
}