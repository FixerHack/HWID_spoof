$spoofer = Join-Path $PSScriptRoot "spoof.exe"
$steam   = "C:\Program Files (x86)\Steam\steam.exe"

# spoof.exe has UAC manifest - will auto-request admin
# -Wait properly waits for the elevated process to finish
Start-Process -FilePath $spoofer -Verb RunAs -Wait

# Launch Steam as normal user (no admin)
Start-Process -FilePath $steam
