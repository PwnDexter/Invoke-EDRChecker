<#
.SYNOPSIS

Enumerates the host and checks it for defensive products.

Author: Ross Bingham (@PwnDexter)
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: None

.DESCRIPTION

Enumerates the host by querying processes, process metadata, known install paths and the registry, then checks the output against a list of known defensive products such as AV's, EDR's and logging tools.

.EXAMPLE
PS C:\> edr-checker
PS C:\> edr-checker-beta

#>

function edr-checker
{
	$edr = @('authtap',
             'carbon',
             'cb',
             'crowd',
             'csagent',
             'csfalcon',
             'csshell',
             'cyclorama',
             'cylance',
             'cyoptics',
             'cyupdate',
             'defendpoint',
             'groundling',
             'inspector',
             'lacuna',
             'PGEPOService',
             'PGSystemTray',
             'PrivilegeGuard',
             'procwall',
             'redcloak',
             'sentinel',
             'splunk',
             'sysinternal',
             'sysmon',
             'tanium',
             'TPython',
             'Wireshark'
            )

    $user = [Security.Principal.WindowsIdentity]::GetCurrent();
    $isadm = (New-Object Security.Principal.WindowsPrincipal $user).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
    if ($isadm | Select-String -Pattern "True") {Write-Host -f green "Woop running as admin, see all the things" }
    else { Write-Host -f yellow "Not running as admin, visibility may be limited" }
    
    Write-Host -f white "Checking running processes"
    if ($proc = get-process | select-object ProcessName,Name,Path,Company,Product,Description | Select-String -Pattern $edr) {Write-Host -Separator `r`n -f yellow $proc }
    else {Write-Host -f Green ("No suspicious processes found, go wild!")}

    Write-Host -f white "Checking Program Files"
    if ($prog = Get-ChildItem -Path 'C:\Program Files\*' | Select Name | Select-String -Pattern $edr -AllMatches) {Write-Host -Separator `r`n -f yellow $prog }
    else {Write-Host -f Green ("Nothing in Program Files, go wild!")}
    
    Write-Host -f white "Checking Program Files x86"
    if ($prog86 = Get-ChildItem -Path 'C:\Program Files (x86)\*' | Select Name | Select-String -Pattern $edr -AllMatches) {Write-Host -Separator `r`n -f yellow $prog86 }
    else {Write-Host -f Green ("Nothing in Program Files x86, go wild!")}

    Write-Host -f white "Checking Program Data"
    if ($prog86 = Get-ChildItem -Path 'C:\ProgramData\*' | Select Name | Select-String -Pattern $edr -AllMatches) {Write-Host -Separator `r`n -f yellow $prog86 }
    else {Write-Host -f Green ("Nothing in Program Data, go wild!")}

}

function edr-checker-beta
{
	$edr = @('authtap',
             'carbon',
             'cb',
             'crowd',
             'csagent',
             'csfalcon',
             'csshell',
             'cyclorama',
             'cylance',
             'cyoptics',
             'cyupdate',
             'defendpoint',
             'groundling',
             'inspector',
             'lacuna',
             'PGEPOService',
             'PGSystemTray',
             'PrivilegeGuard',
             'procwall',
             'redcloak',
             'sentinel',
             'splunk',
             'sysinternal',
             'sysmon',
             'tanium',
             'TPython',
             'Wireshark'
             #'conhost' #For testing output
             #'notepad' #For testing output
            )

    $user = [Security.Principal.WindowsIdentity]::GetCurrent();
    $isadm = (New-Object Security.Principal.WindowsPrincipal $user).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
    if ($isadm | Select-String -Pattern "True") {Write-Host -f green "Woop running as admin, see all the things" }
    else { Write-Host -f yellow "Not running as admin, visibility may be limited" }
    
    Write-Host -f white "Checking running processes"
    if ($proc = get-process | select-object ProcessName,Name,Path,Company,Product,Description | Select-String -Pattern $edr) {Write-Host -Separator `r`n -f yellow $proc }
    else {Write-Host -f Green ("No suspicious processes found, go wild!")}

    Write-Host -f white "Checking Program Files"
    if ($prog = Get-ChildItem -Path 'C:\Program Files\*' | Select Name | Select-String -Pattern $edr -AllMatches) {Write-Host -Separator `r`n -f yellow $prog }
    else {Write-Host -f Green ("Nothing in Program Files, go wild!")}
    
    Write-Host -f white "Checking Program Files x86"
    if ($prog86 = Get-ChildItem -Path 'C:\Program Files (x86)\*' | Select Name | Select-String -Pattern $edr -AllMatches) {Write-Host -Separator `r`n -f yellow $prog86 }
    else {Write-Host -f Green ("Nothing in Program Files x86, go wild!")}

    Write-Host -f white "Checking Program Data"
    if ($prog86 = Get-ChildItem -Path 'C:\ProgramData\*' | Select Name | Select-String -Pattern $edr -AllMatches) {Write-Host -Separator `r`n -f yellow $prog86 }
    else {Write-Host -f Green ("Nothing in Program Data, go wild!")}
    
    Write-Host -f white "Checking the registry"
    if ($reg = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\*' | Select Name,DisplayName,ImagePath,Description | Select-String -SimpleMatch $edr -AllMatches) {Write-Host -Separator `r`n -f yellow $reg }
    else {Write-Host -f Green ("Nothing in Registry, go wild!")}

}
