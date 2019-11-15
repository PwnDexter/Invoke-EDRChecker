$edr_list = @('authtap',
              'avast',
              'avecto',
              'carbon',
              'cb.exe',
              'crowd',
              'csagent',
              'csfalcon',
              'csshell',
              'cyclorama',
              'cylance',
              'cyoptics',
              'cyupdate',
              'defendpoint',
              'defender',
              'eectrl',
              'endgame',
              'fireeye',
              'groundling',
              'inspector',
              'kaspersky',
              'lacuna',
              'logrhythm',
              'mcafee',
              'morphisec',
              'msascuil',
              'msmpeng',
              'nissrv',
              'osquery',
              'pgeposervice',
              'pgsystemtray',
              'privilegeguard',
              'procwall',
              'protectorservice'
              'qradar',
              'redcloak',
              'securityhealthservice',
              'semlaunchsvc'
              'sentinel',
              'sepliveupdate'
              'sisidsservice',
              'sisipsservice',
              'sisipsutil',
              'smc.exe',
              'smcgui',
              'snac64',
              'sophos',
              'splunk',
              'srtsp',
              'symantec',
              'symcorpui'
              'symefasi',
              'sysinternal',
              'sysmon',
              'tanium',
              'tpython',
              'wincollect',
              'windowssensor',
              'wireshark'
             )

<#
.SYNOPSIS

Enumerates the host and checks it for defensive products.

Author: Ross Bingham (@PwnDexter)
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: None

.DESCRIPTION

Enumerates the host by querying processes, process metadata, dlls loaded into your current process and each dlls metadata, known install paths, installed services, the registry and running drivers then checks the output against a list of known defensive products such as AV's, EDR's and logging tools.

.EXAMPLE
PS C:\> Invoke-EDRChecker

#>

function Invoke-EDRChecker
{

    param([Parameter(ValueFromPipeline = $false)] [switch] $ForceReg)

    $edr = $edr_list
    
    Write-Output ""
    Write-Output "[!] Performing EDR Checks"
    Write-Output "[!] Checking current user integrity"
    $user = [Security.Principal.WindowsIdentity]::GetCurrent();
    $isadm = (New-Object Security.Principal.WindowsPrincipal $user).IsInRole([Security.Principal.WindowsBuiltinRole]::Administrator)
    if ($isadm | Select-String -Pattern "True") {Write-Output "[+] Running as admin, all checks will be performed"}
    else {Write-Output "[-] Not running as admin, process metadata, registry and drivers will not be checked"}

    if (($isadm | Select-String -Pattern "False") -or ($ForceReg -eq $true))
    {
    Write-Output "[-] Use the -ForceReg flag to force registry checks when not running as admin"
    }
    
    Write-Output ""
    Write-Output "[!] Checking running processes"
    if ($proc = Get-Process | Select-Object ProcessName,Name,Path,Company,Product,Description | Select-String -Pattern $edr -AllMatches)
    {ForEach ($p in $proc -Replace "@{") {Write-Output "[-] $p".Trim("}")}}
    else {Write-Output "[+] No suspicious processes found"}

    Write-Output ""
    Write-Output "[!] Checking loaded DLLs in your current process"
    $procdll = Get-Process -Id $pid -Module
    if ($metadll = (Get-Item $procdll.FileName).VersionInfo | Select-Object CompanyName,FileDescription,FileName,InternalName,LegalCopyright,OriginalFileName,ProductName | Select-String -Pattern $edr -AllMatches)
    {ForEach ($p in $metadll -Replace "@{") {Write-Output "[-] $p".Trim("}")}}
    else {Write-Output "[+] No suspicious DLLs loaded"}

    Write-Output ""
    Write-Output "[!] Checking Program Files"
    if ($prog = Get-ChildItem -Path 'C:\Program Files\*' | Select-Object Name | Select-String -Pattern $edr -AllMatches)
    {ForEach ($p in $prog -Replace "@{") {Write-Output "[-] $p".Trim("}")}}
    else {Write-Output "[+] Nothing found in Program Files"}
    
    Write-Output ""
    Write-Output "[!] Checking Program Files x86"
    if ($prog86 = Get-ChildItem -Path 'C:\Program Files (x86)\*' | Select-Object Name | Select-String -Pattern $edr -AllMatches)
    {ForEach ($p in $prog86 -Replace "@{") {Write-Output "[-] $p".Trim("}")}}
    else {Write-Output "[+] Nothing found in Program Files x86"}

    Write-Output ""
    Write-Output "[!] Checking Program Data"
    if ($progd = Get-ChildItem -Path 'C:\ProgramData\*' | Select-Object Name | Select-String -Pattern $edr -AllMatches)
    {ForEach ($p in $progd -Replace "@{") {Write-Output "[-] $p".Trim("}")}}
    else {Write-Output "[+] Nothing found in Program Data"}

    Write-Output ""
    Write-Output "[!] Checking installed services"
    if ($serv = Get-Service | Select-Object Name,DisplayName,ServiceName | Select-String -Pattern $edr -AllMatches)
    {ForEach ($p in $serv -Replace "@{") {Write-Output "[-] $p".Trim("}")}}
    else {Write-Output "[+] No suspicious services found"}

    if (($isadm | Select-String -Pattern "True") -or ($ForceReg -eq $true))
    {
        Write-Output ""
        Write-Output "[!] Checking the registry"
        if ($reg = Get-ItemProperty -Path 'HKLM:\SYSTEM\CurrentControlSet\Services\*' | Select-Object PSChildName,PSPath,DisplayName,ImagePath,Description | Select-String -Pattern $edr -AllMatches) 
        {ForEach ($p in $reg -Replace "@{") {Write-Output "[-] $p".Trim("}")}}
        else {Write-Output "[+] Nothing found in Registry"}
    }

    if ($isadm | Select-String -Pattern "True")
    {
        Write-Output ""
        Write-Output "[!] Checking the drivers"
        if ($drv = fltmc instances | Select-String -Pattern $edr -AllMatches) 
        {ForEach ($p in $drv -Replace "@{") {Write-Output "[-] $p".Trim("}")}}
        else {Write-Output "[+] No suspicious drivers found"}
    }

    Write-Output ""
    Write-Output "[!] EDR Checks Complete"
    Write-Output ""

}
