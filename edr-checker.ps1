<#
.SYNOPSIS

Gets a current process listing and checks it for defensive products.

Author: Ross Bingham (@PwnDexter)
License: BSD 3-Clause
Required Dependencies: None
Optional Dependencies: None

.DESCRIPTION

Gets the name of all currently running process then checks them against a list of known defensive products such as AV's, EDR's and logging tools.

.EXAMPLE
PS C:\> edr-checker

#>

function edr-checker
{
	$edr = @(
				'carbon',
				'cb',
				'crowd',
				'csagent',
				'csfalcon',
				'csshell',
				'cylance',
				'cyoptics',
				'cyupdate',
				'defendpoint',
				'PGEPOService',
				'PGSystemTray',
				'PrivilegeGuard',
				'sentinel',
				'splunk',
				'sysmon',
			 )
	
	$proc = get-process | select ProcessName | Select-String -Pattern $edr -AllMatches

	echo $proc
}
