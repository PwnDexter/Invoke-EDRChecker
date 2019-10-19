# edr-checker
Enumerates the host and checks for the presence of known defensive products such as AV's, EDR's and logging tools. The script will check running processes, process metadata, common install directories and if you use the beta function the registry.

This script can be loaded into your C2 server as well for example in PoshC2, place the script into your modules directory, load the module then run it.

I will continue to add and improve the list when time permits, better formatting to come as well. At present you must run edr-checker-beta to include registry checks, this can return false positives on top of the legit positives so be sure to check.

## Example Output - Note: This has only been tested on Windows 10, more testing to come.

If processes found (Beta):

![](https://raw.githubusercontent.com/PwnDexter/edr-checker/master/Images/edr-beta-exch-adm.png)

If processes and drivers are hidden and still found:

![](https://raw.githubusercontent.com/PwnDexter/edr-checker/master/Images/hidden-edr-check-adm.png)

## Roadmap
- [ ] - Add more EDR Products
- [ ] - Refine beta function for registry checking
- [ ] - Test across more Windows and .NET versions
- [ ] - Clean up output
