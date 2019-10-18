# edr-checker
Gets the name of all currently running process then checks them against a list of known defensive products such as AV's, EDR's and logging tools.

This script can be loaded into your C2 server as well for example in PoshC2, place the script into your modules directory, load the module then run it.

I will continue to add and improve the list when time permits, better formatting to come as well.

## Example Output - Note: This has only been tested on Windows 10, more testing to come.

If processes found:

![](https://raw.githubusercontent.com/PwnDexter/edr-checker/master/Images/edr-checker.png)

If processes not found:

![](https://raw.githubusercontent.com/PwnDexter/edr-checker/master/Images/edr-check-pass.png)

## Roadmap
- [ ] - Add more EDR Products
- [ ] - Test across more Windows and .NET versions
