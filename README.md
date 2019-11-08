# EDR-Checker
The script will check running processes, process metadata, Dlls loaded into your current process, common install directories, the registry and running drivers for the presence of known defensive products such as AV's, EDR's and logging tools.

This script can be loaded into your C2 server as well for example in PoshC2, place the script into your modules directory, load the module then run it. Note: this will be pushed and intregrated into PoshC2 soon.

I will continue to add and improve the list when time permits. At present you must be admin include registry checks, I plan to add a -Force flag for this. I will also be porting this to C# and adding in remote host query capability.

Find me on twitter @PwnDexter for any issues or questions!

### Example Output - Note: This has only been tested on Windows 10, more testing to come.

If processes and drivers are hidden and still found:

![](https://raw.githubusercontent.com/PwnDexter/edr-checker/master/Images/edr-new-adm.png)

If running as non-admin to show visibility difference:

![](https://raw.githubusercontent.com/PwnDexter/edr-checker/master/Images/edr-new-noadm.png)

Using EDR-Checker with PoshC2:

![](https://raw.githubusercontent.com/PwnDexter/edr-checker/master/Images/edr-poshc2.png)

## Roadmap
- [ ] - Add more EDR Products
- [x] - Refine beta function for registry checking
  - [ ] - Add in force reg check if not running as admin
- [ ] - Test across more Windows and .NET versions
- [ ] - Port to c#
- [x] - Clean up output
- [x] - Get currently loaded DLL's in your current process
  - [ ] - Get dll metadata of currently loaded dlls
- [ ] - Add remote host query capability
