# Invoke-EDRChecker
The script will check running processes, process metadata, Dlls loaded into your current process and the each DLLs metadata, common install directories, installed services, the registry and running drivers for the presence of known defensive products such as AV's, EDR's and logging tools.

This script can be loaded into your C2 server as well for example in PoshC2, place the script into your modules directory, load the module then run it. Note: this script is now included in PoshC2 so no need to manually add it.

The script also has capacity to perform checks against remote targets if you have the privileges to do so, these checks are presently limited however to process checking, common install directories and installed services.

I will continue to add and improve the list when time permits. A full roadmap can be found below.

Find me on twitter @PwnDexter for any issues or questions!

## Install

```
git clone https://github.com/PwnDexter/Invoke-EDRChecker.git
```

## Usage

Once the script has been loaded into your host or C2 of choice, you can use the following commands:

Run the script against the local host and perform checks based on current user integrity:
```
Invoke-EDRChecker
```

Run the script and force registry checks to be performed (for use when you are not running as admin):
```
Invoke-EDRChecker -Force
```

Run the script against a remote host, this test connectivity and try to resolve the hostname before running:
```
Invoke-EDRChecker -Remote <hostname>
```

To bypass the pre-checks for remote hosts use -Ignore flag to bypass connectivity checks
```
Invoke-EDRChecker -Remote <hostname> -Ignore
```

## Example Output - Note: These screenshots need updated and this has only been tested on Windows 10, more testing to come.

If processes and drivers are hidden and still found:

![](https://raw.githubusercontent.com/PwnDexter/edr-checker/master/Images/edr-new-adm.png)

If running as non-admin to show visibility difference:

![](https://raw.githubusercontent.com/PwnDexter/edr-checker/master/Images/edr-new-noadm.png)

Using EDR-Checker with PoshC2:

![](https://raw.githubusercontent.com/PwnDexter/edr-checker/master/Images/edr-poshc2.png)

## Roadmap
- [ ] - Add more EDR Products - never ending
- [x] - Refine beta function for registry checking
  - [x] - Add in force reg check if not running as admin
- [ ] - Test across more Windows and .NET versions
- [ ] - Port to c# - IN PROGRESS
- [x] - Clean up output
- [x] - Get currently loaded DLL's in your current process
  - [x] - Get dll metadata of currently loaded dlls
- [x] - Add remote host query capability
  - [x] - Add connectivity and DNS checks before performing edr checks
  - [ ] - Add remote privilege checks before performing edr checks
- [x] - Add installed services checks
- [ ] - Port to python for unix/macos support
