# useful_powershell_functions
powershell functions to make my admin work easier

---

# Get-CurrentLoad

great function to get cpu, hdd, ram, nic and gpu load from this or remote computer
it support -detailed parameter to display which process are most intensive

---

# Export-ScriptsToModule
function for easy export of functions in ps1 scripts to psm1 module in safe and simple way
for more information [check my blog](https://doitpsway.com/automate-powershell-module-creation-the-smart-way)

---

# Get-NetworkCapture

function to capture traffic on local/remote computer/s, export it to etl file and copy to specified location

there is still some work to do, but basic functionality is working

---

# Invoke-Command2

proxy function to Invoke-Command that solves problem with inputting localhost + remote computers together to ComputerName parameter which end with access denied error, because you cannot run commands against yourself remotely. 

Typical use case:
You have function that has computers parameter. It run some command against computers in computers parameter using Invoke-Command.
You have to deal with situation that user input:
- just name of his local computer
    so you have to use Invoke-Command -scriptBlock {...}
- name of his local computer and some remote computers
    so you have to use Invoke-Command -computerName $computers -scriptBlock {...} against remote computers and Invoke-Command -scriptblock {...} against localhost separately

This proxy function solves it all. You dont have to worry if you pass just remote computers, or just localhost or combination of two

---

**..., just check the content of this repository..and if you are looking for some easy to use tool to manage your PowerShell content, check my [PowerShell CI/CD repository](https://github.com/ztrhgf/Powershell_CICD_repository)**
