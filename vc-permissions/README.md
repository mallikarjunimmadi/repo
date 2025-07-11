Tested with PowerCLI version VMware-PowerCLI-13.3.0-24145081


Stage 1: Export Permissions (vCenterPermissions-Export.ps1)
1.	This script exports permission data for all vCenters in the respective csv files, in one run
2.	Logging for this script happens in “VIPermissions_Log_$timestamp.log” in the current path
3.	vCenter specific permission CSV files are exported to “VIPermissions_${vcenter}_$timestamp.csv” file in the current path
<br>a.	Example: VIPermissions_vc01.vmi_20250516_182038.csv
4.	Execute with a user account that has access to read the permissions on vCenter


Stage 2: Import Permissions (vCenterPermissions_Import_v0.ps1)
1.	Importing to be done 1 vCenter at a time
2.	For each vCenter, do the following:
<br>a.	Update the “$vCenter ” value with the corresponding vCenter FQDN (line 2)
<br>b.	Update the line with corresponding vCenter exported permissions “VIPermissions_vc01#######.csv” file name (line 5)
<br>c.	Execute with SSO administrator (administrator@vsphere.local)
<br>d.	Verify the permissions update with recent tasks
