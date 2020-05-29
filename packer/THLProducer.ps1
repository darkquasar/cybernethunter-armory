
function Build-Template {

	<# 

	.SYNOPSIS
		Automation Script to select the appropriate template and combination of variables for packer builds. 
		Diego Perez - THL - 2017
		
	.DESCRIPTION
		This function will abstract another layer of the whole build process by choosing a packer template based on the options specified when calling it.
		Use the parameters to alter the template pathway, for example by choosing a "vmware" platform for a "linux" ostype from an "iso" source. When overloading a particular variable, from the ones found inside "variables.json", make sure to include the "-var" switch plus the variable(s) inside quotations marks like so: "-var install_windowsupdates=True -var install_sysinternals=False".
		
		NOTE: By default, the "variables.json" file points to empty values for "iso_url", "iso_checksum" and "iso_checksum_type". These are overloaded by the current script when selecting a particular platform
	
	.EXAMPLE 1
		Build a Windows 2012 R2 from an ISO for VMWare, using the defaults (ISO file will be downloaded from the internet) and other variables coded in "variables.json"
		Build-Template -Platform vmware -OSType windows -OSName Win2012R2 -VMSource iso
		
	.EXAMPLE 2
		Build a Windows 7 VM from an ISO for VMWare specifying the location of the ISO and associated paramaters.
		Build-Template -Platform vmware -OSType windows -OSName Win7 -VMSource iso -Variables '-var iso_url=C:/D13g0/VirtualMachines/ISO/7600.16385.090713-1255_x64fre_enterprise_en-us_EVAL_Eval_Enterprise-GRMCENXEVAL_EN_DVD.iso -var iso_checksum_type=sha256 -var iso_checksum=B202E27008FD2553F226C0F3DE4DD042E4BB7AE93CFC5B255BB23DC228A1B88E -var output_directory=P:/vmware-win7-test -var install_windowsupdates=True -var install_openssh=False -var install_firefox=False -var install_chrome=False'
	
	.EXAMPLE 3
		Build a Windows 2012 R2 from a VMWare VMX (existing VM machine) and install Windows Updates plus FLAREVM tools but no openssh. Specify a different output folder (output_directory) and explicitly select the source folder (source_path).
		Build-Template -Platform vmware -OSType windows -OSName Win2012R2 -VMSource vmx -Variables '-var source_path=./output-vmware-iso/packer-vmware-iso.vmx -var output_directory=P:/vmware-vmx-test -var install_windowsupdates=True -var install_flarevm=True -var install_openssh=False'
		
	.EXAMPLE
		asdf
		
		
	#>

	[cmdletbinding()]
	param(
		[Parameter(Mandatory=$true,Position=0)]
		[ValidateSet("vbox", "vmware", "vagrant")]
		[string]$Platform,
		[Parameter(Mandatory=$false,Position=1)]
		[ValidateSet("linux", "windows")]
		[string]$OSType = "windows",
		[Parameter(Mandatory=$true,Position=2)]
		[ValidateSet("Win2012R2", "Win2016StdCore", "Win10", "Win7", "UbuntuXenial")]
		[string]$OSName,
		[Parameter(Mandatory=$true,Position=3)]
		[ValidateSet("iso", "vmx")]
		[string]$VMSource,
		[Parameter(Mandatory=$false,Position=4)]
		[string]$Variables,
		[Parameter(Mandatory=$false,Position=5)]
		[string]$TemplatePath = ".\"
	)

	switch ($OSName)
	{
		'Win2012R2' {
			$osData = @{
				os_name = 'win2012r2'
				guest_os_type = @{vbox = 'Windows2012_64' ; vmware = 'windows8srv-64'}
				full_os_name = 'Windows2012R2'
				iso_checksum = '849734f37346385dac2c101e4aacba4626bb141c'
				iso_checksum_type = 'md5'
				iso_url = 'http://care.dlservice.microsoft.com/dl/download/6/2/A/62A76ABB-9990-4EFC-A4FE-C7D698DAEB96/9600.17050.WINBLUE_REFRESH.140317-1640_X64FRE_SERVER_EVAL_EN-US-IR3_SSS_X64FREE_EN-US_DV9.ISO'
				autounattend = './scripts/answer_file_win2012/autounattend.xml'
			}
		}

		'Win2016StdCore' {
			$osData = @{
				os_name = 'win2016stdcore'
				guest_os_type = @{vbox = 'Windows2012_64' ; vmware = 'windows9srv-64'}
				full_os_name = 'Windows2016StdCore'
				iso_checksum = '3bb1c60417e9aeb3f4ce0eb02189c0c84a1c6691'
				iso_checksum_type = 'md5'
				iso_url = 'http://care.dlservice.microsoft.com/dl/download/1/6/F/16FA20E6-4662-482A-920B-1A45CF5AAE3C/14393.0.160715-1616.RS1_RELEASE_SERVER_EVAL_X64FRE_EN-US.ISO'
				autounattend = './scripts/answer_file_win2012/autounattend.xml'
			}
		}
		
		'Win10' {
			$osData = @{
				os_name = 'win2012r2'
				guest_os_type = @{vbox = 'Windows10_64' ; vmware = 'windows9-64'}
				full_os_name = 'Windows10'
				iso_checksum = '6c60f91bf0ad7b20f469ab8f80863035c517f34f'
				iso_checksum_type = 'md5'
				iso_url = 'http://care.dlservice.microsoft.com/dl/download/B/8/B/B8B452EC-DD2D-4A8F-A88C-D2180C177624/15063.0.170317-1834.RS2_RELEASE_CLIENTENTERPRISEEVAL_OEMRET_X64FRE_EN-US.ISO'
				autounattend = './scripts/answer_file_win2012/autounattend.xml'
			}
		}
		
		'Win7' {
			$osData = @{
				os_name = 'win7ent'
				guest_os_type = @{vbox = 'windows7-64' ; vmware = 'windows7-64'}
				full_os_name = 'Windows7'
				iso_checksum = '1D0D239A252CB53E466D39E752B17C28'
				iso_checksum_type = 'md5'
				iso_url = 'http://care.dlservice.microsoft.com/dl/download/evalx/win7/x64/EN/7600.16385.090713-1255_x64fre_enterprise_en-us_EVAL_Eval_Enterprise-GRMCENXEVAL_EN_DVD.iso'
				autounattend = './scripts/answer_file_win7/Autounattend.xml'
			}
		}
	}

	switch ($OSType)
	{
	
		'linux'		{$ostypex = 'Linux'}
		'windows'	{$ostypex = 'Windows'}
	
	}
	
	switch ($Platform)
	{
	
		'vbox'		{$vmplatform = $ostypex + '-vbox'}
		'vmware'	{$vmplatform = $ostypex + '-vmware'}
		'vagrant'	{$vmplatform = $ostypex + '-vagrant'}
	
	}
	
	switch ($VMSource)
	{
	
		'iso'		{$vmsourcex = $vmplatform + '-iso.json'}
		'vmx'		{$vmsourcex = $vmplatform + '-vmx.json'}
	
	}

	
	# Run some basic checks to make sure everything is in place before deployment
	if(!(Test-Path $TemplatePath\$vmsourcex)) {Write-Host "Template $($vmsourcex) is missing, please make sure you copy it to the right folder" -ForegroundColor Green}
	
	# Build template with packer based on chosen options
	# if the user chose to overload any variables provided in variables.json, they will be inserted in the commandline with $(if($Variables){$Variables})
	
	Start-Process -FilePath 'packer.exe' -ArgumentList "build  -var-file=variables.json -var `"os_name=$($osData.os_name)`" -var `"iso_checksum=$($osData.iso_checksum)`" -var `"iso_checksum_type=$($osData.iso_checksum_type)`" -var `"iso_url=$($osData.iso_url)`" -var `"guest_os_type=$($osData.guest_os_type.platform)`" $(if($Variables){$Variables}) .\$($vmsourcex)" -Wait -NoNewWindow

}