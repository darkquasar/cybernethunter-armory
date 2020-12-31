<#
    CYBRHUNTER SECURITY OPERATIONS :)
    Author: Diego Perez (@darkquassar)
    Version: 1.3.0
    Created: 15/04/2018
    Module: Get-ScriptsFromRepository
    Description: This module will fetch available scripts in the SocOps repo and present them in an interactive menu.
#>

# ***** BEGIN: LOAD REQUIRED MODULES *****

# ***** END: LOAD REQUIRED MODULES *****

# ***** BEGIN: INTERACTIVE MENU CODE *****
Function Start-DrawMenu {

    Param (
        [Parameter(Mandatory=$True)]
        [array]$MenuItems,

        [Parameter(Mandatory=$False)]
        [int]$MenuPosition,

        [Parameter(Mandatory=$False)]
        [bool]$Multiselect,

        [Parameter(Mandatory=$False)]
        [array]$Selection
    )

    $MenuItemsLenght = $MenuItems.length

    for ($i = 0; $i -le $MenuItemsLenght; $i++) {

		if ($MenuItems[$i]) {

            $item = $MenuItems[$i]
            
			if ($Multiselect)
			{
				if ($selection -contains $i){
					$item = '[x] ' + $item
				}
				else {
					$item = '[ ] ' + $item
				}
            }
            
			if ($i -eq $MenuPosition) {
				Write-Host "> $($item)" -ForegroundColor Green
			} else {
				Write-Host "  $($item)"
			}
		}
    }
}

Function New-Menu {

    Param (
        
        [Parameter(Mandatory=$True)]
        [array]$MenuItems,

        [Parameter(Mandatory=$False)]
        [string]$MenuArrayListSelector,

        [Parameter(Mandatory=$False)]
        [switch]$ReturnIndex,

        [Parameter(Mandatory=$False)]
        [switch]$Multiselect,

        [Parameter(Mandatory=$False)]
        [scriptblock]$ChoiceAction,

        [Parameter(Mandatory=$False)]
        [string]$ReturnValueName,        

        [Parameter(Mandatory=$False)]
        [switch]$ReadPowershellScriptDescription

    )

    $SOCBanner = '


                  |\                     /)
                /\_\\__               (_//
               |   `>\-`     _._       //`)
                \ /` \\  _.-`:::`-._  //
                 `    \|`    :::    `|/
                       |     :::     |
                       |.....:::.....|
                       |:::::::::::::|
                       |     :::     |
                       \     :::     /
                        \    :::    /
                         `-. ::: .-`
                          //`:::`\\
                         //   `   \\
                        |/         \\ 
                                                  
        CYBRHUNTER SECURITY OPERATIONS SCRIPTS ARMORY

 '
    Clear-Host
    Write-Host $SOCBanner -ForegroundColor Green

    $vkeycode = 0
    $Position = 0
    $Selection = @()

    # Setting cursor options
    $CursorPosition = [System.Console]::CursorTop
    [Console]::CursorVisible = $False # Prevents cursor flickering

    $SelectedMenuItemsList = $MenuItems.($MenuArrayListSelector)

    if ($SelectedMenuItemsList.Length -gt 0)
	{
        Start-DrawMenu $SelectedMenuItemsList $Position $Multiselect $Selection
        
        # KeyCode 13 = Enter
        # KeyCode 27 = Escape
		While ($vkeycode -ne 13 -and $vkeycode -ne 27) {

            $KeyOptions = [System.Management.Automation.Host.ReadKeyOptions]"NoEcho,IncludeKeyDown"
			$Press = $Host.UI.RawUI.ReadKey($KeyOptions)
			$vkeycode = $Press.virtualkeycode
			if ($vkeycode -eq 38 -or $Press.Character -eq 'k') {$Position--}
			if ($vkeycode -eq 40 -or $Press.Character -eq 'j') {$Position++}
			if ($Position -lt 0) {$Position = 0}
			if ($vkeycode -eq 27) {$Position = $null }
			if ($Position -ge $SelectedMenuItemsList.length) {$Position = $SelectedMenuItemsList.length -1}
			if ($vkeycode -ne 27 -and $vkeycode -ne 17)
			{
                Clear-Host
                Write-Host $SOCBanner -ForegroundColor Green
				[System.Console]::SetCursorPosition(0, $CursorPosition)
                Start-DrawMenu $SelectedMenuItemsList $Position $Multiselect $Selection

                if ($ReadPowershellScriptDescription) {
                    Write-Host "`n"
                    $ScriptDescription = $MenuItems[$Position].Description
                    Write-Host "   $ScriptDescription" -ForegroundColor Yellow

                }
            }
		}
	}
	else
	{
		$Position = $null
    }
    
    # Restoring Cursor Options
    [Console]::CursorVisible = $True
    $Host.UI.RawUI.FlushInputBuffer()

    if ($ReturnIndex -eq $False -and $Position -ne $null)
	{
        # If we only want to return the value of a particular item in the menu dict
        # then follow this path
        if ($ReturnValueName) {
            Return $MenuItems[$Position].$ReturnValueName
        }
        # However, if we wish to execute a script as part of the menu selection, use this
        else {
            # Invoke-Expression (Invoke-WebRequest $MenuItems[$Position].Url -UseDefaultCredentials -UseBasicParsing)
            $ChoiceAction.Invoke()
            Return
        }
        
	}
	else 
	{
		Return $Position
    }
}

# ***** END: INTERACTIVE MENU CODE *****

Function Invoke-AzureDevOpsAPI {

    <#

    .SYNOPSIS
        Function to connect to Azure DevOps API Endpoints.

    .DESCRIPTION
        TBD

    .PARAMETER PersonalAccessToken
        Your read-only PAT

    .PARAMETER RepoName
        Your read-only PAT

    .PARAMETER AzureDevOpsProjectName
        Your read-only PAT

    .PARAMETER AzureDevOpsAccountName
        Your read-only PAT

    .PARAMETER APIOperation
        Your read-only PAT

    .PARAMETER FilePath
        Your read-only PAT

    .EXAMPLE
        Todo

    #>

    Param (
        [Parameter(Mandatory=$True)]
        [String]$PersonalAccessToken,

        [Parameter(Mandatory=$True)]
        [String]$RepoName,

        [Parameter(Mandatory=$True)]
        [String]$AzureDevOpsProjectName,

        [Parameter(Mandatory=$False)]
        [String]$AzureDevOpsAccountName = "some_org",

        [Parameter(Mandatory=$False)]
        [ValidateSet("download_file", "get_file_contents", "list_directory_contents")]
        [String]$APIOperation = "get_file_contents",

        [Parameter(Mandatory=$False)]
        [String]$FilePath

    )
    

    Add-Type -AssemblyName System.Web

    $UserName = ""
    $Base64AuthInfo = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(("{0}:{1}" -f $UserName,$PersonalAccessToken)))
    $HTTPEncodedFilePath = [System.Web.HttpUtility]::UrlPathEncode($FilePath)
    $HTTPEncodedProjectName = [System.Web.HttpUtility]::UrlPathEncode($AzureDevOpsProjectName)
    $RepoName = [System.Web.HttpUtility]::UrlPathEncode($RepoName)

    switch ($APIOperation) {

        download_file {

            if(!$FilePath) {
                Write-Host "You must provide a value for the FilePath parameter"
                break
            }
            try {
                $APIURI = "https://dev.azure.com/$($AzureDevOpsAccountName)/$($HTTPEncodedProjectName)/_apis/git/repositories/$($RepoName)/items?path=$($HTTPEncodedFilePath)&download=true&api-version=6.0"
            }
            catch {
                Write-Host $_.ErrorDetails
                break
            }

            $ReqResults = Invoke-RestMethod -Uri $APIURI -Method Get -ContentType "application/json" -Headers @{Authorization=("Basic {0}" -f $Base64AuthInfo)}

            Return $ReqResults

          }

        get_file_contents {

            if(!$FilePath) {
                Write-Host "You must provide a value for the FilePath parameter"
                break
            }
            try {
                $APIURI = "https://dev.azure.com/$($AzureDevOpsAccountName)/$($HTTPEncodedProjectName)/_apis/git/repositories/$($RepoName)/items?path=$($HTTPEncodedFilePath)&download=false&`$format=text&api-version=6.0"
            }
            catch {
                Write-Host $_.ErrorDetails
                break
            }

            $ReqResults = Invoke-RestMethod -Uri $APIURI -Method Get -ContentType "application/json" -Headers @{Authorization=("Basic {0}" -f $Base64AuthInfo)}

            Return $ReqResults

        }

        list_directory_contents {

            if(!$FilePath) {
                Write-Host "You must provide a value for the FilePath parameter"
                break
            }
            try {
                $APIURI = "https://dev.azure.com/$($AzureDevOpsAccountName)/$($HTTPEncodedProjectName)/_apis/git/repositories/$($RepoName)/items?scopePath=$($HTTPEncodedFilePath)&recursionLevel=Full&includeContentMetadata=true&api-version=6.0-preview.1"
            }
            catch {
                Write-Host $_.ErrorDetails
                break
            }

            $ReqResults = Invoke-RestMethod -Uri $APIURI -Method Get -ContentType "application/json" -Headers @{Authorization=("Basic {0}" -f $Base64AuthInfo)}

            Return $ReqResults
        }

    }

    Write-Host $GetFileContentsURI

    
}

Function Get-ScriptsFromRepository {

    <#

    .DESCRIPTION
        This function will grab remote scripts from our GIT server and display them in a menu
    
    .PARAMETER PersonalAccessToken
        Your PAT as obtained from Azure DevOps

    .PARAMETER SomeSwitchOptionWhatever
        This parameter is a mere placeholder for the moment :)

    .EXAMPLE
        To call this script you need to open a non-ISE Powershell console and run:

        Get-ScriptsFromRepository -PersonalAccessToken [YourToken]

    #>

    Param ( 

      [Parameter(Mandatory=$False, ParameterSetName="Standard")]
      [System.Security.SecureString]$PersonalAccessToken,

      [Parameter(Mandatory=$False, ParameterSetName="Standard")]
      [Switch]$SomeSwitchOptionWhatever

    )

    if ($Global:PersonalAccessTokenStored) {
        # We have a previously instantiated PAT, let's use it
        $PAT = [Runtime.InteropServices.Marshal]::PtrToStringUni( [Runtime.InteropServices.Marshal]::SecureStringToGlobalAllocUnicode( $Global:PersonalAccessTokenStored ))
    }
    elseif (!$PersonalAccessToken) {
        $PATSecureString = Read-Host -AsSecureString -Prompt "Please type in your Azure DevOps PAT"
        $PAT = [Runtime.InteropServices.Marshal]::PtrToStringUni( [Runtime.InteropServices.Marshal]::SecureStringToGlobalAllocUnicode( $PATSecureString ))

        $Global:PersonalAccessTokenStored = $PATSecureString
    }
    else {
        $PAT = [Runtime.InteropServices.Marshal]::PtrToStringUni( [Runtime.InteropServices.Marshal]::SecureStringToGlobalAllocUnicode( $PersonalAccessToken ))
    }

    # List Scripts
    $RepoScriptsList = Invoke-AzureDevOpsAPI -PersonalAccessToken $PAT -AzureDevOpsProjectName "cybrhunter" -RepoName "CyberOps" -APIOperation list_directory_contents -FilePath "\analyst_scripts\powershell"
    $PowershellScriptList = $RepoScriptsList | Where-Object {$_.Value.Path -LIKE "*powershell/*"}

    # Instantiating an ArrayList that will hold all of our dictionary entries
    [System.Collections.ArrayList]$OpsFunctionsDict = @()

    # We need to iterate over the JSON items in the returned response and collect those in a proper PS Object
    ForEach($Item in $PowershellScriptList.Value) {

        # Instantiating an Ordered Dict object to store our properties
        $OpsFunction = [Ordered]@{ 

            "ScriptName"        = "NA"
            "Url"               = $False
            "Path"              = "NA"
            "Description"       = "NA"
            "ScriptContents"    = "NA"

        }

        $OpsFunction['Script'] = $Item.Path.TrimStart("/")
        $OpsFunction['Url'] = $Item.url
        $OpsFunction['Path'] = $Item.Path

        # Skip any item that is a directory
        if ($Item.isFolder -eq "True") {
            continue
        }

        # Get the script Description if any
        $ScriptContents = Invoke-AzureDevOpsAPI -PersonalAccessToken $PAT -AzureDevOpsProjectName "cybrhunter" -RepoName "CyberOps" -APIOperation get_file_contents -FilePath $Item.Path
        $RegExOptions = [System.Text.RegularExpressions.RegexOptions]::Singleline
        $Pattern = [Regex]::new('\<\#(.*?)\#\>', $RegExOptions)
        
        try {
            $RegExMatches = $Pattern.Matches($ScriptContents)
            $OpsFunction['Description'] = $RegExMatches.Groups[1].Value
        }
        catch {
            $OpsFunction['Description'] = "This script does not have a description. Please ask the author to provide one :)"
        }

        # Adding the collected dict values to a PSObject, this will allow us to capture each property as a "column"
        $OpsFunctionObj = New-Object -TypeName PSObject -Property $OpsFunction

        # We have set all our values in the Functions Dict, now let's append that to our master list
        $OpsFunctionsDict.Add($OpsFunctionObj) | Out-Null

    }

    # Let's remove any scripts we would like to filter out of our menu
    # Create an array of script names here that you would like to remove, wildcards accepted
    # These will be compared against the values of the "Script" key in the $OpsFunctionsDict dictionary
    $ListOfScriptsToFilterOut = @("analyst_scripts/powershell", "*archive*", "*Get-ScriptsFromRepository.ps1*", "*Get-InteractiveMenu.ps1*")

    foreach ($WordFilder in $ListOfScriptsToFilterOut) {
        # First, let's obtain an array of all the indices where the keyword is located, which can be more than 1
        $ObjectIndexInArray = $OpsFunctionsDict.Where({$_.Script -like $WordFilder}) | ForEach-Object {$OpsFunctionsDict.IndexOf($_)}
        # Now let's cycle through the amount of times the keyword has been detected in the Script Array, 
        # we then need to repeat the operation of finding the index of the object we want to remove with
        # the filter to only return the "first" match. If we don't do this, then we could be removing 
        # the wrong scripts, since the collection $OpsFunctionsDict is modified as we remove things
        # So each time we remove something we have to repeat the operation... There are easier ways to do this probably
        foreach ($IndexOfItemToRemove in $ObjectIndexInArray) {
            $ObjectIndexInArray2 = $OpsFunctionsDict.Where({$_.Script -like $WordFilder}, 1) | ForEach-Object {$OpsFunctionsDict.IndexOf($_)}
            $OpsFunctionsDict.Remove($OpsFunctionsDict[$ObjectIndexInArray2])
        }
    }

    # Present Menu with the resulting scripts. Upon pressing "enter" these will be executed 
    # and any required arguments requested through the console.
    # We use the "Script" column as the selector for the array that we want to display as a Menu
    While ($True) {

        [scriptblock]$MenuAction = {

            $ScriptContents = Invoke-AzureDevOpsAPI -PersonalAccessToken $PAT -AzureDevOpsProjectName "cybrhunter" -RepoName "CyberOps" -APIOperation get_file_contents -FilePath $MenuItems[$Position].Path

            Invoke-Expression $ScriptContents
        }

        $MenuSelectionValue = New-Menu -MenuItems $OpsFunctionsDict -MenuArrayListSelector "Script" -ReadPowershellScriptDescription -ReturnValueName "Path"

        $ScriptContents = Invoke-AzureDevOpsAPI -PersonalAccessToken $PAT -AzureDevOpsProjectName "cybrhunter" -RepoName "CyberOps" -APIOperation get_file_contents -FilePath $MenuSelectionValue
        $ScriptToRun = [scriptblock]::Create($ScriptContents)

        New-Module -ScriptBlock $ScriptToRun | Out-Null

    } 

}
