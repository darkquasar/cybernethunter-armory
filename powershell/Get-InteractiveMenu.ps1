<#
    CYBRHUNTER SECURITY OPERATIONS ARMORY
    Author: Diego Perez
    Version: 1.3.0
    Module: Get-InteractiveMenu.ps1
    Description: This module generates an interactive menu from passed variables.
    Ref: https://github.com/chrisseroka/ps-menu/blob/master/ps-menu.psm1
#>

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

    <#

    .SYNOPSIS
        Function to create new menus based on an array and a main array selector.

    .DESCRIPTION
        This function will allow you to display a new menu based on an attribute of an array which is used as the selector. You can pass a "ChoiceAction" parameter with a scriptblock that gets executed upon selection on an option in the menu. Alternatively, it can return a particular value from the provided array.

    .PARAMETER MenuItems
        An array of key/value pairs

    .PARAMETER MenuArrayListSelector
        The key used to create the menu options from

    .PARAMETER ChoiceAction
        A scriptblock that runs upon selection of an option

    .PARAMETER ReturnValueName
        The name of the key whose value is to be returned upon selection of an option

    .PARAMETER ProvideOptionDescription
        This switch tells the script to read a "description" key from within the passed array to display it back to the user below the options. Your array must contain one key with the name "description" for this to work.

    .EXAMPLE
        Todo

    #>

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
        [switch]$ProvideOptionDescription

    )

    $SOCBanner = @'


     _____       _          _   _             _            
    /  __ \     | |        | | | |           | |           
    | /  \/_   _| |__  _ __| |_| |_   _ _ __ | |_ ___ _ __ 
    | |   | | | | '_ \| '__|  _  | | | | '_ \| __/ _ \ '__|
    | \__/\ |_| | |_) | |  | | | | |_| | | | | ||  __/ |   
     \____/\__, |_.__/|_|  \_| |_/\__,_|_| |_|\__\___|_|   
            __/ |                                          
           |___/                                           
    

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
                                                  
                  CYBRHUNTER SCRIPTS ARMORY

'@
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

                if ($ProvideOptionDescription) {
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