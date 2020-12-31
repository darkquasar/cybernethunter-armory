<# 
    CYBRHUNTER SECURITY OPERATIONS :)
    Author: Diego Perez (@darkquassar)
    Version: 1.0.0
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