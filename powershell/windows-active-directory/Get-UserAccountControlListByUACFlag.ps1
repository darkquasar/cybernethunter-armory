# See https://github.com/russelltomkins/Active-Directory for more scripts to add to this audit
# Add https://gallery.technet.microsoft.com/scriptcenter/Find-all-accounts-using-04658a99 to get list of accounts with delegation
# Convert decimal to HEX: '{0:x}' -f 193034


Function Find-ADAccountByUACFlag {

    <#

    .SYNOPSIS
        Function to find a user account by their UACFlag in Active Directory using .NET. Returns a System.DirectoryServices.DirectoryEntry object.

    .DESCRIPTION
        This function searches all accounts in the AD base directory searching with a specific UACFlag and returns a table of all accounts

    .PARAMETER UACValue
        The UAC Flag value in decimal. See http://support.microsoft.com/kb/305144/en-us

    .PARAMETER ADBaseDir
        The DN of the base directory to search from.

    .EXAMPLE
        Todo

    #>

    Param (
        [Parameter(Mandatory=$True)]
        [String]$UACValue,

        [Parameter(Mandatory=$True)]
        [String]$ADBaseDir,

        [Parameter(Mandatory=$False)]
        [System.Array]$ADProperties

    )
    
    # Setting this at the beginning of any function to determine whether we should be providing output to stdout
    # Useful for debugging.
    if ($PSBoundParameters['Verbose']) { $Global:LogfileWriteConsole = $True } elseif ($Global:LogfileWriteConsole -ne $True) { $Global:LogfileWriteConsole = $False }

    Write-Host "Looking for UACValue $UACValue..."

    # We use .NET here to connect to the Domain via LDAP and check whether an account is member of the group

    $strFilter = "(&(userAccountControl:1.2.840.113556.1.4.803:=$UACValue))"
    $strDomainDN = "LDAP://$ADBaseDir"
    $objDomain = New-Object -TypeName System.DirectoryServices.DirectoryEntry -ArgumentList $strDomainDN
    $objSearcher = New-Object System.DirectoryServices.DirectorySearcher
    $objSearcher.SearchRoot = $objDomain
    $objSearcher.PageSize = 10
    $objSearcher.Filter = $strFilter
    $objSearcher.SearchScope = "Subtree"

    ForEach ($prop in $ADProperties) {$objSearcher.PropertiesToLoad.Add($prop)}
    
    $objADSearchResult = $objSearcher.FindAll()
    

    Return $objADSearchResult
   
}

[System.Collections.ArrayList]$UACListByUACFlag = @()

Function Get-UsersUACListByUAC {

    # This function returns similar results to Get-UsersUACListByUser except that it will produce a list grouped by userAccountControl values
    
    # We need an array to store our results
    #[System.Collections.ArrayList]$Global:UACListByUACFlag = @()

    # Storing values of UAC Flags in HashTable
    # see http://support.microsoft.com/kb/305144/en-us
	
    $userAccountControlHashTable = New-Object HashTable
    $userAccountControlHashTable.Add("SCRIPT",1)
    $userAccountControlHashTable.Add("ACCOUNTDISABLE",2)
    $userAccountControlHashTable.Add("HOMEDIR_REQUIRED",8) 
    $userAccountControlHashTable.Add("LOCKOUT",16)
    $userAccountControlHashTable.Add("PASSWD_NOTREQD",32)
    $userAccountControlHashTable.Add("ENCRYPTED_TEXT_PWD_ALLOWED",128)
    $userAccountControlHashTable.Add("TEMP_DUPLICATE_ACCOUNT",256)
    $userAccountControlHashTable.Add("NORMAL_ACCOUNT",512)
    $userAccountControlHashTable.Add("INTERDOMAIN_TRUST_ACCOUNT",2048)
    $userAccountControlHashTable.Add("WORKSTATION_TRUST_ACCOUNT",4096)
    $userAccountControlHashTable.Add("SERVER_TRUST_ACCOUNT",8192)
    $userAccountControlHashTable.Add("DONT_EXPIRE_PASSWORD",65536) 
    $userAccountControlHashTable.Add("MNS_LOGON_ACCOUNT",131072)
    $userAccountControlHashTable.Add("SMARTCARD_REQUIRED",262144)
    $userAccountControlHashTable.Add("TRUSTED_FOR_DELEGATION",524288) 
    $userAccountControlHashTable.Add("NOT_DELEGATED",1048576)
    $userAccountControlHashTable.Add("USE_DES_KEY_ONLY",2097152) 
    $userAccountControlHashTable.Add("DONT_REQ_PREAUTH",4194304) 
    $userAccountControlHashTable.Add("PASSWORD_EXPIRED",8388608) 
    $userAccountControlHashTable.Add("TRUSTED_TO_AUTH_FOR_DELEGATION",16777216) 
    $userAccountControlHashTable.Add("PARTIAL_SECRETS_ACCOUNT",67108864)

    $userAccountControlHashTable = $userAccountControlHashTable.GetEnumerator() | Sort-Object -Property Value

    ForEach($UACFlag in $userAccountControlHashTable){
       
       $objListOfUsersWithUACFlag = Find-ADAccount -ADBaseDir "DC=some-of-your-domains,DC=com,DC=au" -UACValue $UACFlag.Value
       
       ForEach($UserItem in $objListOfUsersWithUACFlag) {

           $UserEntry = New-Object -TypeName PSObject -Property @{ "User" = $UserItem.Properties.samaccountname[0] ; "UACDecimal" = $UserItem.Properties.useraccountcontrol[0] ; "UACFlag" = $UACFlag.Key }
           $UACListByUACFlag.add($UserEntry) | Out-Null
           
       }
    }
}


Function Set-UserAccountControlValueTable
{
	# see http://support.microsoft.com/kb/305144/en-us
	
    $userAccountControlHashTable = New-Object HashTable
    $userAccountControlHashTable.Add("SCRIPT",1)
    $userAccountControlHashTable.Add("ACCOUNTDISABLE",2)
    $userAccountControlHashTable.Add("HOMEDIR_REQUIRED",8) 
    $userAccountControlHashTable.Add("LOCKOUT",16)
    $userAccountControlHashTable.Add("PASSWD_NOTREQD",32)
    $userAccountControlHashTable.Add("ENCRYPTED_TEXT_PWD_ALLOWED",128)
    $userAccountControlHashTable.Add("TEMP_DUPLICATE_ACCOUNT",256)
    $userAccountControlHashTable.Add("NORMAL_ACCOUNT",512)
    $userAccountControlHashTable.Add("INTERDOMAIN_TRUST_ACCOUNT",2048)
    $userAccountControlHashTable.Add("WORKSTATION_TRUST_ACCOUNT",4096)
    $userAccountControlHashTable.Add("SERVER_TRUST_ACCOUNT",8192)
    $userAccountControlHashTable.Add("DONT_EXPIRE_PASSWORD",65536) 
    $userAccountControlHashTable.Add("MNS_LOGON_ACCOUNT",131072)
    $userAccountControlHashTable.Add("SMARTCARD_REQUIRED",262144)
    $userAccountControlHashTable.Add("TRUSTED_FOR_DELEGATION",524288) 
    $userAccountControlHashTable.Add("NOT_DELEGATED",1048576)
    $userAccountControlHashTable.Add("USE_DES_KEY_ONLY",2097152) 
    $userAccountControlHashTable.Add("DONT_REQ_PREAUTH",4194304) 
    $userAccountControlHashTable.Add("PASSWORD_EXPIRED",8388608) 
    $userAccountControlHashTable.Add("TRUSTED_TO_AUTH_FOR_DELEGATION",16777216) 
    $userAccountControlHashTable.Add("PARTIAL_SECRETS_ACCOUNT",67108864)

    $userAccountControlHashTable = $userAccountControlHashTable.GetEnumerator() | Sort-Object -Property Value 
    return $userAccountControlHashTable
}

Function Get-UserAccountControlFlags($userInput)
{    
        Set-UserAccountControlValueTable | foreach {
	    $binaryAnd = $_.value -band $userInput
	    if ($binaryAnd -ne "0") { write $_ }
    }
}

Function Get-UsersUACListByUser {

# This function returns a list of Users with each of the flags for their userAccountControl value

[System.Collections.ArrayList]$UACListByUser = @()

Get-ADUser -Filter 'SamAccountName -like "*"' -Properties userAccountControl | 
  Select-Object SamAccountName, userAccountControl | 
    ForEach-Object {
      $UACTranslated = Get-UserAccountControlFlags($_.userAccountControl)
      $UserItem = New-Object -TypeName PSObject -Property @{ "User" = $_.SamAccountName ; "UACDecimal" = $_.userAccountControl ; "UACTranslated" = $($UACTranslated.Name -join " ") }
      $UACListByUser.Add($UserItem)
      }

}

function Get-DomainSearcher {
<#
.SYNOPSIS
Helper used by various functions that builds a custom AD searcher object.
Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: Get-Domain  
.DESCRIPTION
Takes a given domain and a number of customizations and returns a
System.DirectoryServices.DirectorySearcher object. This function is used
heavily by other LDAP/ADSI searcher functions (Verb-Domain*).
.PARAMETER Domain
Specifies the domain to use for the query, defaults to the current domain.
.PARAMETER LDAPFilter
Specifies an LDAP query string that is used to filter Active Directory objects.
.PARAMETER Properties
Specifies the properties of the output object to retrieve from the server.
.PARAMETER SearchBase
The LDAP source to search through, e.g. "LDAP://OU=secret,DC=testlab,DC=local"
Useful for OU queries.
.PARAMETER SearchBasePrefix
Specifies a prefix for the LDAP search string (i.e. "CN=Sites,CN=Configuration").
.PARAMETER Server
Specifies an Active Directory server (domain controller) to bind to for the search.
.PARAMETER SearchScope
Specifies the scope to search under, Base/OneLevel/Subtree (default of Subtree).
.PARAMETER ResultPageSize
Specifies the PageSize to set for the LDAP searcher object.
.PARAMETER ResultPageSize
Specifies the PageSize to set for the LDAP searcher object.
.PARAMETER ServerTimeLimit
Specifies the maximum amount of time the server spends searching. Default of 120 seconds.
.PARAMETER SecurityMasks
Specifies an option for examining security information of a directory object.
One of 'Dacl', 'Group', 'None', 'Owner', 'Sacl'.
.PARAMETER Tombstone
Switch. Specifies that the searcher should also return deleted/tombstoned objects.
.PARAMETER Credential
A [Management.Automation.PSCredential] object of alternate credentials
for connection to the target domain.
.EXAMPLE
Get-DomainSearcher -Domain testlab.local
Return a searcher for all objects in testlab.local.
.EXAMPLE
Get-DomainSearcher -Domain testlab.local -LDAPFilter '(samAccountType=805306368)' -Properties 'SamAccountName,lastlogon'
Return a searcher for user objects in testlab.local and only return the SamAccountName and LastLogon properties.
.EXAMPLE
Get-DomainSearcher -SearchBase "LDAP://OU=secret,DC=testlab,DC=local"
Return a searcher that searches through the specific ADS/LDAP search base (i.e. OU).
.OUTPUTS
System.DirectoryServices.DirectorySearcher
#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('System.DirectoryServices.DirectorySearcher')]
    [CmdletBinding()]
    Param(
        [Parameter(ValueFromPipeline = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $LDAPFilter,

        [ValidateNotNullOrEmpty()]
        [String[]]
        $Properties,

        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $SearchBase,

        [ValidateNotNullOrEmpty()]
        [String]
        $SearchBasePrefix,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $SearchScope = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit = 120,

        [ValidateSet('Dacl', 'Group', 'None', 'Owner', 'Sacl')]
        [String]
        $SecurityMasks,

        [Switch]
        $Tombstone,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    PROCESS {
        if ($PSBoundParameters['Domain']) {
            $TargetDomain = $Domain
        }
        else {
            # if not -Domain is specified, retrieve the current domain name
            if ($PSBoundParameters['Credential']) {
                $DomainObject = Get-Domain -Credential $Credential
            }
            else {
                $DomainObject = Get-Domain
            }
            $TargetDomain = $DomainObject.Name
        }

        if (-not $PSBoundParameters['Server']) {
            # if there's not a specified server to bind to, try to pull the current domain PDC
            try {
                if ($DomainObject) {
                    $BindServer = $DomainObject.PdcRoleOwner.Name
                }
                elseif ($PSBoundParameters['Credential']) {
                    $BindServer = ((Get-Domain -Credential $Credential).PdcRoleOwner).Name
                }
                else {
                    $BindServer = ((Get-Domain).PdcRoleOwner).Name
                }
            }
            catch {
                throw "[Get-DomainSearcher] Error in retrieving PDC for current domain: $_"
            }
        }
        else {
            $BindServer = $Server
        }

        $SearchString = 'LDAP://'

        if ($BindServer -and ($BindServer.Trim() -ne '')) {
            $SearchString += $BindServer
            if ($TargetDomain) {
                $SearchString += '/'
            }
        }

        if ($PSBoundParameters['SearchBasePrefix']) {
            $SearchString += $SearchBasePrefix + ','
        }

        if ($PSBoundParameters['SearchBase']) {
            if ($SearchBase -Match '^GC://') {
                # if we're searching the global catalog, get the path in the right format
                $DN = $SearchBase.ToUpper().Trim('/')
                $SearchString = ''
            }
            else {
                if ($SearchBase -match '^LDAP://') {
                    if ($SearchBase -match "LDAP://.+/.+") {
                        $SearchString = ''
                        $DN = $SearchBase
                    }
                    else {
                        $DN = $SearchBase.SubString(7)
                    }
                }
                else {
                    $DN = $SearchBase
                }
            }
        }
        else {
            # transform the target domain name into a distinguishedName if an ADS search base is not specified
            if ($TargetDomain -and ($TargetDomain.Trim() -ne '')) {
                $DN = "DC=$($TargetDomain.Replace('.', ',DC='))"
            }
        }

        $SearchString += $DN
        Write-Verbose "[Get-DomainSearcher] search string: $SearchString"

        if ($Credential -ne [Management.Automation.PSCredential]::Empty) {
            Write-Verbose "[Get-DomainSearcher] Using alternate credentials for LDAP connection"
            # bind to the inital search object using alternate credentials
            $DomainObject = New-Object DirectoryServices.DirectoryEntry($SearchString, $Credential.UserName, $Credential.GetNetworkCredential().Password)
            $Searcher = New-Object System.DirectoryServices.DirectorySearcher($DomainObject)
        }
        else {
            # bind to the inital object using the current credentials
            $Searcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]$SearchString)
        }

        $Searcher.PageSize = $ResultPageSize
        $Searcher.SearchScope = $SearchScope
        $Searcher.CacheResults = $False
        $Searcher.ReferralChasing = [System.DirectoryServices.ReferralChasingOption]::All

        if ($PSBoundParameters['ServerTimeLimit']) {
            $Searcher.ServerTimeLimit = $ServerTimeLimit
        }

        if ($PSBoundParameters['Tombstone']) {
            $Searcher.Tombstone = $True
        }

        if ($PSBoundParameters['LDAPFilter']) {
            $Searcher.filter = $LDAPFilter
        }

        if ($PSBoundParameters['SecurityMasks']) {
            $Searcher.SecurityMasks = Switch ($SecurityMasks) {
                'Dacl' { [System.DirectoryServices.SecurityMasks]::Dacl }
                'Group' { [System.DirectoryServices.SecurityMasks]::Group }
                'None' { [System.DirectoryServices.SecurityMasks]::None }
                'Owner' { [System.DirectoryServices.SecurityMasks]::Owner }
                'Sacl' { [System.DirectoryServices.SecurityMasks]::Sacl }
            }
        }

        if ($PSBoundParameters['Properties']) {
            # handle an array of properties to load w/ the possibility of comma-separated strings
            $PropertiesToLoad = $Properties| ForEach-Object { $_.Split(',') }
            $Null = $Searcher.PropertiesToLoad.AddRange(($PropertiesToLoad))
        }

        $Searcher
    }
}


Function Convert-LDAPProperty {
	<#
		.SYNOPSIS
		Helper that converts specific LDAP property result fields and outputs
		a custom psobject.
		Author: Will Schroeder (@harmj0y)  
		License: BSD 3-Clause  
		Required Dependencies: None  
		
		.DESCRIPTION
		Converts a set of raw LDAP properties results from ADSI/LDAP searches
		into a proper PSObject. Used by several of the Get-Domain* function.
		
		.PARAMETER Properties
		Properties object to extract out LDAP fields for display.
		
		.OUTPUTS
		System.Management.Automation.PSCustomObject
		A custom PSObject with LDAP hashtable properties translated.
	#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('System.Management.Automation.PSCustomObject')]
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $True, ValueFromPipeline = $True)]
        [ValidateNotNullOrEmpty()]
        $Properties
    )

    $ObjectProperties = @{}

    $Properties.PropertyNames | ForEach-Object {
        if ($_ -ne 'adspath') {
            if (($_ -eq 'objectsid') -or ($_ -eq 'sidhistory')) {
                # convert all listed sids (i.e. if multiple are listed in sidHistory)
                $ObjectProperties[$_] = $Properties[$_] | ForEach-Object { (New-Object System.Security.Principal.SecurityIdentifier($_, 0)).Value }
            }
            elseif ($_ -eq 'grouptype') {
                $ObjectProperties[$_] = $Properties[$_][0] -as $GroupTypeEnum
            }
            elseif ($_ -eq 'samaccounttype') {
                $ObjectProperties[$_] = $Properties[$_][0] -as $SamAccountTypeEnum
            }
            elseif ($_ -eq 'objectguid') {
                # convert the GUID to a string
                $ObjectProperties[$_] = (New-Object Guid (,$Properties[$_][0])).Guid
            }
            elseif ($_ -eq 'useraccountcontrol') {
                $ObjectProperties[$_] = $Properties[$_][0] -as $UACEnum
            }
            elseif ($_ -eq 'ntsecuritydescriptor') {
                # $ObjectProperties[$_] = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList $Properties[$_][0], 0
                $Descriptor = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList $Properties[$_][0], 0
                if ($Descriptor.Owner) {
                    $ObjectProperties['Owner'] = $Descriptor.Owner
                }
                if ($Descriptor.Group) {
                    $ObjectProperties['Group'] = $Descriptor.Group
                }
                if ($Descriptor.DiscretionaryAcl) {
                    $ObjectProperties['DiscretionaryAcl'] = $Descriptor.DiscretionaryAcl
                }
                if ($Descriptor.SystemAcl) {
                    $ObjectProperties['SystemAcl'] = $Descriptor.SystemAcl
                }
            }
            elseif ($_ -eq 'accountexpires') {
                if ($Properties[$_][0] -gt [DateTime]::MaxValue.Ticks) {
                    $ObjectProperties[$_] = "NEVER"
                }
                else {
                    $ObjectProperties[$_] = [datetime]::fromfiletime($Properties[$_][0])
                }
            }
            elseif ( ($_ -eq 'lastlogon') -or ($_ -eq 'lastlogontimestamp') -or ($_ -eq 'pwdlastset') -or ($_ -eq 'lastlogoff') -or ($_ -eq 'badPasswordTime') ) {
                # convert timestamps
                if ($Properties[$_][0] -is [System.MarshalByRefObject]) {
                    # if we have a System.__ComObject
                    $Temp = $Properties[$_][0]
                    [Int32]$High = $Temp.GetType().InvokeMember('HighPart', [System.Reflection.BindingFlags]::GetProperty, $Null, $Temp, $Null)
                    [Int32]$Low  = $Temp.GetType().InvokeMember('LowPart',  [System.Reflection.BindingFlags]::GetProperty, $Null, $Temp, $Null)
                    $ObjectProperties[$_] = ([datetime]::FromFileTime([Int64]("0x{0:x8}{1:x8}" -f $High, $Low)))
                }
                else {
                    # otherwise just a string
                    $ObjectProperties[$_] = ([datetime]::FromFileTime(($Properties[$_][0])))
                }
            }
            elseif ($Properties[$_][0] -is [System.MarshalByRefObject]) {
                # try to convert misc com objects
                $Prop = $Properties[$_]
                try {
                    $Temp = $Prop[$_][0]
                    [Int32]$High = $Temp.GetType().InvokeMember('HighPart', [System.Reflection.BindingFlags]::GetProperty, $Null, $Temp, $Null)
                    [Int32]$Low  = $Temp.GetType().InvokeMember('LowPart',  [System.Reflection.BindingFlags]::GetProperty, $Null, $Temp, $Null)
                    $ObjectProperties[$_] = [Int64]("0x{0:x8}{1:x8}" -f $High, $Low)
                }
                catch {
                    Write-Verbose "[Convert-LDAPProperty] error: $_"
                    $ObjectProperties[$_] = $Prop[$_]
                }
            }
            elseif ($Properties[$_].count -eq 1) {
                $ObjectProperties[$_] = $Properties[$_][0]
            }
            else {
                $ObjectProperties[$_] = $Properties[$_]
            }
        }
    }
    try {
        New-Object -TypeName PSObject -Property $ObjectProperties
    }
    catch {
        Write-Warning "[Convert-LDAPProperty] Error parsing LDAP properties : $_"
    }
}


function Get-Domain {
<#
.SYNOPSIS
Returns the domain object for the current (or specified) domain.
Author: Will Schroeder (@harmj0y)  
License: BSD 3-Clause  
Required Dependencies: None  
.DESCRIPTION
Returns a System.DirectoryServices.ActiveDirectory.Domain object for the current
domain or the domain specified with -Domain X.
.PARAMETER Domain
Specifies the domain name to query for, defaults to the current domain.
.PARAMETER Credential
A [Management.Automation.PSCredential] object of alternate credentials
for connection to the target domain.
.EXAMPLE
Get-Domain -Domain testlab.local
.EXAMPLE
$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
Get-Domain -Credential $Cred
.OUTPUTS
System.DirectoryServices.ActiveDirectory.Domain
A complex .NET domain object.
.LINK
http://social.technet.microsoft.com/Forums/scriptcenter/en-US/0c5b3f83-e528-4d49-92a4-dee31f4b481c/finding-the-dn-of-the-the-domain-without-admodule-in-powershell?forum=ITCG
#>

    [OutputType([System.DirectoryServices.ActiveDirectory.Domain])]
    [CmdletBinding()]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty
    )

    PROCESS {
        if ($PSBoundParameters['Credential']) {

            Write-Verbose '[Get-Domain] Using alternate credentials for Get-Domain'

            if ($PSBoundParameters['Domain']) {
                $TargetDomain = $Domain
            }
            else {
                # if no domain is supplied, extract the logon domain from the PSCredential passed
                $TargetDomain = $Credential.GetNetworkCredential().Domain
                Write-Verbose "[Get-Domain] Extracted domain '$TargetDomain' from -Credential"
            }

            $DomainContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Domain', $TargetDomain, $Credential.UserName, $Credential.GetNetworkCredential().Password)

            try {
                [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($DomainContext)
            }
            catch {
                Write-Verbose "[Get-Domain] The specified domain '$TargetDomain' does not exist, could not be contacted, there isn't an existing trust, or the specified credentials are invalid: $_"
            }
        }
        elseif ($PSBoundParameters['Domain']) {
            $DomainContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext('Domain', $Domain)
            try {
                [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($DomainContext)
            }
            catch {
                Write-Verbose "[Get-Domain] The specified domain '$Domain' does not exist, could not be contacted, or there isn't an existing trust : $_"
            }
        }
        else {
            try {
                [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
            }
            catch {
                Write-Verbose "[Get-Domain] Error retrieving the current domain: $_"
            }
        }
    }
}

Function Get-DomainUser {
	<#
		.SYNOPSIS
		Return all users or specific user objects in AD.
		Author: Will Schroeder (@harmj0y)  
		License: BSD 3-Clause  
		Required Dependencies: Get-DomainSearcher, Convert-ADName, Convert-LDAPProperty  
		
		.DESCRIPTION
		Builds a directory searcher object using Get-DomainSearcher, builds a custom
		LDAP filter based on targeting/filter parameters, and searches for all objects
		matching the criteria. To only return specific properties, use
		"-Properties samaccountname,usnchanged,...". By default, all user objects for
		the current domain are returned.
		
		.PARAMETER Identity
		A SamAccountName (e.g. harmj0y), DistinguishedName (e.g. CN=harmj0y,CN=Users,DC=testlab,DC=local),
		SID (e.g. S-1-5-21-890171859-3433809279-3366196753-1108), or GUID (e.g. 4c435dd7-dc58-4b14-9a5e-1fdb0e80d201).
		Wildcards accepted. Also accepts DOMAIN\user format.
		
		.PARAMETER SPN
		Switch. Only return user objects with non-null service principal names.
		
		.PARAMETER UACFilter
		Dynamic parameter that accepts one or more values from $UACEnum, including
		"NOT_X" negation forms. To see all possible values, run '0|ConvertFrom-UACValue -ShowAll'.
		
		.PARAMETER AdminCount
		Switch. Return users with '(adminCount=1)' (meaning are/were privileged).
		
		.PARAMETER AllowDelegation
		Switch. Return user accounts that are not marked as 'sensitive and not allowed for delegation'
		
		.PARAMETER DisallowDelegation
		Switch. Return user accounts that are marked as 'sensitive and not allowed for delegation'
		
		.PARAMETER TrustedToAuth
		Switch. Return computer objects that are trusted to authenticate for other principals.
		
		.PARAMETER PreauthNotRequired
		Switch. Return user accounts with "Do not require Kerberos preauthentication" set.
		
		.PARAMETER Domain
		Specifies the domain to use for the query, defaults to the current domain.
		
		.PARAMETER LDAPFilter
		Specifies an LDAP query string that is used to filter Active Directory objects.
		
		.PARAMETER Properties
		Specifies the properties of the output object to retrieve from the server.
		
		.PARAMETER SearchBase
		The LDAP source to search through, e.g. "LDAP://OU=secret,DC=testlab,DC=local"
		Useful for OU queries.
		
		.PARAMETER Server
		Specifies an Active Directory server (domain controller) to bind to.
		
		.PARAMETER SearchScope
		Specifies the scope to search under, Base/OneLevel/Subtree (default of Subtree).
		
		.PARAMETER ResultPageSize
		Specifies the PageSize to set for the LDAP searcher object.
		
		.PARAMETER ServerTimeLimit
		Specifies the maximum amount of time the server spends searching. Default of 120 seconds.
		
		.PARAMETER SecurityMasks
		Specifies an option for examining security information of a directory object.
		One of 'Dacl', 'Group', 'None', 'Owner', 'Sacl'.
		
		.PARAMETER Tombstone
		Switch. Specifies that the searcher should also return deleted/tombstoned objects.
		
		.PARAMETER FindOne
		Only return one result object.
		
		.PARAMETER Credential
		A [Management.Automation.PSCredential] object of alternate credentials
		for connection to the target domain.
		
		.PARAMETER Raw
		Switch. Return raw results instead of translating the fields into a custom PSObject.
		
		.EXAMPLE
		Get-DomainUser -Domain testlab.local
		Return all users for the testlab.local domain
		
		.EXAMPLE
		Get-DomainUser "S-1-5-21-890171859-3433809279-3366196753-1108","administrator"
		Return the user with the given SID, as well as Administrator.
		
		.EXAMPLE
		'S-1-5-21-890171859-3433809279-3366196753-1114', 'CN=dfm,CN=Users,DC=testlab,DC=local','4c435dd7-dc58-4b14-9a5e-1fdb0e80d201','administrator' | Get-DomainUser -Properties samaccountname,lastlogoff
		lastlogoff                                   samaccountname
		----------                                   --------------
		12/31/1600 4:00:00 PM                        dfm.a
		12/31/1600 4:00:00 PM                        dfm
		12/31/1600 4:00:00 PM                        harmj0y
		12/31/1600 4:00:00 PM                        Administrator
		
		.EXAMPLE
		Get-DomainUser -SearchBase "LDAP://OU=secret,DC=testlab,DC=local" -AdminCount -AllowDelegation
		Search the specified OU for privileged user (AdminCount = 1) that allow delegation
		
		.EXAMPLE
		Get-DomainUser -LDAPFilter '(!primarygroupid=513)' -Properties samaccountname,lastlogon
		Search for users with a primary group ID other than 513 ('domain users') and only return samaccountname and lastlogon
		
		.EXAMPLE
		Get-DomainUser -UACFilter DONT_REQ_PREAUTH,NOT_PASSWORD_EXPIRED
		Find users who doesn't require Kerberos preauthentication and DON'T have an expired password.
		
		.EXAMPLE
		$SecPassword = ConvertTo-SecureString 'Password123!' -AsPlainText -Force
		$Cred = New-Object System.Management.Automation.PSCredential('TESTLAB\dfm.a', $SecPassword)
		Get-DomainUser -Credential $Cred
		
		.EXAMPLE
		Get-Domain | Select-Object -Expand name
		testlab.local
		Get-DomainUser dev\user1 -Verbose -Properties distinguishedname
		VERBOSE: [Get-DomainSearcher] search string: LDAP://PRIMARY.testlab.local/DC=testlab,DC=local
		VERBOSE: [Get-DomainSearcher] search string: LDAP://PRIMARY.testlab.local/DC=dev,DC=testlab,DC=local
		VERBOSE: [Get-DomainUser] filter string: (&(samAccountType=805306368)(|(samAccountName=user1)))
		distinguishedname
		-----------------
		CN=user1,CN=Users,DC=dev,DC=testlab,DC=local
		
		.INPUTS
		String
		
		.OUTPUTS
		PowerView.User
		Custom PSObject with translated user property fields.
		PowerView.User.Raw
		The raw DirectoryServices.SearchResult object, if -Raw is enabled.
	#>

    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSUseDeclaredVarsMoreThanAssignments', '')]
    [Diagnostics.CodeAnalysis.SuppressMessageAttribute('PSShouldProcess', '')]
    [OutputType('PowerView.User')]
    [OutputType('PowerView.User.Raw')]
    [CmdletBinding(DefaultParameterSetName = 'AllowDelegation')]
    Param(
        [Parameter(Position = 0, ValueFromPipeline = $True, ValueFromPipelineByPropertyName = $True)]
        [Alias('DistinguishedName', 'SamAccountName', 'Name', 'MemberDistinguishedName', 'MemberName')]
        [String[]]
        $Identity,

        [Switch]
        $SPN,

        [Switch]
        $AdminCount,

        [Parameter(ParameterSetName = 'AllowDelegation')]
        [Switch]
        $AllowDelegation,

        [Parameter(ParameterSetName = 'DisallowDelegation')]
        [Switch]
        $DisallowDelegation,

        [Switch]
        $TrustedToAuth,

        [Alias('KerberosPreauthNotRequired', 'NoPreauth')]
        [Switch]
        $PreauthNotRequired,

        [ValidateNotNullOrEmpty()]
        [String]
        $Domain,

        [ValidateNotNullOrEmpty()]
        [Alias('Filter')]
        [String]
        $LDAPFilter,

        [ValidateNotNullOrEmpty()]
        [String[]]
        $Properties,

        [ValidateNotNullOrEmpty()]
        [Alias('ADSPath')]
        [String]
        $SearchBase,

        [ValidateNotNullOrEmpty()]
        [Alias('DomainController')]
        [String]
        $Server,

        [ValidateSet('Base', 'OneLevel', 'Subtree')]
        [String]
        $SearchScope = 'Subtree',

        [ValidateRange(1, 10000)]
        [Int]
        $ResultPageSize = 200,

        [ValidateRange(1, 10000)]
        [Int]
        $ServerTimeLimit,

        [ValidateSet('Dacl', 'Group', 'None', 'Owner', 'Sacl')]
        [String]
        $SecurityMasks,

        [Switch]
        $Tombstone,

        [Alias('ReturnOne')]
        [Switch]
        $FindOne,

        [Management.Automation.PSCredential]
        [Management.Automation.CredentialAttribute()]
        $Credential = [Management.Automation.PSCredential]::Empty,

        [Switch]
        $Raw
    )
<#
    DynamicParam {
        $UACValueNames = [Enum]::GetNames($UACEnum)
        # add in the negations
        $UACValueNames = $UACValueNames | ForEach-Object {$_; "NOT_$_"}
        # create new dynamic parameter
        New-DynamicParameter -Name UACFilter -ValidateSet $UACValueNames -Type ([array])
    }
#>
    BEGIN {
        $SearcherArguments = @{}
        if ($PSBoundParameters['Domain']) { $SearcherArguments['Domain'] = $Domain }
        if ($PSBoundParameters['Properties']) { $SearcherArguments['Properties'] = $Properties }
        if ($PSBoundParameters['SearchBase']) { $SearcherArguments['SearchBase'] = $SearchBase }
        if ($PSBoundParameters['Server']) { $SearcherArguments['Server'] = $Server }
        if ($PSBoundParameters['SearchScope']) { $SearcherArguments['SearchScope'] = $SearchScope }
        if ($PSBoundParameters['ResultPageSize']) { $SearcherArguments['ResultPageSize'] = $ResultPageSize }
        if ($PSBoundParameters['ServerTimeLimit']) { $SearcherArguments['ServerTimeLimit'] = $ServerTimeLimit }
        if ($PSBoundParameters['SecurityMasks']) { $SearcherArguments['SecurityMasks'] = $SecurityMasks }
        if ($PSBoundParameters['Tombstone']) { $SearcherArguments['Tombstone'] = $Tombstone }
        if ($PSBoundParameters['Credential']) { $SearcherArguments['Credential'] = $Credential }
        $UserSearcher = Get-DomainSearcher @SearcherArguments
    }

    PROCESS {
        #bind dynamic parameter to a friendly variable
        #if ($PSBoundParameters -and ($PSBoundParameters.Count -ne 0)) {
        #    New-DynamicParameter -CreateVariables -BoundParameters $PSBoundParameters
        #}

        if ($UserSearcher) {
            $IdentityFilter = ''
            $Filter = ''
            $Identity | Where-Object {$_} | ForEach-Object {
                $IdentityInstance = $_.Replace('(', '\28').Replace(')', '\29')
                if ($IdentityInstance -match '^S-1-') {
                    $IdentityFilter += "(objectsid=$IdentityInstance)"
                }
                elseif ($IdentityInstance -match '^CN=') {
                    $IdentityFilter += "(distinguishedname=$IdentityInstance)"
                    if ((-not $PSBoundParameters['Domain']) -and (-not $PSBoundParameters['SearchBase'])) {
                        # if a -Domain isn't explicitly set, extract the object domain out of the distinguishedname
                        #   and rebuild the domain searcher
                        $IdentityDomain = $IdentityInstance.SubString($IdentityInstance.IndexOf('DC=')) -replace 'DC=','' -replace ',','.'
                        Write-Verbose "[Get-DomainUser] Extracted domain '$IdentityDomain' from '$IdentityInstance'"
                        $SearcherArguments['Domain'] = $IdentityDomain
                        $UserSearcher = Get-DomainSearcher @SearcherArguments
                        if (-not $UserSearcher) {
                            Write-Warning "[Get-DomainUser] Unable to retrieve domain searcher for '$IdentityDomain'"
                        }
                    }
                }
                elseif ($IdentityInstance -imatch '^[0-9A-F]{8}-([0-9A-F]{4}-){3}[0-9A-F]{12}$') {
                    $GuidByteString = (([Guid]$IdentityInstance).ToByteArray() | ForEach-Object { '\' + $_.ToString('X2') }) -join ''
                    $IdentityFilter += "(objectguid=$GuidByteString)"
                }
                elseif ($IdentityInstance.Contains('\')) {
                    $ConvertedIdentityInstance = $IdentityInstance.Replace('\28', '(').Replace('\29', ')') | Convert-ADName -OutputType Canonical
                    if ($ConvertedIdentityInstance) {
                        $UserDomain = $ConvertedIdentityInstance.SubString(0, $ConvertedIdentityInstance.IndexOf('/'))
                        $UserName = $IdentityInstance.Split('\')[1]
                        $IdentityFilter += "(samAccountName=$UserName)"
                        $SearcherArguments['Domain'] = $UserDomain
                        Write-Verbose "[Get-DomainUser] Extracted domain '$UserDomain' from '$IdentityInstance'"
                        $UserSearcher = Get-DomainSearcher @SearcherArguments
                    }
                }
                else {
                    $IdentityFilter += "(samAccountName=$IdentityInstance)"
                }
            }

            if ($IdentityFilter -and ($IdentityFilter.Trim() -ne '') ) {
                $Filter += "(|$IdentityFilter)"
            }

            if ($PSBoundParameters['SPN']) {
                Write-Verbose '[Get-DomainUser] Searching for non-null service principal names'
                $Filter += '(servicePrincipalName=*)'
            }
            if ($PSBoundParameters['AllowDelegation']) {
                Write-Verbose '[Get-DomainUser] Searching for users who can be delegated'
                # negation of "Accounts that are sensitive and not trusted for delegation"
                $Filter += '(!(userAccountControl:1.2.840.113556.1.4.803:=1048574))'
            }
            if ($PSBoundParameters['DisallowDelegation']) {
                Write-Verbose '[Get-DomainUser] Searching for users who are sensitive and not trusted for delegation'
                $Filter += '(userAccountControl:1.2.840.113556.1.4.803:=1048574)'
            }
            if ($PSBoundParameters['AdminCount']) {
                Write-Verbose '[Get-DomainUser] Searching for adminCount=1'
                $Filter += '(admincount=1)'
            }
            if ($PSBoundParameters['TrustedToAuth']) {
                Write-Verbose '[Get-DomainUser] Searching for users that are trusted to authenticate for other principals'
                $Filter += '(msds-allowedtodelegateto=*)'
            }
            if ($PSBoundParameters['PreauthNotRequired']) {
                Write-Verbose '[Get-DomainUser] Searching for user accounts that do not require kerberos preauthenticate'
                $Filter += '(userAccountControl:1.2.840.113556.1.4.803:=4194304)'
            }
            if ($PSBoundParameters['LDAPFilter']) {
                Write-Verbose "[Get-DomainUser] Using additional LDAP filter: $LDAPFilter"
                $Filter += "$LDAPFilter"
            }

            # build the LDAP filter for the dynamic UAC filter value
            $UACFilter | Where-Object {$_} | ForEach-Object {
                if ($_ -match 'NOT_.*') {
                    $UACField = $_.Substring(4)
                    $UACValue = [Int]($UACEnum::$UACField)
                    $Filter += "(!(userAccountControl:1.2.840.113556.1.4.803:=$UACValue))"
                }
                else {
                    $UACValue = [Int]($UACEnum::$_)
                    $Filter += "(userAccountControl:1.2.840.113556.1.4.803:=$UACValue)"
                }
            }

            $UserSearcher.filter = "(&(samAccountType=805306368)$Filter)"
            Write-Verbose "[Get-DomainUser] filter string: $($UserSearcher.filter)"

            if ($PSBoundParameters['FindOne']) { $Results = $UserSearcher.FindOne() }
            else { $Results = $UserSearcher.FindAll() }
            $Results | Where-Object {$_} | ForEach-Object {
                if ($PSBoundParameters['Raw']) {
                    # return raw result objects
                    $User = $_
                    $User.PSObject.TypeNames.Insert(0, 'PowerView.User.Raw')
                }
                else {
                    $User = Convert-LDAPProperty -Properties $_.Properties
                    $User.PSObject.TypeNames.Insert(0, 'PowerView.User')
                }
                $User
            }
            if ($Results) {
                try { $Results.dispose() }
                catch {
                    Write-Verbose "[Get-DomainUser] Error disposing of the Results object: $_"
                }
            }
            $UserSearcher.dispose()
        }
    }
}

Function Get-UsersWithSPN {

	$UserSearcherArguments = @{
		'SPN' = $True
		'Properties' = 'samaccountname,distinguishedname,serviceprincipalname'
	}
	
	Get-DomainUser @UserSearcherArguments | Where-Object {$_.samaccountname -ne 'krbtgt'}
}