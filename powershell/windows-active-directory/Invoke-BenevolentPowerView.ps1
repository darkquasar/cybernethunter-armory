<#
    CYBRHUNTER SECURITY OPERATIONS :)
    Author: Diego Perez (@darkquassar)
    Version: 1.0.0
    Module: Invoke-BenevolentPowerView.ps1
    Description: This module contains adapted functions that are not malicious from PowerView, allowed by the AV and used for generic domain queries. Extracted from --> https://raw.githubusercontent.com/PowerShellEmpire/PowerTools/2fe3519000cba494d164cbdd6bcb8253ef467856/powerview.ps1. Requires Powershell Version 2.0
#>

<#
    Implementation of Sharefinder that utilizes
        https://github.com/mattifestation/psreflect to
        stay off of disk.

    By @harmj0y
#>

function New-InMemoryModule
{
    <#
        .SYNOPSIS

        Creates an in-memory assembly and module

        Author: Matthew Graeber (@mattifestation)
        License: BSD 3-Clause
        Required Dependencies: None
        Optional Dependencies: None
 
        .DESCRIPTION

        When defining custom enums, structs, and unmanaged functions, it is
        necessary to associate to an assembly module. This helper function
        creates an in-memory module that can be passed to the 'enum',
        'struct', and Add-Win32Type functions.

        .PARAMETER ModuleName

        Specifies the desired name for the in-memory assembly and module. If
        ModuleName is not provided, it will default to a GUID.

        .EXAMPLE

        $Module = New-InMemoryModule -ModuleName Win32
    #>

    [OutputType([Reflection.Emit.ModuleBuilder])]
    Param
    (
        [Parameter(Position = 0)]
        [ValidateNotNullOrEmpty()]
        [String]
        $ModuleName = [Guid]::NewGuid().ToString()
    )

    $DynAssembly = New-Object Reflection.AssemblyName($ModuleName)
    $Domain = [AppDomain]::CurrentDomain
    $AssemblyBuilder = $Domain.DefineDynamicAssembly($DynAssembly, 'Run')
    $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule($ModuleName, $False)

    return $ModuleBuilder
}


# A helper function used to reduce typing while defining function
# prototypes for Add-Win32Type.
# Author: Matthew Graeber (@mattifestation)
function func
{
    Param
    (
        [Parameter(Position = 0, Mandatory = $True)]
        [String]
        $DllName,

        [Parameter(Position = 1, Mandatory = $True)]
        [string]
        $FunctionName,

        [Parameter(Position = 2, Mandatory = $True)]
        [Type]
        $ReturnType,

        [Parameter(Position = 3)]
        [Type[]]
        $ParameterTypes,

        [Parameter(Position = 4)]
        [Runtime.InteropServices.CallingConvention]
        $NativeCallingConvention,

        [Parameter(Position = 5)]
        [Runtime.InteropServices.CharSet]
        $Charset,

        [Switch]
        $SetLastError
    )

    $Properties = @{
        DllName = $DllName
        FunctionName = $FunctionName
        ReturnType = $ReturnType
    }

    if ($ParameterTypes) { $Properties['ParameterTypes'] = $ParameterTypes }
    if ($NativeCallingConvention) { $Properties['NativeCallingConvention'] = $NativeCallingConvention }
    if ($Charset) { $Properties['Charset'] = $Charset }
    if ($SetLastError) { $Properties['SetLastError'] = $SetLastError }

    New-Object PSObject -Property $Properties
}


function Add-Win32Type
{
    <#
        .SYNOPSIS

        Creates a .NET type for an unmanaged Win32 function.

        Author: Matthew Graeber (@mattifestation)
        License: BSD 3-Clause
        Required Dependencies: None
        Optional Dependencies: func
 
        .DESCRIPTION

        Add-Win32Type enables you to easily interact with unmanaged (i.e.
        Win32 unmanaged) functions in PowerShell. After providing
        Add-Win32Type with a function signature, a .NET type is created
        using reflection (i.e. csc.exe is never called like with Add-Type).

        The 'func' helper function can be used to reduce typing when defining
        multiple function definitions.

        .PARAMETER DllName

        The name of the DLL.

        .PARAMETER FunctionName

        The name of the target function.

        .PARAMETER ReturnType

        The return type of the function.

        .PARAMETER ParameterTypes

        The function parameters.

        .PARAMETER NativeCallingConvention

        Specifies the native calling convention of the function. Defaults to
        stdcall.

        .PARAMETER Charset

        If you need to explicitly call an 'A' or 'W' Win32 function, you can
        specify the character set.

        .PARAMETER SetLastError

        Indicates whether the callee calls the SetLastError Win32 API
        function before returning from the attributed method.

        .PARAMETER Module

        The in-memory module that will host the functions. Use
        New-InMemoryModule to define an in-memory module.

        .PARAMETER Namespace

        An optional namespace to prepend to the type. Add-Win32Type defaults
        to a namespace consisting only of the name of the DLL.

        .EXAMPLE

        $Mod = New-InMemoryModule -ModuleName Win32

        $FunctionDefinitions = @(
        (func kernel32 GetProcAddress ([IntPtr]) @([IntPtr], [String]) -Charset Ansi -SetLastError),
        (func kernel32 GetModuleHandle ([Intptr]) @([String]) -SetLastError),
        (func ntdll RtlGetCurrentPeb ([IntPtr]) @())
        )

        $Types = $FunctionDefinitions | Add-Win32Type -Module $Mod -Namespace 'Win32'
        $Kernel32 = $Types['kernel32']
        $Ntdll = $Types['ntdll']
        $Ntdll::RtlGetCurrentPeb()
        $ntdllbase = $Kernel32::GetModuleHandle('ntdll')
        $Kernel32::GetProcAddress($ntdllbase, 'RtlGetCurrentPeb')

        .NOTES

        Inspired by Lee Holmes' Invoke-WindowsApi http://poshcode.org/2189

        When defining multiple function prototypes, it is ideal to provide
        Add-Win32Type with an array of function signatures. That way, they
        are all incorporated into the same in-memory module.
    #>

    [OutputType([Hashtable])]
    Param(
        [Parameter(Mandatory = $True, ValueFromPipelineByPropertyName = $True)]
        [String]
        $DllName,

        [Parameter(Mandatory = $True, ValueFromPipelineByPropertyName = $True)]
        [String]
        $FunctionName,

        [Parameter(Mandatory = $True, ValueFromPipelineByPropertyName = $True)]
        [Type]
        $ReturnType,

        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [Type[]]
        $ParameterTypes,

        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [Runtime.InteropServices.CallingConvention]
        $NativeCallingConvention = [Runtime.InteropServices.CallingConvention]::StdCall,

        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [Runtime.InteropServices.CharSet]
        $Charset = [Runtime.InteropServices.CharSet]::Auto,

        [Parameter(ValueFromPipelineByPropertyName = $True)]
        [Switch]
        $SetLastError,

        [Parameter(Mandatory = $True)]
        [Reflection.Emit.ModuleBuilder]
        $Module,

        [ValidateNotNull()]
        [String]
        $Namespace = ''
    )

    BEGIN
    {
        $TypeHash = @{}
    }

    PROCESS
    {
        # Define one type for each DLL
        if (!$TypeHash.ContainsKey($DllName))
        {
            if ($Namespace)
            {
                $TypeHash[$DllName] = $Module.DefineType("$Namespace.$DllName", 'Public,BeforeFieldInit')
            }
            else
            {
                $TypeHash[$DllName] = $Module.DefineType($DllName, 'Public,BeforeFieldInit')
            }
        }

        $Method = $TypeHash[$DllName].DefineMethod(
            $FunctionName,
            'Public,Static,PinvokeImpl',
            $ReturnType,
            $ParameterTypes)

        # Make each ByRef parameter an Out parameter
        $i = 1
        foreach($Parameter in $ParameterTypes)
        {
            if ($Parameter.IsByRef)
            {
                [void] $Method.DefineParameter($i, 'Out', $null)
            }

            $i++
        }

        $DllImport = [Runtime.InteropServices.DllImportAttribute]
        $SetLastErrorField = $DllImport.GetField('SetLastError')
        $CallingConventionField = $DllImport.GetField('CallingConvention')
        $CharsetField = $DllImport.GetField('CharSet')
        if ($SetLastError) { $SLEValue = $True } else { $SLEValue = $False }

        # Equivalent to C# version of [DllImport(DllName)]
        $Constructor = [Runtime.InteropServices.DllImportAttribute].GetConstructor([String])
        $DllImportAttribute = New-Object Reflection.Emit.CustomAttributeBuilder($Constructor,
            $DllName, [Reflection.PropertyInfo[]] @(), [Object[]] @(),
            [Reflection.FieldInfo[]] @($SetLastErrorField, $CallingConventionField, $CharsetField),
            [Object[]] @($SLEValue, ([Runtime.InteropServices.CallingConvention] $NativeCallingConvention), ([Runtime.InteropServices.CharSet] $Charset)))

        $Method.SetCustomAttribute($DllImportAttribute)
    }

    END
    {
        $ReturnTypes = @{}

        foreach ($Key in $TypeHash.Keys)
        {
            $Type = $TypeHash[$Key].CreateType()
            
            $ReturnTypes[$Key] = $Type
        }

        return $ReturnTypes
    }
}


# A helper function used to reduce typing while defining struct
# fields.
# Author: Matthew Graeber (@mattifestation)
function field
{
    Param
    (
        [Parameter(Position = 0, Mandatory = $True)]
        [UInt16]
        $Position,
        
        [Parameter(Position = 1, Mandatory = $True)]
        [Type]
        $Type,
        
        [Parameter(Position = 2)]
        [UInt16]
        $Offset,
        
        [Object[]]
        $MarshalAs
    )

    @{
        Position = $Position
        Type = $Type -as [Type]
        Offset = $Offset
        MarshalAs = $MarshalAs
    }
}

# Author: Matthew Graeber (@mattifestation)
function struct
{
    <#
        .SYNOPSIS

        Creates an in-memory struct for use in your PowerShell session.

        Author: Matthew Graeber (@mattifestation)
        License: BSD 3-Clause
        Required Dependencies: None
        Optional Dependencies: field
 
        .DESCRIPTION

        The 'struct' function facilitates the creation of structs entirely in
        memory using as close to a "C style" as PowerShell will allow. Struct
        fields are specified using a hashtable where each field of the struct
        is comprosed of the order in which it should be defined, its .NET
        type, and optionally, its offset and special marshaling attributes.

        One of the features of 'struct' is that after your struct is defined,
        it will come with a built-in GetSize method as well as an explicit
        converter so that you can easily cast an IntPtr to the struct without
        relying upon calling SizeOf and/or PtrToStructure in the Marshal
        class.

        .PARAMETER Module

        The in-memory module that will host the struct. Use
        New-InMemoryModule to define an in-memory module.

        .PARAMETER FullName

        The fully-qualified name of the struct.

        .PARAMETER StructFields

        A hashtable of fields. Use the 'field' helper function to ease
        defining each field.

        .PARAMETER PackingSize

        Specifies the memory alignment of fields.

        .PARAMETER ExplicitLayout

        Indicates that an explicit offset for each field will be specified.

        .EXAMPLE

        $Mod = New-InMemoryModule -ModuleName Win32

        $ImageDosSignature = enum $Mod PE.IMAGE_DOS_SIGNATURE UInt16 @{
        DOS_SIGNATURE =    0x5A4D
        OS2_SIGNATURE =    0x454E
        OS2_SIGNATURE_LE = 0x454C
        VXD_SIGNATURE =    0x454C
        }

        $ImageDosHeader = struct $Mod PE.IMAGE_DOS_HEADER @{
        e_magic =    field 0 $ImageDosSignature
        e_cblp =     field 1 UInt16
        e_cp =       field 2 UInt16
        e_crlc =     field 3 UInt16
        e_cparhdr =  field 4 UInt16
        e_minalloc = field 5 UInt16
        e_maxalloc = field 6 UInt16
        e_ss =       field 7 UInt16
        e_sp =       field 8 UInt16
        e_csum =     field 9 UInt16
        e_ip =       field 10 UInt16
        e_cs =       field 11 UInt16
        e_lfarlc =   field 12 UInt16
        e_ovno =     field 13 UInt16
        e_res =      field 14 UInt16[] -MarshalAs @('ByValArray', 4)
        e_oemid =    field 15 UInt16
        e_oeminfo =  field 16 UInt16
        e_res2 =     field 17 UInt16[] -MarshalAs @('ByValArray', 10)
        e_lfanew =   field 18 Int32
        }

        # Example of using an explicit layout in order to create a union.
        $TestUnion = struct $Mod TestUnion @{
        field1 = field 0 UInt32 0
        field2 = field 1 IntPtr 0
        } -ExplicitLayout

        .NOTES

        PowerShell purists may disagree with the naming of this function but
        again, this was developed in such a way so as to emulate a "C style"
        definition as closely as possible. Sorry, I'm not going to name it
        New-Struct. :P
    #>

    [OutputType([Type])]
    Param
    (
        [Parameter(Position = 1, Mandatory = $True)]
        [Reflection.Emit.ModuleBuilder]
        $Module,

        [Parameter(Position = 2, Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [String]
        $FullName,

        [Parameter(Position = 3, Mandatory = $True)]
        [ValidateNotNullOrEmpty()]
        [Hashtable]
        $StructFields,

        [Reflection.Emit.PackingSize]
        $PackingSize = [Reflection.Emit.PackingSize]::Unspecified,

        [Switch]
        $ExplicitLayout
    )

    [Reflection.TypeAttributes] $StructAttributes = 'AnsiClass,
        Class,
        Public,
        Sealed,
        BeforeFieldInit'

    if ($ExplicitLayout)
    {
        $StructAttributes = $StructAttributes -bor [Reflection.TypeAttributes]::ExplicitLayout
    }
    else
    {
        $StructAttributes = $StructAttributes -bor [Reflection.TypeAttributes]::SequentialLayout
    }

    $StructBuilder = $Module.DefineType($FullName, $StructAttributes, [ValueType], $PackingSize)
    $ConstructorInfo = [Runtime.InteropServices.MarshalAsAttribute].GetConstructors()[0]
    $SizeConst = @([Runtime.InteropServices.MarshalAsAttribute].GetField('SizeConst'))

    $Fields = New-Object Hashtable[]($StructFields.Count)

    # Sort each field according to the orders specified
    # Unfortunately, PSv2 doesn't have the luxury of the
    # hashtable [Ordered] accelerator.
    foreach ($Field in $StructFields.Keys)
    {
        $Index = $StructFields[$Field]['Position']
        $Fields[$Index] = @{FieldName = $Field; Properties = $StructFields[$Field]}
    }

    foreach ($Field in $Fields)
    {
        $FieldName = $Field['FieldName']
        $FieldProp = $Field['Properties']

        $Offset = $FieldProp['Offset']
        $Type = $FieldProp['Type']
        $MarshalAs = $FieldProp['MarshalAs']

        $NewField = $StructBuilder.DefineField($FieldName, $Type, 'Public')

        if ($MarshalAs)
        {
            $UnmanagedType = $MarshalAs[0] -as ([Runtime.InteropServices.UnmanagedType])
            if ($MarshalAs[1])
            {
                $Size = $MarshalAs[1]
                $AttribBuilder = New-Object Reflection.Emit.CustomAttributeBuilder($ConstructorInfo,
                    $UnmanagedType, $SizeConst, @($Size))
            }
            else
            {
                $AttribBuilder = New-Object Reflection.Emit.CustomAttributeBuilder($ConstructorInfo, [Object[]] @($UnmanagedType))
            }
            
            $NewField.SetCustomAttribute($AttribBuilder)
        }

        if ($ExplicitLayout) { $NewField.SetOffset($Offset) }
    }

    # Make the struct aware of its own size.
    # No more having to call [Runtime.InteropServices.Marshal]::SizeOf!
    $SizeMethod = $StructBuilder.DefineMethod('GetSize',
        'Public, Static',
        [Int],
        [Type[]] @())
    $ILGenerator = $SizeMethod.GetILGenerator()
    # Thanks for the help, Jason Shirk!
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Ldtoken, $StructBuilder)
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Call,
        [Type].GetMethod('GetTypeFromHandle'))
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Call,
        [Runtime.InteropServices.Marshal].GetMethod('SizeOf', [Type[]] @([Type])))
    $ILGenerator.Emit([Reflection.Emit.OpCodes]::Ret)

    # Allow for explicit casting from an IntPtr
    # No more having to call [Runtime.InteropServices.Marshal]::PtrToStructure!
    $ImplicitConverter = $StructBuilder.DefineMethod('op_Implicit',
        'PrivateScope, Public, Static, HideBySig, SpecialName',
        $StructBuilder,
        [Type[]] @([IntPtr]))
    $ILGenerator2 = $ImplicitConverter.GetILGenerator()
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Nop)
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Ldarg_0)
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Ldtoken, $StructBuilder)
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Call,
        [Type].GetMethod('GetTypeFromHandle'))
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Call,
        [Runtime.InteropServices.Marshal].GetMethod('PtrToStructure', [Type[]] @([IntPtr], [Type])))
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Unbox_Any, $StructBuilder)
    $ILGenerator2.Emit([Reflection.Emit.OpCodes]::Ret)

    $StructBuilder.CreateType()
}


function Test-Server {
    <#
        .SYNOPSIS
        Tests a connection to a remote server.
        
        .DESCRIPTION
        This function uses either ping (test-connection) or RPC
        (through WMI) to test connectivity to a remote server.

        .PARAMETER Server
        The hostname/IP to test connectivity to.

        .OUTPUTS
        $True/$False
        
        .EXAMPLE
        > Test-Server -Server WINDOWS7
        Tests ping connectivity to the WINDOWS7 server.

        .EXAMPLE
        > Test-Server -RPC -Server WINDOWS7
        Tests RPC connectivity to the WINDOWS7 server.

        .LINK
        http://gallery.technet.microsoft.com/scriptcenter/Enhanced-Remote-Server-84c63560
    #>
    
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $True)] 
        [String] 
        $Server,
        
        [Switch]
        $RPC
    )
    
    if ($RPC){
        $WMIParameters = @{
                        namespace = 'root\cimv2'
                        Class = 'win32_ComputerSystem'
                        ComputerName = $Name
                        ErrorAction = 'Stop'
                      }
        if ($Credential -ne $null)
        {
            $WMIParameters.Credential = $Credential
        }
        try
        {
            Get-WmiObject @WMIParameters
        }
        catch { 
            Write-Verbose -Message 'Could not connect via WMI'
        } 
    }
    # otherwise, use ping
    else{
        Test-Connection -ComputerName $Server -count 1 -Quiet
    }
}


function Get-ShuffledArray {
    <#
        .SYNOPSIS
        Returns a randomly-shuffled version of a passed array.
        
        .DESCRIPTION
        This function takes an array and returns a randomly-shuffled
        version.
        
        .PARAMETER Array
        The passed array to shuffle.

        .OUTPUTS
        System.Array. The passed array but shuffled.
        
        .EXAMPLE
        > $shuffled = Get-ShuffledArray $array
        Get a shuffled version of $array.

        .LINK
        http://sqlchow.wordpress.com/2013/03/04/shuffle-the-deck-using-powershell/
    #>
    [CmdletBinding()]
    param( 
        [Array]$Array 
    )
    Begin{}
    Process{
        $len = $Array.Length
        while($len){
            $i = Get-Random ($len --)
            $tmp = $Array[$len]
            $Array[$len] = $Array[$i]
            $Array[$i] = $tmp
        }
        $Array;
    }
}

function Invoke-CheckWrite {
    <#
    .SYNOPSIS
    Check if the current user has write access to a given file.
    
    .DESCRIPTION
    This function tries to open a given file for writing and then
    immediately closes it, returning true if the file successfully
    opened, and false if it failed.
    
    .PARAMETER Path
    Path of the file to check for write access

    .OUTPUTS
    System.bool. True if the add succeeded, false otherwise.
    
    .EXAMPLE
    > Invoke-CheckWrite "test.txt"
    Check if the current user has write access to "test.txt"
    #>

    param(
        [Parameter(Mandatory = $True)] [String] $Path
    )

    try { 
         $filetest = [IO.FILE]::OpenWrite($Path)
         $filetest.close()
         $true
       }
    catch { 
        Write-Verbose $Error[0]
        $false
    }
}


function Get-NetCurrentUser {
    <#
        .SYNOPSIS
        Gets the name of the current user.
        
        .DESCRIPTION
        This function returns the username of the current user context,
        with the domain appended if appropriate.
        
        .OUTPUTS
        System.String. The current username.
        
        .EXAMPLE
        > Get-NetCurrentUser
        Return the current user.
    #>
    
    [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
}


function Get-NetDomain {
    <#
        .SYNOPSIS
        Returns the name of the current user's domain.
        
        .DESCRIPTION
        This function utilizes ADSI (Active Directory Service Interface) to
        get the currect domain root and return its distinguished name.
        It then formats the name into a single string.
        
        .PARAMETER Base
        Just return the base of the current domain (i.e. no .com)

        .OUTPUTS
        System.String. The full domain name.
        
        .EXAMPLE
        > Get-NetDomain
        Return the current domain.

        .EXAMPLE
        > Get-NetDomain -base
        Return just the base of the current domain.

        .LINK
        http://social.technet.microsoft.com/Forums/scriptcenter/en-US/0c5b3f83-e528-4d49-92a4-dee31f4b481c/finding-the-dn-of-the-the-domain-without-admodule-in-powershell?forum=ITCG
    #>
    
    [CmdletBinding()]
    param(
        [Switch]
        $Base
    )
    
    # just get the base of the domain name
    if ($Base){
        $temp = [string] ([adsi]'').distinguishedname -replace 'DC=','' -replace ',','.'
        $parts = $temp.split('.')
        $parts[0..($parts.length-2)] -join '.'
    }
    else{
        ([adsi]'').distinguishedname -replace 'DC=','' -replace ',','.'
    }
}

function Get-NetDomainTrusts {
    <#
    .SYNOPSIS
    Return all current domain trusts.
    
    .DESCRIPTION
    This function returns all current trusts associated
    with the current domain.
    
    .EXAMPLE
    > Get-NetDomainTrusts
    Return current domain trusts.
    #>

    $domain = [System.DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain()
    $domain.GetAllTrustRelationships()
}

function Get-NetForest {
    <#
    .SYNOPSIS
    Return the current forest associated with this domain.
    
    .DESCRIPTION
    This function returns the current forest associated 
    with the domain the current user is authenticated to.
    
    .EXAMPLE
    > Get-NetForest
    Return current forest.
    #>

    [System.DirectoryServices.ActiveDirectory.Forest]::GetCurrentForest()
}


function Get-NetForestDomains {
    <#
    .SYNOPSIS
    Return all domains for the current forest.

    .DESCRIPTION
    This function returns all domains for the current forest
    the current domain is a part of.

    .PARAMETER Domain
    Return doamins that match this term/wildcard.

    .EXAMPLE
    > Get-NetForestDomains 
    Return domains apart of the current forest.
    #>

    [CmdletBinding()]
    param(
        [string]$Domain
    )

    if($Domain){
        # try to detect a wild card so we use -like
        if($Domain.Contains("*")){
            (Get-NetForest).Domains | ? {$_.Name -like $Domain}
        }
        else {
            # match the exact domain name if there's not a wildcard
            (Get-NetForest).Domains | ? {$_.Name.ToLower() -eq $Domain.ToLower()}
        }
    }
    else{
        # return all domains
        (Get-NetForest).Domains
    }
}


function Get-NetForestTrusts {
    <#
    .SYNOPSIS
    Return all trusts for the current forest.
    
    .DESCRIPTION
    This function returns all current trusts associated
    the forest the current domain is a part of.
    
    .EXAMPLE
    > Get-NetForestTrusts
    Return current forest trusts
    #>

    (Get-NetForest).GetAllTrustRelationships()
}


function Get-NetDomainControllers 
{
    <#
    .SYNOPSIS
    Return the current domain controllers for the active domain.
    
    .DESCRIPTION
    Uses DirectoryServices.ActiveDirectory to return the current domain 
    controllers.

    .PARAMETER Domain
    The domain whose domain controller to enumerate.
    If not given, gets the current computer's domain controller.

    .OUTPUTS
    System.Array. An array of found domain controllers.

    .EXAMPLE
    > Get-NetDomainControllers
    Returns the domain controller for the current computer's domain.  
    Approximately equivialent to the hostname given in the LOGONSERVER 
    environment variable.

    .EXAMPLE
    > Get-NetDomainControllers -Domain test
    Returns the domain controller for the current computer's domain.  
    Approximately equivialent to the hostname given in the LOGONSERVER 
    environment variable.
    #>

    [CmdletBinding()]
    param(
        [string]$Domain
    )

    # if a domain is specified, try to grab that domain using Get-NetForestDomains
    if ($Domain){
        try {
            (Get-NetForestDomains -Domain $Domain).DomainControllers
        }
        catch{}
    }
    else{
        # otherwise, grab the current domain
        [DirectoryServices.ActiveDirectory.Domain]::GetCurrentDomain().DomainControllers
    }
}


function Get-NetCurrentUser {
    <#
    .SYNOPSIS
    Gets the name of the current user.
    
    .DESCRIPTION
    This function returns the username of the current user context,
    with the domain appended if appropriate.
    
    .OUTPUTS
    System.String. The current username.
    
    .EXAMPLE
    > Get-NetCurrentUser
    Return the current user.
    #>

    [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
}


function Get-NetUsers {
    <#
    .SYNOPSIS
    Gets a list of all current users in a domain.
    
    .DESCRIPTION
    This function will user DirectoryServices.AccountManagement query the
    current domain for all users, or use System.DirectoryServices.DirectorySearcher
    to query for users in another domain trust.

    This is a replacement for "net users /domain"

    .PARAMETER Domain
    The domain to query for users. If not supplied, the 
    current domain is used.

    .OUTPUTS
    Collection objects with the properties of each user found.

    .EXAMPLE
    > Get-NetUsers
    Returns the member users of the current domain.

    .EXAMPLE
    > Get-NetUsers -Domain testing
    Returns all the members in the "testing" domain.
    #>

    [CmdletBinding()]
    param(
        [string]$Domain
    )

    # if a domain is specified, try to grab that domain using Get-NetForestDomains
    if ($Domain){
        try {
            # reference - http://blogs.msdn.com/b/javaller/archive/2013/07/29/searching-across-active-directory-domains-in-powershell.aspx
            $dn = "DC=$($Domain.Replace('.', ',DC='))"
            $userSearcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]"LDAP://$dn") 
            # samAccountType=805306368 indicates user objects 
            $userSearcher.filter="(&(samAccountType=805306368))"
            $userSearcher.FindAll() |foreach {$_.properties}
        }
        catch{
            Write-Warning "Error connecting to domain $Domain, is there a trust?"
        }
    }
    else{
        # otherwise, use the current domain
        $userSearcher = [adsisearcher]"(&(samAccountType=805306368))"
        $userSearcher.FindAll() |foreach {$_.properties}
    }
}


function Get-NetUser {
    <#
    .SYNOPSIS
    Returns data for a specified domain user.
    
    .DESCRIPTION
    This function utilizes DirectoryServices.AccountManagement to query
    the current AD context for users in a specified group, and then
    queries information for each user in that group. If no GroupName is 
    specified, it defaults to querying the "Domain Admins" group. 

    .PARAMETER UserName
    The domain username to query for. If not given, it defaults to "administrator"

    .PARAMETER Domain
    The domain to query for for the user.

    .OUTPUTS
    Collection object with the properties of the user found, or $null if the
    user isn't found.

    .EXAMPLE
    > Get-NetUser
    Returns data about the "administrator" user for the current domain.

    .EXAMPLE
    > Get-NetUser -UserName "jsmith"
    Returns data about user "jsmith" in the current domain.  

    .EXAMPLE
    > Get-NetUser -UserName "jsmith" -Domain testing
    Returns data about user "jsmith" in the 'testing' domain.  
    #>

    [CmdletBinding()]
    param(
        [string]$UserName = "administrator",
        [string]$Domain
    )

    # if a domain is specified, try to grab that domain using Get-NetForestDomains
    if ($Domain){
        try {
            # reference - http://blogs.msdn.com/b/javaller/archive/2013/07/29/searching-across-active-directory-domains-in-powershell.aspx
            $dn = "DC=$($Domain.Replace('.', ',DC='))"
            $userSearcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]"LDAP://$dn") 
            $userSearcher.filter="(&(samaccountname=$UserName))"
            
            $user = $userSearcher.FindOne()
            if ($user){
                $user.properties
            }
            else{
                Write-Warning "Username $UserName not found in domain $Domain"
                $null
            }
        }
        catch{
            Write-Warning "Error connecting to domain $Domain, is there a trust?"
        }
    }
    else{
        # otherwise, use the current domain
        $userSearcher = [adsisearcher]"(&(samaccountname=$UserName))"
        $user = $userSearcher.FindOne()
        if ($user){
            $user.properties
        }
        else{
            Write-Warning "Username $UserName not found in the current domain."
            $null
        }
    }
}


function Invoke-NetUserAdd {
    <#
    .SYNOPSIS
    Adds a local or domain user.
    
    .DESCRIPTION
    This function utilizes DirectoryServices.AccountManagement to add a
    user to the local machine or a domain (if permissions allow). It will
    default to adding to the local machine. An optional group name to
    add the user to can be specified.

    .PARAMETER UserName
    The username to add. If not given, it defaults to "backdoor"

    .PARAMETER Password
    The password to set for the added user. If not given, it defaults to "Password123!"

    .PARAMETER GroupName
    Group to optionally add the user to.

    .PARAMETER HostName
    Host to add the local user to, defaults to 'localhost'

    .PARAMETER Domain
    Specified domain to add the user to.
        
    .OUTPUTS
    System.bool. True if the add succeeded, false otherwise.

    .EXAMPLE
    > Invoke-NetUserAdd -UserName john -Password password
    Adds a localuser "john" to the machine with password "password"

    .EXAMPLE
    > Invoke-NetUserAdd -UserName john -Password password -GroupName "Domain Admins" -domain ''
    Adds the user "john" with password "password" to the current domain and adds
    the user to the domain group "Domain Admins" 

    .EXAMPLE
    > Invoke-NetUserAdd -UserName john -Password password -GroupName "Domain Admins" -domain 'testing'
    Adds the user "john" with password "password" to the 'testing' domain and adds
    the user to the domain group "Domain Admins" 

    .Link
    http://blogs.technet.com/b/heyscriptingguy/archive/2010/11/23/use-powershell-to-create-local-user-accounts.aspx
    #>

    [CmdletBinding()]
    Param (
        [string]$UserName = "backdoor",
        [string]$Password = "Password123!",
        [string]$GroupName = "",
        [string]$HostName = "localhost",
        [string]$Domain
    )

    if ($Domain){

        # add the assembly we need
        Add-Type -AssemblyName System.DirectoryServices.AccountManagement

        # http://richardspowershellblog.wordpress.com/2008/05/25/system-directoryservices-accountmanagement/

        $ct = [System.DirectoryServices.AccountManagement.ContextType]::Domain

        try{
            # try to create the context for the target domain
            $DomainContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext("Domain", $Domain)
            $d = [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($DomainContext)
        }
        catch{
            Write-Warning "Error connecting to domain $Domain, is there a trust?"
            return $null
        }

        # get the domain context
        $context = New-Object -TypeName System.DirectoryServices.AccountManagement.PrincipalContext -ArgumentList $ct, $d

        # create the user object
        $usr = New-Object -TypeName System.DirectoryServices.AccountManagement.UserPrincipal -ArgumentList $context

        # set user properties
        $usr.name = $UserName
        $usr.SamAccountName = $UserName
        $usr.PasswordNotRequired = $false
        $usr.SetPassword($password)
        $usr.Enabled = $true

        try{
            # commit the user
            $usr.Save()
            Write-Host "User $UserName successfully created in domain $Domain"
        }
        catch {
            Write-Warning "[!] User already exists!"
            return
        }
    }
    else{
        $objOu = [ADSI]"WinNT://$HostName"
        $objUser = $objOU.Create("User", $UserName)
        $objUser.SetPassword($Password)
        # $objUser.Properties | Select-Object # full object properties

        # commit the changes to the local machine
        try{ 
            $b = $objUser.SetInfo()
            Write-Host "User $UserName successfully created on host $HostName"
        }
        catch{
            # TODO: error handling if permissions incorrect
            Write-Warning "[!] Account already exists!"
            return
        }
    }

    # if a group is specified, invoke Invoke-NetGroupUserAdd and return its value
    if ($GroupName -ne ""){
        # if we're adding the user to a domain
        if ($Domain){
            Invoke-NetGroupUserAdd -UserName $UserName -GroupName $GroupName -Domain $Domain
            Write-Host "User $UserName successfully added to group $GroupName in domain $Domain"
        }
        # otherwise, we're adding to a local group
        else{
            Invoke-NetGroupUserAdd -UserName $UserName -GroupName $GroupName -HostName $HostName
            Write-Host "User $UserName successfully added to group $GroupName on host $HostName"
        }
    }

}

function Get-NetComputers {
    <#
        .SYNOPSIS
        Gets an array of all current computers objects in a domain.
        
        .DESCRIPTION
        This function utilizes adsisearcher to query the current AD context 
        for current computer objects. Based off of Carlos Perez's Audit.psm1 
        script in Posh-SecMod (link below).
        
        .PARAMETER HostName
        Return computers with a specific name, wildcards accepted.

        .PARAMETER SPN
        Return computers with a specific service principal name, wildcards accepted.

        .PARAMETER OperatingSystem
        Return computers with a specific operating system, wildcards accepted.

        .PARAMETER ServicePack
        Return computers with a specific service pack, wildcards accepted.

        .PARAMETER FullData
        Return full user computer objects instead of just system names (the default).

        .PARAMETER Domain
        The domain to query for computers.

        .OUTPUTS
        System.Array. An array of found system objects.

        .EXAMPLE
        > Get-NetComputers
        Returns the current computers in current domain.

        .EXAMPLE
        > Get-NetComputers -SPN mssql*
        Returns all MS SQL servers on the domain.

        .EXAMPLE
        > Get-NetComputers -Domain testing
        Returns the current computers in 'testing' domain.

        > Get-NetComputers -Domain testing -FullData
        Returns full computer objects in the 'testing' domain.

        .LINK
        https://github.com/darkoperator/Posh-SecMod/blob/master/Audit/Audit.psm1
    #>
    
    [CmdletBinding()]
    Param (
        [string]
        $HostName = '*',

        [string]
        $SPN = '*',

        [string]
        $OperatingSystem = '*',

        [string]
        $ServicePack = '*',

        [Switch]
        $FullData,

        [string]
        $Domain
    )

    # if a domain is specified, try to grab that domain
    if ($Domain){

        # try to grab the primary DC for the current domain
        try{
            $PrimaryDC = ([Array](Get-NetDomainControllers))[0].Name
        }
        catch{
            $PrimaryDC = $Null
        }

        try {
            # reference - http://blogs.msdn.com/b/javaller/archive/2013/07/29/searching-across-active-directory-domains-in-powershell.aspx
            $dn = "DC=$($Domain.Replace('.', ',DC='))"

            # if we could grab the primary DC for the current domain, use that for the query
            if($PrimaryDC){
                $CompSearcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]"LDAP://$PrimaryDC/$dn") 
            }
            else{
                # otherwise try to connect to the DC for the target domain
                $CompSearcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]"LDAP://$dn") 
            }

            # create the searcher object with our specific filters
            if ($ServicePack -ne '*'){
                $CompSearcher.filter="(&(objectClass=Computer)(dnshostname=$HostName)(operatingsystem=$OperatingSystem)(operatingsystemservicepack=$ServicePack)(servicePrincipalName=$SPN))"
            }
            else{
                # server 2012 peculiarity- remove any mention to service pack
                $CompSearcher.filter="(&(objectClass=Computer)(dnshostname=$HostName)(operatingsystem=$OperatingSystem)(servicePrincipalName=$SPN))"
            }
            
        }
        catch{
            Write-Warning "The specified domain $Domain does not exist, could not be contacted, or there isn't an existing trust."
        }
    }
    else{
        # otherwise, use the current domain
        if ($ServicePack -ne '*'){
            $CompSearcher = [adsisearcher]"(&(objectClass=Computer)(dnshostname=$HostName)(operatingsystem=$OperatingSystem)(operatingsystemservicepack=$ServicePack)(servicePrincipalName=$SPN))"
        }
        else{
            # server 2012 peculiarity- remove any mention to service pack
            $CompSearcher = [adsisearcher]"(&(objectClass=Computer)(dnshostname=$HostName)(operatingsystem=$OperatingSystem)(servicePrincipalName=$SPN))"
        }
    }
    
    if ($CompSearcher){
        
        # eliminate that pesky 1000 system limit
        $CompSearcher.PageSize = 200
        
        $CompSearcher.FindAll() | ForEach-Object {
            # return full data objects
            if ($FullData){
                $_.properties
            }
            else{
                # otherwise we're just returning the DNS host name
                $_.properties.dnshostname
            }
        }
    }
}


function Get-NetShare {
    <#
        .SYNOPSIS
        Gets share information for a specified server.
    
        .DESCRIPTION
        This function will execute the NetShareEnum Win32API call to query
        a given host for open shares. This is a replacement for
        "net share \\hostname"

        .PARAMETER HostName
        The hostname to query for shares.

        .OUTPUTS
        SHARE_INFO_1 structure. A representation of the SHARE_INFO_1
        result structure which includes the name and note for each share.

        .EXAMPLE
        > Get-NetShare
        Returns active shares on the local host.

        .EXAMPLE
        > Get-NetShare -HostName sqlserver
        Returns active shares on the 'sqlserver' host
    #>
    
    [CmdletBinding()]
    param(
        [string]
        $HostName = 'localhost'
    )
    
    If ($PSBoundParameters['Debug']) {
        $DebugPreference = 'Continue'
    }
    
    # arguments for NetShareEnum
    $QueryLevel = 1
    $ptrInfo = [IntPtr]::Zero
    $EntriesRead = 0
    $TotalRead = 0
    $ResumeHandle = 0

    # get the share information
    $Result = $Netapi32::NetShareEnum($HostName, $QueryLevel,[ref]$ptrInfo,-1,[ref]$EntriesRead,[ref]$TotalRead,[ref]$ResumeHandle)

    # Locate the offset of the initial intPtr
    $offset = $ptrInfo.ToInt64()
    
    Write-Debug "Get-NetShare result: $Result"
    
    # 0 = success
    if (($Result -eq 0) -and ($offset -gt 0)) {
        
        # Work out how mutch to increment the pointer by finding out the size of the structure
        $Increment = $SHARE_INFO_1::GetSize()
        
        # parse all the result structures
        for ($i = 0; ($i -lt $EntriesRead); $i++){
            # create a new int ptr at the given offset and cast 
            # the pointer as our result structure
            $newintptr = New-Object system.Intptr -ArgumentList $offset
            $Info = $newintptr -as $SHARE_INFO_1
            # return all the sections of the structure
            $Info | Select-Object *
            $offset = $newintptr.ToInt64()
            $offset += $increment
        }
        # free up the result buffer
        $Netapi32::NetApiBufferFree($ptrInfo) | Out-Null
    }
    else 
    {
        switch ($Result) {
            (5)           {Write-Debug 'The user does not have access to the requested information.'}
            (124)         {Write-Debug 'The value specified for the level parameter is not valid.'}
            (87)          {Write-Debug 'The specified parameter is not valid.'}
            (234)         {Write-Debug 'More entries are available. Specify a large enough buffer to receive all entries.'}
            (8)           {Write-Debug 'Insufficient memory is available.'}
            (2312)        {Write-Debug 'A session does not exist with the computer name.'}
            (2351)        {Write-Debug 'The computer name is not valid.'}
            (2221)        {Write-Debug 'Username not found.'}
            (53)          {Write-Debug 'Hostname could not be found'}
        }
    }
}

function Get-NetGroup {
    <#
    .SYNOPSIS
    Gets a list of all current users in a specified domain group.
    
    .DESCRIPTION
    This function utilizes DirectoryServices.AccountManagement to query
    the current AD context or trusted domain for users in a specified group.
    If no GroupName is specified, it defaults to querying the "Domain Admins"
    group. This is a replacement for "net group 'name' /domain"

    .PARAMETER GroupName
    The group name to query for users. If not given, it defaults to "domain admins"
    
    .PARAMETER Domain
    The domain to query for group users.
    
    .OUTPUTS
    System.Array. An array of found users for the specified group.

    .EXAMPLE
    > Get-NetGroup
    Returns the usernames that of members of the "Domain Admins" domain group.
    
    .EXAMPLE
    > Get-NetGroup -GroupName "Power Users"
    Returns the usernames that of members of the "Power Users" domain group.

    .EXAMPLE
    > Get-NetGroup -Domain testing
    Returns the usernames that of members of the "Domain Admins" group
    in the 'testing' domain.

    .LINK
    http://www.powershellmagazine.com/2013/05/23/pstip-retrieve-group-membership-of-an-active-directory-group-recursively/
    #>

    [CmdletBinding()]
    param(
        [string]$GroupName = "Domain Admins",
        [Parameter(Mandatory = $False)] [Switch] $FullData,
        [string]$Domain
    )

    # if a domain is specified, try to grab that domain using Get-NetForestDomains
    if ($Domain){
        try {
            # reference - http://blogs.msdn.com/b/javaller/archive/2013/07/29/searching-across-active-directory-domains-in-powershell.aspx
            $dn = "DC=$($Domain.Replace('.', ',DC='))"
            $groupSearcher = New-Object System.DirectoryServices.DirectorySearcher([ADSI]"LDAP://$dn") 
            # samAccountType=805306368 indicates user objects 
            $groupSearcher.filter = "(&(objectClass=group)(name=$GroupName))"
        }
        catch{
            Write-Warning "Error connecting to domain $Domain, is there a trust?"
        }
    }
    else{
        # otherwise, use the current domain
        $groupSearcher = [adsisearcher]"(&(objectClass=group)(name=$GroupName))"
    }

    if ($groupSearcher){
        # return full data objects
        if ($FullData.IsPresent) {
            $groupSearcher.FindOne().properties['member'] | ForEach-Object {
                # for each user/member, do a quick adsi object grab
                ([adsi]"LDAP://$_").Properties | ft PropertyName, Value
            }
        }
        else{
            $groupSearcher.FindOne().properties['member'] | ForEach-Object {
                ([adsi]"LDAP://$_").SamAccountName
            }
        }
    }

}


function Get-NetLocalGroups {
    <#
    .SYNOPSIS
    Gets a list of all localgroups on a remote machine.
    
    .DESCRIPTION
    This function utilizes ADSI to query a remote (or local) host for
    all localgroups on a specified remote machine.

    .PARAMETER HostName
    The hostname or IP to query for local group users.

    .PARAMETER HostList
    List of hostnames/IPs to query for local group users.
        
    .OUTPUTS
    System.Array. An array of found local groups.

    .EXAMPLE
    > Get-NetLocalGroups
    Returns all local groups, equivalent to "net localgroup"
    
    .EXAMPLE
    > Get-NetLocalGroups -HostName WINDOWSXP
    Returns all the local groups for WINDOWSXP

    .LINK
    http://stackoverflow.com/questions/21288220/get-all-local-members-and-groups-displayed-together
    #>

    [CmdletBinding()]
    param(
        [string]$HostName = "localhost",
        [string]$HostList
    )

    $Servers = @()

    # if we have a host list passed, grab it
    if($HostList){
        if (Test-Path $HostList){
            foreach ($Item in Get-Content $HostList) {
                if (($Item -ne $null) -and ($Item.trim() -ne "")){
                    $servers += $Item
                }
            }
        }
        else {
            Write-Warning "[!] Input file '$HostList' doesn't exist!"
            $null
        }
    }
    else{
        # otherwise assume a single host name
        $Servers = $($HostName)
    }

    foreach($Server in $Servers)
    {
        $computer = [ADSI]"WinNT://$server,computer"

        $computer.psbase.children | where { $_.psbase.schemaClassName -eq 'group' } | foreach {
            new-object psobject -Property @{
                Server = $Server
                Group = ($_.name)[0]
                SID = (new-object System.Security.Principal.SecurityIdentifier $_.objectsid[0],0).Value
            }
            # order preserving:
            # $out = New-Object System.Collections.Specialized.OrderedDictionary
            # $out.add('Server', $Server)
            # $out.add('Group', ($_.name)[0])
            # $out
        }
    }
}


function Get-NetLocalGroup {
    <#
    .SYNOPSIS
    Gets a list of all current users in a specified local group.
    
    .DESCRIPTION
    This function utilizes ADSI to query a remote (or local) host for
    all members of a specified localgroup.
    Note: in order for the accountdisabled field to be properly extracted,
    just the hostname needs to be supplied, not the IP or FQDN.

    .PARAMETER HostName
    The hostname or IP to query for local group users.

    .PARAMETER HostList
    List of hostnames/IPs to query for local group users.
     
    .PARAMETER GroupName
    The local group name to query for users. If not given, it defaults to "Administrators"
        
    .OUTPUTS
    System.Array. An array of found users for the specified local group.

    .EXAMPLE
    > Get-NetLocalGroup
    Returns the usernames that of members of localgroup "Administrators" on the local host.
    
    .EXAMPLE
    > Get-NetLocalGroup -HostName WINDOWSXP
    Returns all the local administrator accounts for WINDOWSXP

    .LINK
    http://stackoverflow.com/questions/21288220/get-all-local-members-and-groups-displayed-together
    http://msdn.microsoft.com/en-us/library/aa772211(VS.85).aspx
    #>

    [CmdletBinding()]
    param(
        [string]$HostName = "localhost",
        [string]$HostList,
        [string]$GroupName
    )

    $Servers = @()

    # if we have a host list passed, grab it
    if($HostList){
        if (Test-Path $HostList){
            foreach ($Item in Get-Content $HostList) {
                if (($Item -ne $null) -and ($Item.trim() -ne "")){
                    $servers += $Item
                }
            }
        }
        else {
            Write-Warning "[!] Input file '$HostList' doesn't exist!"
            $null
        }
    }
    else{
        # otherwise assume a single host name
        $Servers = $($HostName)
    }

    if (-not $GroupName){
        # resolve the SID for the local admin group - this should usually default to "Administrators"
        $objSID = New-Object System.Security.Principal.SecurityIdentifier("S-1-5-32-544")
        $objgroup = $objSID.Translate( [System.Security.Principal.NTAccount])
        $GroupName = ($objgroup.Value).Split("\")[1]
    }

    # query the specified group using the WINNT provider, and
    # extract fields as appropriate from the results
    foreach($Server in $Servers)
    {
        $members = @($([ADSI]"WinNT://$server/$groupname").psbase.Invoke("Members"))
        $members | foreach {
            new-object psobject -Property @{
                Server = $Server
                AccountName =( $_.GetType().InvokeMember("Adspath", 'GetProperty', $null, $_, $null)).Replace("WinNT://", "")
                # translate the binary sid to a string
                SID = ConvertSID ($_.GetType().InvokeMember("ObjectSID", 'GetProperty', $null, $_, $null))
                # if the account is local, check if it's disabled, if it's domain, always print $false
                Disabled = $(if((($_.GetType().InvokeMember("Adspath", 'GetProperty', $null, $_, $null)).Replace("WinNT://", "")-like "*/$server/*")) {try{$_.GetType().InvokeMember("AccountDisabled", 'GetProperty', $null, $_, $null)} catch {"ERROR"} } else {$False} ) 
                # check if the member is a group
                IsGroup = ($_.GetType().InvokeMember("Class", 'GetProperty', $Null, $_, $Null) -eq "group")
            }
        }
    }

}


function Get-NetLocalServices {
    <#
    .SYNOPSIS
    Gets a list of all local services running on a remote machine.
    
    .DESCRIPTION
    This function utilizes ADSI to query a remote (or local) host for
    all locally running services.

    .PARAMETER HostName
    The hostname or IP to query for local group users.

    .PARAMETER HostList
    List of hostnames/IPs to query for local group users.

    .OUTPUTS
    System.Array. An array of found services for the specified group.

    .EXAMPLE
    > Get-NetLocalServices -HostName WINDOWSXP
    Returns all the local services running on for WINDOWSXP
    #>

    [CmdletBinding()]
    param(
        [string]$HostName = "localhost",
        [string]$HostList
    )

    $Servers = @()

    # if we have a host list passed, grab it
    if($HostList){
        if (Test-Path $HostList){
            foreach ($Item in Get-Content $HostList) {
                if (($Item -ne $null) -and ($Item.trim() -ne "")){
                    $servers += $Item
                }
            }
        }
        else {
            Write-Warning "[!] Input file '$HostList' doesn't exist!"
            $null
        }
    }
    else{
        # otherwise assume a single host name
        $Servers = $($HostName)
    }

    foreach($Server in $Servers)
    {
        $computer = [ADSI]"WinNT://$server,computer"

        $computer.psbase.children | where { $_.psbase.schemaClassName -eq 'service' } | foreach {
            new-object psobject -Property @{
                Server = $Server
                ServiceName = $_.name
                ServicePath = $_.Path
                ServiceAccountName = $_.ServiceAccountName
            }
        }
    }
}


function Invoke-NetGroupUserAdd {
    <#
    .SYNOPSIS
    Adds a local or domain user to a local or domain group.
    
    .DESCRIPTION
    This function utilizes DirectoryServices.AccountManagement to add a
    user to a local machine or domain group (if permissions allow). It will
    default to addingt to the local machine.

    .PARAMETER UserName
    The domain username to query for.

    .PARAMETER GroupName
    Group to add the user to.

    .PARAMETER Domain
    Domain to add the user to.
    
    .PARAMETER HostName
    Hostname to add the user to, defaults to localhost.
        
    .OUTPUTS
    System.bool. True if the add succeeded, false otherwise.

    .EXAMPLE
    > Invoke-NetGroupUserAdd -UserName john -GroupName Administrators
    Adds a localuser "john" to the local group "Administrators"

    .EXAMPLE
    > Invoke-NetGroupUserAdd -UserName john -GroupName "Domain Admins" -Domain
    Adds the existing user "john" to the domain group "Domain Admins" 
    #>

    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $True)] [string]$UserName,
        [Parameter(Mandatory = $True)] [string]$GroupName,
        [string]$Domain,
        [string]$HostName = "localhost"
    )

    # add the assembly if we need it
    Add-Type -AssemblyName System.DirectoryServices.AccountManagement

    # if we're adding to a remote host, use the WinNT provider
    if($HostName -ne "localhost"){
        try{
            ([ADSI]"WinNT://$HostName/$GroupName,group").add("WinNT://$HostName/$UserName,user")
            Write-Host "User $UserName successfully added to group $GroupName on $HostName"
        }
        catch{
            Write-Warning "Error adding user $UserName to group $GroupName on $HostName"
            return
        }
    }

    # otherwise it's a local or domain add
    else{
        if ($Domain){
            try{
                # try to create the context for the target domain
                $DomainContext = New-Object System.DirectoryServices.ActiveDirectory.DirectoryContext("Domain", $Domain)
                $d = [System.DirectoryServices.ActiveDirectory.Domain]::GetDomain($DomainContext)

                # get the domain context
                $ct = [System.DirectoryServices.AccountManagement.ContextType]::Domain
            }
            catch{
                Write-Warning "Error connecting to domain $Domain, is there a trust?"
                return $null
            }
        }
        else{
            # otherwise, get the local machine context
            $ct = [System.DirectoryServices.AccountManagement.ContextType]::Machine
        }

        # get the full principal context
        $context = New-Object -TypeName System.DirectoryServices.AccountManagement.PrincipalContext -ArgumentList $ct, $d

        # find the particular group
        $group = [System.DirectoryServices.AccountManagement.GroupPrincipal]::FindByIdentity($context,$GroupName)

        # add the particular user to the group
        $group.Members.add($context, [System.DirectoryServices.AccountManagement.IdentityType]::SamAccountName, $UserName)

        # commit the changes
        $group.Save()
    }
}


function Get-NetFileServers {
    <#
    .SYNOPSIS
    Returns a list of all file servers extracted from user home directories.
    
    .DESCRIPTION
    This function pulls all user information, extracts all file servers from
    user home directories, and returns the uniquified list.

    .PARAMETER Domain
    The domain to query for user file servers.

    .OUTPUTS
    System.Array. An array of found fileservers.

    .EXAMPLE
    > Get-NetFileServers
    Returns active file servers.
    #>

    [CmdletBinding()]
    param(
        [string]$Domain
    )

    $FileServers = @()

    # get all the domain users for the specified or local domain
    if ($Domain){
        $users = Get-NetUsers -Domain $Domain
    }
    else {
        $users = Get-NetUsers
    }

    # extract all home directories and create a unique list
    foreach ($user in $users){
        
        $d = $user.homedirectory
        # pull the HomeDirectory field from this user record
        if ($d){
            $d = $user.homedirectory[0]
        }
        if (($d -ne $null) -and ($d.trim() -ne "")){
            # extract the server name from the homedirectory path
            $parts = $d.split("\")
            if ($parts.count -gt 2){
                # append the base file server to the target $FileServers list
                $FileServers += $parts[2]
            }
        }
    }

    # uniquify the fileserver list
    $t = $FileServers | Get-Unique
    ([Array]$t)
}

function Get-NetLoggedon {
    <#
    .SYNOPSIS
    Gets users actively logged onto a specified server.
    
    .DESCRIPTION
    This function will execute the NetWkstaUserEnum Win32API call to query
    a given host for actively logged on users.

    .PARAMETER HostName
    The hostname to query for logged on users.

    .OUTPUTS
    WKSTA_USER_INFO_1 structure. A representation of the WKSTA_USER_INFO_1
    result structure which includes the username and domain of logged on users.

    .EXAMPLE
    > Get-NetLoggedon
    Returns users actively logged onto the local host.

    .EXAMPLE
    > Get-NetLoggedon -HostName sqlserver
    Returns users actively logged onto the 'sqlserver' host.
    #>

    [CmdletBinding()]
    param(
        # default to querying the localhost if no name is supplied
        [string]$HostName = "localhost"
    )

    If ($PSBoundParameters['Debug']) {
        $DebugPreference = 'Continue'
    }

    # load up the assemblies we need - http://www.exploit-monday.com/2012/07/structs-and-enums-using-reflection.html
    $Domain = [AppDomain]::CurrentDomain
    $DynAssembly = New-Object System.Reflection.AssemblyName('TestAssembly')
    $AssemblyBuilder = $Domain.DefineDynamicAssembly($DynAssembly, [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
    $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule('TestModule', $False)

    # used for C structures below
    $MarshalAsConstructor = [Runtime.InteropServices.MarshalAsAttribute].GetConstructor([Runtime.InteropServices.UnmanagedType])
    $MarshalAsCustomAttribute = New-Object Reflection.Emit.CustomAttributeBuilder($MarshalAsConstructor, @([Runtime.InteropServices.UnmanagedType]::LPWStr))

    # 4 for 32 bit, 8 for 64 bit
    $PtrSize = [IntPtr]::size

    # build the WKSTA_USER_INFO_1 structure (http://msdn.microsoft.com/en-us/library/windows/desktop/aa371409(v=vs.85).aspx) 
    #   manually using reflection
    #   adapted heavily from @mattifestation's post at http://www.exploit-monday.com/2012/07/structs-and-enums-using-reflection.html
    $Attributes = 'AutoLayout, AnsiClass, Class, Public, ExplicitLayout, Sealed, BeforeFieldInit'
    $TypeBuilder = $ModuleBuilder.DefineType('WKSTA_USER_INFO_1', $Attributes, [System.ValueType], $PtrSize*4)

    $BufferField1 = $TypeBuilder.DefineField('wkui1_username', [String], 'Public, HasFieldMarshal')
    $BufferField1.SetCustomAttribute($MarshalAsCustomAttribute)
    $BufferField1.SetOffset(0)

    $BufferField2 = $TypeBuilder.DefineField('wkui1_logon_domain', [String], 'Public, HasFieldMarshal')
    $BufferField2.SetCustomAttribute($MarshalAsCustomAttribute)
    $BufferField2.SetOffset($PtrSize*1)

    $BufferField3 = $TypeBuilder.DefineField('wkui1_oth_domains', [String], 'Public, HasFieldMarshal')
    $BufferField3.SetCustomAttribute($MarshalAsCustomAttribute)
    $BufferField3.SetOffset($PtrSize*2)

    $BufferField4 = $TypeBuilder.DefineField('wkui1_logon_server', [String], 'Public, HasFieldMarshal')
    $BufferField4.SetCustomAttribute($MarshalAsCustomAttribute)
    $BufferField4.SetOffset($PtrSize*3)

    $WKSTA_USER_INFO_1 = $TypeBuilder.CreateType()

    # Declare the reference variables
    $QueryLevel = 1
    $ptrInfo = [System.Intptr] 0 
    $EntriesRead = 0
    $TotalRead = 0
    $ResumeHandle = 0

    # 'manually' convert this string to unicode by inserting 0x00's between characters
    # because the reflection implicitly converts the string to ascii
    $NewHostName = ""
    foreach ($c in $HostName.ToCharArray()) { $NewHostName += "$c$([char]0x0000)" }

    # adapted heavily from http://www.exploit-monday.com/2012/05/accessing-native-windows-api-in.html    
    $NetWkstaUserEnumAddr = Get-ProcAddress netapi32.dll NetWkstaUserEnum
    $NetWkstaUserEnumDelegate = Get-DelegateType @( [string], [Int32], [Int].MakeByRefType(), [Int], [Int32].MakeByRefType(), [Int32].MakeByRefType(), [Int32].MakeByRefType()) ([Int])
    $NetWkstaUserEnum = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($NetWkstaUserEnumAddr, $NetWkstaUserEnumDelegate)
    $Result = $NetWkstaUserEnum.Invoke($NewHostName, $QueryLevel,[ref]$ptrInfo,-1,[ref]$EntriesRead,[ref]$TotalRead,[ref]$ResumeHandle)

    # have to recast this
    $ptrInfo = [System.Intptr] $ptrInfo

    # Locate the offset of the initial intPtr
    $offset = $ptrInfo.ToInt64()

    Write-Debug "Get-NetLoggedon result: $Result"

    # 0 = success
    if (($Result -eq 0) -and ($offset -gt 0)) {

        # Work out how mutch to increment the pointer by finding out the size of the structure
        $Increment = [System.Runtime.Interopservices.Marshal]::SizeOf($WKSTA_USER_INFO_1)

        # parse all the result structures
        for ($i = 0; ($i -lt $EntriesRead); $i++){
            $newintptr = New-Object system.Intptr -ArgumentList $offset
            $Info = [System.Runtime.InteropServices.Marshal]::PtrToStructure($newintptr,$WKSTA_USER_INFO_1)
            $Info | Select-Object *
            $offset = $newintptr.ToInt64()
            $offset += $increment
        }
        # cleanup the ptr buffer using NetApiBufferFree
        $NetApiBufferFreeAddr = Get-ProcAddress netapi32.dll NetApiBufferFree
        $NetApiBufferFreeDelegate = Get-DelegateType @( [IntPtr]) ([Int])
        $NetApiBufferFree = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($NetApiBufferFreeAddr, $NetApiBufferFreeDelegate)
        $t = $NetApiBufferFree.Invoke($ptrInfo)
    }
    else 
    {
        switch ($Result) {
          (5)           {Write-Debug "The user does not have access to the requested information."}
          (124)         {Write-Debug "The value specified for the level parameter is not valid."}
          (87)          {Write-Debug 'The specified parameter is not valid.'}
          (234)         {Write-Debug 'More entries are available. Specify a large enough buffer to receive all entries.'}
          (8)           {Write-Debug 'Insufficient memory is available.'}
          (2312)        {Write-Debug 'A session does not exist with the computer name.'}
          (2351)        {Write-Debug 'The computer name is not valid.'}
          (2221)        {Write-Debug 'Username not found.'}
          (53)          {Write-Debug 'Hostname could not be found'}
        }
    }
}


function Get-NetConnections {
    <#
    .SYNOPSIS
    Gets active connections to a server resource.
    
    .DESCRIPTION
    This function will execute the NetConnectionEnum Win32API call to query
    a given host for users connected to a particular resource.
    
    Note: only members of the Administrators or Account Operators local group 
    can successfully execute NetFileEnum

    .PARAMETER HostName
    The hostname to query.

    .PARAMETER Share
    The share to check connections to.

    .OUTPUTS
    CONNECTION_INFO_1  structure. A representation of the CONNECTION_INFO_1 
    result structure which includes the username host of connected users.

    .EXAMPLE
    > Get-NetConnections -HostName fileserver -Share secret
    Returns users actively connected to the share 'secret' on a fileserver.
    #>
    [CmdletBinding()]
    param(
        # default to querying the localhost if no name is supplied
        [string]$HostName = "localhost",
        [string]$Share = "C$"
    )

    If ($PSBoundParameters['Debug']) {
        $DebugPreference = 'Continue'
    }

    # load up the assemblies we need - http://www.exploit-monday.com/2012/07/structs-and-enums-using-reflection.html
    $Domain = [AppDomain]::CurrentDomain
    $DynAssembly = New-Object System.Reflection.AssemblyName('TestAssembly')
    $AssemblyBuilder = $Domain.DefineDynamicAssembly($DynAssembly, [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
    $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule('TestModule', $False)

    # used for C structures below
    $MarshalAsConstructor = [Runtime.InteropServices.MarshalAsAttribute].GetConstructor([Runtime.InteropServices.UnmanagedType])
    $MarshalAsCustomAttribute = New-Object Reflection.Emit.CustomAttributeBuilder($MarshalAsConstructor, @([Runtime.InteropServices.UnmanagedType]::LPWStr))

    # 4 for 32 bit, 8 for 64 bit
    $PtrSize = [IntPtr]::size

    # build the FILE_INFO_3 structure manually using reflection
    #   adapted heavily from @mattifestation's post at http://www.exploit-monday.com/2012/07/structs-and-enums-using-reflection.html
    $Attributes = 'AutoLayout, AnsiClass, Class, Public, ExplicitLayout, Sealed, BeforeFieldInit'
    $TypeBuilder = $ModuleBuilder.DefineType('FILE_INFO_3', $Attributes, [System.ValueType], 24+$PtrSize*2)

    $TypeBuilder.DefineField('coni1_id', [UInt32], 'Public').SetOffset(0) | Out-Null
    $TypeBuilder.DefineField('coni1_type', [UInt32], 'Public').SetOffset(4) | Out-Null
    $TypeBuilder.DefineField('coni1_num_opens', [UInt32], 'Public').SetOffset(8) | Out-Null
    $TypeBuilder.DefineField('coni1_num_users', [UInt32], 'Public').SetOffset(12) | Out-Null
    $TypeBuilder.DefineField('coni1_time', [UInt32], 'Public').SetOffset(16) | Out-Null

    $BufferField1 = $TypeBuilder.DefineField('coni1_username', [String], 'Public, HasFieldMarshal')
    $BufferField1.SetCustomAttribute($MarshalAsCustomAttribute)
    $BufferField1.SetOffset(24)

    $BufferField2 = $TypeBuilder.DefineField('coni1_netname', [String], 'Public, HasFieldMarshal')
    $BufferField2.SetCustomAttribute($MarshalAsCustomAttribute)
    $BufferField2.SetOffset(24+$PtrSize)

    $CONNECTION_INFO_1 = $TypeBuilder.CreateType()

    # arguments for NetConnectionEnum
    $QueryLevel = 1
    $ptrInfo = 0 
    $EntriesRead = 0
    $TotalRead = 0
    $ResumeHandle = 0

    # 'manually' convert these strings to unicode by inserting 0x00's between characters
    # because the reflection implicitly converts the string to ascii
    $NewHostName = ""
    foreach ($c in $HostName.ToCharArray()) { $NewHostName += "$c$([char]0x0000)" }
    $NewShare = ""
    foreach ($c in $Share.ToCharArray()) { $NewShare += "$c$([char]0x0000)" }

    # adapted heavily from http://www.exploit-monday.com/2012/05/accessing-native-windows-api-in.html    
    $NetConnectionEnumAddr = Get-ProcAddress netapi32.dll NetConnectionEnum
    $NetConnectionEnumDelegate = Get-DelegateType @( [string], [string], [Int32], [Int].MakeByRefType(), [Int], [Int32].MakeByRefType(), [Int32].MakeByRefType(), [Int32].MakeByRefType()) ([Int])
    $NetConnectionEnum = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($NetConnectionEnumAddr, $NetConnectionEnumDelegate)
    $Result = $NetConnectionEnum.Invoke($NewHostName, $NewShare, $QueryLevel,[ref]$ptrInfo,-1,[ref]$EntriesRead,[ref]$TotalRead,[ref]$ResumeHandle)

    # have to recast this
    $ptrInfo = [System.Intptr] $ptrInfo

    # Locate the offset of the initial intPtr
    $offset = $ptrInfo.ToInt64()

    Write-Debug "Get-NetConnection result: $Result"

    # 0 = success
    if (($Result -eq 0) -and ($offset -gt 0)) {

        # Work out how mutch to increment the pointer by finding out the size of the structure
        $Increment = [System.Runtime.Interopservices.Marshal]::SizeOf($CONNECTION_INFO_1)

        # parse all the result structures
        for ($i = 0; ($i -lt $EntriesRead); $i++){
            $newintptr = New-Object system.Intptr -ArgumentList $offset
            $Info = [system.runtime.interopservices.marshal]::PtrToStructure($newintptr,$CONNECTION_INFO_1)
            $Info | Select-Object *
            $offset = $newintptr.ToInt64()
            $offset += $increment
        }
        # cleanup the ptr buffer using NetApiBufferFree
        $NetApiBufferFreeAddr = Get-ProcAddress netapi32.dll NetApiBufferFree
        $NetApiBufferFreeDelegate = Get-DelegateType @( [IntPtr]) ([Int])
        $NetApiBufferFree = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($NetApiBufferFreeAddr, $NetApiBufferFreeDelegate)
        $t = $NetApiBufferFree.Invoke($ptrInfo)
    }
    else 
    {
        switch ($Result) {
          (5)           {Write-Debug "The user does not have access to the requested information."}
          (124)         {Write-Debug "The value specified for the level parameter is not valid."}
          (87)          {Write-Debug 'The specified parameter is not valid.'}
          (234)         {Write-Debug 'More entries are available. Specify a large enough buffer to receive all entries.'}
          (8)           {Write-Debug 'Insufficient memory is available.'}
          (2312)        {Write-Debug 'A session does not exist with the computer name.'}
          (2351)        {Write-Debug 'The computer name is not valid.'}
          (2221)        {Write-Debug 'Username not found.'}
          (53)          {Write-Debug 'Hostname could not be found'}
        }
    }
}


function Get-NetSessions {
    <#
    .SYNOPSIS
    Gets active sessions for a specified server.
    Heavily adapted from dunedinite's post on stackoverflow (see LINK below)

    .DESCRIPTION
    This function will execute the NetSessionEnum Win32API call to query
    a given host for active sessions on the host.

    .PARAMETER HostName
    The hostname to query for active sessions.

    .PARAMETER UserName
    The user name to query for active sessions.

    .OUTPUTS
    SESSION_INFO_10 structure. A representation of the SESSION_INFO_10
    result structure which includes the host and username associated
    with active sessions.

    .EXAMPLE
    > Get-NetSessions
    Returns active sessions on the local host.

    .EXAMPLE
    > Get-NetSessions -HostName sqlserver
    Returns active sessions on the 'sqlserver' host.

    .LINK
    http://www.exploit-monday.com/2012/05/accessing-native-windows-api-in.html
    #>
    
    [CmdletBinding()]
    param(
        # default to querying the localhost if no name is supplied
        [string]$HostName = "localhost",
        [string]$UserName = ""
    )

    If ($PSBoundParameters['Debug']) {
        $DebugPreference = 'Continue'
    }

    # load up the assemblies we need - http://www.exploit-monday.com/2012/07/structs-and-enums-using-reflection.html
    $Domain = [AppDomain]::CurrentDomain
    $DynAssembly = New-Object System.Reflection.AssemblyName('TestAssembly')
    $AssemblyBuilder = $Domain.DefineDynamicAssembly($DynAssembly, [System.Reflection.Emit.AssemblyBuilderAccess]::Run)
    $ModuleBuilder = $AssemblyBuilder.DefineDynamicModule('TestModule', $False)

    # used for C structures below
    $MarshalAsConstructor = [Runtime.InteropServices.MarshalAsAttribute].GetConstructor([Runtime.InteropServices.UnmanagedType])
    $MarshalAsCustomAttribute = New-Object Reflection.Emit.CustomAttributeBuilder($MarshalAsConstructor, @([Runtime.InteropServices.UnmanagedType]::LPWStr))

    # 4 for 32 bit, 8 for 64 bit
    $PtrSize = [IntPtr]::size

    # build the SESSION_INFO_10 structure manually using reflection
    #   adapted heavily from @mattifestation's post at http://www.exploit-monday.com/2012/07/structs-and-enums-using-reflection.html
    $Attributes = 'AutoLayout, AnsiClass, Class, Public, ExplicitLayout, Sealed, BeforeFieldInit'
    $TypeBuilder = $ModuleBuilder.DefineType('SESSION_INFO_10', $Attributes, [System.ValueType], 8+$PtrSize*2)

    $BufferField1 = $TypeBuilder.DefineField('sesi10_cname', [String], 'Public, HasFieldMarshal')
    $BufferField1.SetCustomAttribute($MarshalAsCustomAttribute)
    $BufferField1.SetOffset(0)

    $BufferField2 = $TypeBuilder.DefineField('sesi10_username', [String], 'Public, HasFieldMarshal')
    $BufferField2.SetCustomAttribute($MarshalAsCustomAttribute)
    $BufferField2.SetOffset($PtrSize*1)

    $TypeBuilder.DefineField('sesi10_time', [UInt32], 'Public').SetOffset($PtrSize*2) | Out-Null
    $TypeBuilder.DefineField('sesi10_idle_time', [UInt32], 'Public').SetOffset($PtrSize*2+4) | Out-Null

    $SESSION_INFO_10 = $TypeBuilder.CreateType()

    # arguments for NetSessionEnum
    $QueryLevel = 10
    $ptrInfo = 0 
    $EntriesRead = 0
    $TotalRead = 0
    $ResumeHandle = 0

    # 'manually' convert these strings to unicode by inserting 0x00's between characters
    # because the reflection implicitly converts the string to ascii
    $NewHostName = ""
    foreach ($c in $HostName.ToCharArray()) { $NewHostName += "$c$([char]0x0000)" }
    $NewUserName = ""
    foreach ($c in $UserName.ToCharArray()) { $NewUserName += "$c$([char]0x0000)" }

    # adapted heavily from http://www.exploit-monday.com/2012/05/accessing-native-windows-api-in.html    
    $NetSessionEnumAddr = Get-ProcAddress netapi32.dll NetSessionEnum
    $NetSessionEnumDelegate = Get-DelegateType @( [string], [string], [string], [Int32], [Int].MakeByRefType(), [Int], [Int32].MakeByRefType(), [Int32].MakeByRefType(), [Int32].MakeByRefType()) ([Int])
    $NetSessionEnum = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($NetSessionEnumAddr, $NetSessionEnumDelegate)
    $Result = $NetSessionEnum.Invoke($NewHostName, "", $NewUserName, $QueryLevel,[ref]$ptrInfo,-1,[ref]$EntriesRead,[ref]$TotalRead,[ref]$ResumeHandle)

    # have to recast this
    $ptrInfo = [System.Intptr] $ptrInfo

    # Locate the offset of the initial intPtr
    $offset = $ptrInfo.ToInt64()

    Write-Debug "Get-NetSessions result: $Result"

    # 0 = success
    if (($Result -eq 0) -and ($offset -gt 0)) {

        # Work out how mutch to increment the pointer by finding out the size of the structure
        $Increment = [System.Runtime.Interopservices.Marshal]::SizeOf($SESSION_INFO_10)

        # parse all the result structures
        for ($i = 0; ($i -lt $EntriesRead); $i++){
            $newintptr = New-Object system.Intptr -ArgumentList $offset
            $Info = [system.runtime.interopservices.marshal]::PtrToStructure($newintptr,$SESSION_INFO_10)
            $Info | Select-Object *
            $offset = $newintptr.ToInt64()
            $offset += $increment
        }
        # cleanup the ptr buffer using NetApiBufferFree
        $NetApiBufferFreeAddr = Get-ProcAddress netapi32.dll NetApiBufferFree
        $NetApiBufferFreeDelegate = Get-DelegateType @( [IntPtr]) ([Int])
        $NetApiBufferFree = [System.Runtime.InteropServices.Marshal]::GetDelegateForFunctionPointer($NetApiBufferFreeAddr, $NetApiBufferFreeDelegate)
        $t = $NetApiBufferFree.Invoke($ptrInfo)
    }
    else 
    {
        switch ($Result) {
          (5)           {Write-Debug "The user does not have access to the requested information."}
          (124)         {Write-Debug "The value specified for the level parameter is not valid."}
          (87)          {Write-Debug 'The specified parameter is not valid.'}
          (234)         {Write-Debug 'More entries are available. Specify a large enough buffer to receive all entries.'}
          (8)           {Write-Debug 'Insufficient memory is available.'}
          (2312)        {Write-Debug 'A session does not exist with the computer name.'}
          (2351)        {Write-Debug 'The computer name is not valid.'}
          (2221)        {Write-Debug 'Username not found.'}
          (53)          {Write-Debug 'Hostname could not be found'}
        }
    }
}

function Invoke-ShareFinder {
    <#
        .SYNOPSIS
        Finds (non-standard) shares on machines in the domain.

        Author: @harmj0y
        
        .DESCRIPTION
        This function finds the local domain name for a host using Get-NetDomain,
        queries the domain for all active machines with Get-NetComputers, then for 
        each server it lists of active shares with Get-NetShare. Non-standard shares 
        can be filtered out with -Exclude* flags.

        .PARAMETER HostList
        List of hostnames/IPs to search.

        .PARAMETER ExcludeStandard
        Exclude standard shares from display (C$, IPC$, print$ etc.)

        .PARAMETER ExcludePrint
        Exclude the print$ share

        .PARAMETER ExcludeIPC
        Exclude the IPC$ share

        .PARAMETER CheckShareAccess
        Only display found shares that the local user has access to.

        .PARAMETER CheckAdmin
        Only display ADMIN$ shares the local user has access to.

        .PARAMETER Ping
        Ping each host to ensure it's up before enumerating.

        .PARAMETER NoPing
        Ping each host to ensure it's up before enumerating.

        .PARAMETER NoPing
        Don't ping each host to ensure it's up before enumerating.

        .PARAMETER Delay
        Delay between enumerating hosts, defaults to 0

        .PARAMETER Jitter
        Jitter for the host delay, defaults to +/- 0.3

        .PARAMETER Domain
        Domain to query for machines.

        .EXAMPLE
        > Invoke-ShareFinder
        Find shares on the domain.
        
        .EXAMPLE
        > Invoke-ShareFinder -ExcludeStandard
        Find non-standard shares on the domain.

        .EXAMPLE
        > Invoke-ShareFinder -Delay 60
        Find shares on the domain with a 60 second (+/- *.3) 
        randomized delay between touching each host.

        .EXAMPLE
        > Invoke-ShareFinder -HostList hosts.txt
        Find shares for machines in the specified hostlist.

        .LINK
        http://blog.harmj0y.net
    #>
    
    [CmdletBinding()]
    param(
        [string]
        $HostList,

        [Switch]
        $ExcludeStandard,

        [Switch]
        $ExcludePrint,

        [Switch]
        $ExcludeIPC,

        [Switch]
        $Ping,

        [Switch]
        $NoPing,

        [Switch]
        $CheckShareAccess,

        [Switch]
        $CheckAdmin,

        [UInt32]
        $Delay = 0,

        [double]
        $Jitter = .3,

        [String]
        $Domain
    )
    
    If ($PSBoundParameters['Debug']) {
        $DebugPreference = 'Continue'
    }
    
    # figure out the shares we want to ignore
    [String[]] $excludedShares = @('')
    
    if ($ExcludePrint){
        $excludedShares = $excludedShares + "PRINT$"
    }
    if ($ExcludeIPC){
        $excludedShares = $excludedShares + "IPC$"
    }
    if ($ExcludeStandard){
        $excludedShares = @('', "ADMIN$", "IPC$", "C$", "PRINT$")
    }
    
    # random object for delay
    $randNo = New-Object System.Random
    
    # get the current user
    $CurrentUser = Get-NetCurrentUser
    
    # get the target domain
    if($Domain){
        $targetDomain = $Domain
    }
    else{
        # use the local domain
        $targetDomain = Get-NetDomain
    }
    
    Write-Verbose "[*] Running ShareFinder on domain $targetDomain with delay of $Delay"
    $servers = @()

    # if we're using a host list, read the targets in and add them to the target list
    if($HostList){
        if (Test-Path -Path $HostList){
            $servers = Get-Content -Path $HostList
        }
        else {
            Write-Warning "`r`n[!] Input file '$HostList' doesn't exist!`r`n"
            return $null
        }
    }
    else{
        # otherwise, query the domain for target servers
        Write-Verbose "[*] Querying domain $targetDomain for hosts...`r`n"
        $servers = Get-NetComputers -Domain $targetDomain
    }
    
    # randomize the server list
    $servers = Get-ShuffledArray $servers
    
    if (($servers -eq $null) -or ($servers.Count -eq 0)){
        Write-Warning "`r`n[!] No hosts found!"
        return $null
    }
    else{
        
        # return/output the current status lines
        $counter = 0
        
        foreach ($server in $servers){
            
            $counter = $counter + 1
            
            Write-Verbose "[*] Enumerating server $server ($counter of $($servers.count))"
            
            if ($server -ne ''){
                # sleep for our semi-randomized interval
                Start-Sleep -Seconds $randNo.Next((1-$Jitter)*$Delay, (1+$Jitter)*$Delay)
                
                # optionally check if the server is up first
                $up = $true
                if(-not $NoPing){
                    $up = Test-Server -Server $server
                }
                if($up){
                    # get the shares for this host and display what we find
                    $shares = Get-NetShare -HostName $server
                    foreach ($share in $shares) {
                        Write-Debug "[*] Server share: $share"
                        $netname = $share.shi1_netname
                        $remark = $share.shi1_remark
                        $path = '\\'+$server+'\'+$netname

                        # make sure we get a real share name back
                        if (($netname) -and ($netname.trim() -ne '')){
                            
                            # if we're just checking for access to ADMIN$
                            if($CheckAdmin){
                                if($netname.ToUpper() -eq "ADMIN$"){
                                    try{
                                        $f=[IO.Directory]::GetFiles($path)
                                        "\\$server\$netname `t- $remark"
                                    }
                                    catch {}
                                }
                            }
                            
                            # skip this share if it's in the exclude list
                            elseif ($excludedShares -notcontains $netname.ToUpper()){
                                # see if we want to check access to this share
                                if($CheckShareAccess){
                                    # check if the user has access to this path
                                    try{
                                        $f=[IO.Directory]::GetFiles($path)
                                        "\\$server\$netname `t- $remark"
                                    }
                                    catch {}
                                }
                                else{
                                    "\\$server\$netname `t- $remark"
                                }
                            } 
                            
                        }
                        
                    }
                }
                
            }
            
        }
    }
}


function Invoke-ShareFinderThreaded {
    <#
        .SYNOPSIS
        Finds (non-standard) shares on machines in the domain.
        Threaded version of Invoke-ShareFinder.
        Author: @harmj0y
        
        .DESCRIPTION
        This function finds the local domain name for a host using Get-NetDomain,
        queries the domain for all active machines with Get-NetComputers, then for 
        each server it lists of active shares with Get-NetShare. Non-standard shares 
        can be filtered out with -Exclude* flags.
        Threaded version of Invoke-ShareFinder.

        .PARAMETER HostList
        List of hostnames/IPs to search.

        .PARAMETER ExcludedShares
        Shares to exclude from output, wildcards accepted (i.e. IPC*)

        .PARAMETER CheckShareAccess
        Only display found shares that the local user has access to.

        .PARAMETER CheckAdmin
        Only display ADMIN$ shares the local user has access to.

        .PARAMETER NoPing
        Don't ping each host to ensure it's up before enumerating.

        .PARAMETER Domain
        Domain to query for machines.

        .PARAMETER MaxThreads
        The maximum concurrent threads to execute.

        .EXAMPLE
        > Invoke-ShareFinder
        Find shares on the domain.
        
        .EXAMPLE
        > Invoke-ShareFinder -ExcludedShares IPC$,PRINT$
        Find shares on the domain excluding IPC$ and PRINT$

        .EXAMPLE
        > Invoke-ShareFinder -HostList hosts.txt
        Find shares for machines in the specified hostlist.

        .LINK
        http://blog.harmj0y.net
    #>
    
    [CmdletBinding()]
    param(
        [string]
        $HostList,

        [string[]]
        $ExcludedShares = @(),

        [Switch]
        $NoPing,

        [Switch]
        $CheckShareAccess,

        [Switch]
        $CheckAdmin,

        [String]
        $Domain,

        [Int]
        $MaxThreads = 10
    )
    
    If ($PSBoundParameters['Debug']) {
        $DebugPreference = 'Continue'
    }
    
    # get the current user
    $CurrentUser = Get-NetCurrentUser
    
    # get the target domain
    if($Domain){
        $targetDomain = $Domain
    }
    else{
        # use the local domain
        $targetDomain = Get-NetDomain
    }
    
    Write-Verbose "[*] Running Invoke-ShareFinderThreaded on domain $targetDomain with delay of $Delay"
    $servers = @()

    # if we're using a host list, read the targets in and add them to the target list
    if($HostList){
        if (Test-Path -Path $HostList){
            $servers = Get-Content -Path $HostList
        }
        else {
            Write-Warning "`r`n[!] Input file '$HostList' doesn't exist!`r`n"
            return $null
        }
    }
    else{
        # otherwise, query the domain for target servers
        Write-Verbose "[*] Querying domain $targetDomain for hosts...`r`n"
        $servers = Get-NetComputers -Domain $targetDomain
    }
    
    # randomize the server list
    $servers = Get-ShuffledArray $servers
    
    if (($servers -eq $null) -or ($servers.Count -eq 0)){
        Write-Warning "`r`n[!] No hosts found!"
        return $null
    }

    # script block that eunmerates a server
    # this is called by the multi-threading code later
    $EnumServerBlock = {
        param($Server, $Ping, $CheckShareAccess, $ExcludedShares, $CheckAdmin)

        # optionally check if the server is up first
        $up = $true
        if($Ping){
            $up = Test-Server -Server $Server
        }
        if($up){
            # get the shares for this host and check what we find
            $shares = Get-NetShare -HostName $Server
            foreach ($share in $shares) {
                Write-Debug "[*] Server share: $share"
                $netname = $share.shi1_netname
                $remark = $share.shi1_remark
                $path = '\\'+$server+'\'+$netname

                # make sure we get a real share name back
                if (($netname) -and ($netname.trim() -ne '')){
                    # if we're just checking for access to ADMIN$
                    if($CheckAdmin){
                        if($netname.ToUpper() -eq "ADMIN$"){
                            try{
                                $f=[IO.Directory]::GetFiles($path)
                                "\\$server\$netname `t- $remark"
                            }
                            catch {}
                        }
                    }
                    # skip this share if it's in the exclude list
                    elseif ($excludedShares -notcontains $netname.ToUpper()){
                        # see if we want to check access to this share
                        if($CheckShareAccess){
                            # check if the user has access to this path
                            try{
                                $f=[IO.Directory]::GetFiles($path)
                                "\\$server\$netname `t- $remark"
                            }
                            catch {}
                        }
                        else{
                            "\\$server\$netname `t- $remark"
                        }
                    } 
                }
            }
        }
    }

    # Adapted from:
    #   http://powershell.org/wp/forums/topic/invpke-parallel-need-help-to-clone-the-current-runspace/
    $sessionState = [System.Management.Automation.Runspaces.InitialSessionState]::CreateDefault()
    $sessionState.ApartmentState = [System.Threading.Thread]::CurrentThread.GetApartmentState()
 
    # grab all the current variables for this runspace
    $MyVars = Get-Variable -Scope 1
 
    # these Variables are added by Runspace.Open() Method and produce Stop errors if you add them twice
    $VorbiddenVars = @("?","args","ConsoleFileName","Error","ExecutionContext","false","HOME","Host","input","InputObject","MaximumAliasCount","MaximumDriveCount","MaximumErrorCount","MaximumFunctionCount","MaximumHistoryCount","MaximumVariableCount","MyInvocation","null","PID","PSBoundParameters","PSCommandPath","PSCulture","PSDefaultParameterValues","PSHOME","PSScriptRoot","PSUICulture","PSVersionTable","PWD","ShellId","SynchronizedHash","true")
 
    # Add Variables from Parent Scope (current runspace) into the InitialSessionState 
    ForEach($Var in $MyVars) {
        If($VorbiddenVars -notcontains $Var.Name) {
        $sessionstate.Variables.Add((New-Object -TypeName System.Management.Automation.Runspaces.SessionStateVariableEntry -ArgumentList $Var.name,$Var.Value,$Var.description,$Var.options,$Var.attributes))
        }
    }

    # Add Functions from current runspace to the InitialSessionState
    ForEach($Function in (Get-ChildItem Function:)) {
        $sessionState.Commands.Add((New-Object -TypeName System.Management.Automation.Runspaces.SessionStateFunctionEntry -ArgumentList $Function.Name, $Function.Definition))
    }
 
    # threading adapted from
    # https://github.com/darkoperator/Posh-SecMod/blob/master/Discovery/Discovery.psm1#L407
    # Thanks Carlos!   
    $counter = 0

    # create a pool of maxThread runspaces   
    $pool = [runspacefactory]::CreateRunspacePool(1, $MaxThreads, $sessionState, $host)
    $pool.Open()

    $jobs = @()   
    $ps = @()   
    $wait = @()

    $serverCount = $servers.count
    "`r`n[*] Enumerating $serverCount servers..."

    foreach ($server in $servers){
        
        # make sure we get a server name
        if ($server -ne ''){
            Write-Verbose "[*] Enumerating server $server ($counter of $($servers.count))"

            While ($($pool.GetAvailableRunspaces()) -le 0) {
                Start-Sleep -milliseconds 500
            }
    
            # create a "powershell pipeline runner"   
            $ps += [powershell]::create()
   
            $ps[$counter].runspacepool = $pool

            # add the script block + arguments
            [void]$ps[$counter].AddScript($EnumServerBlock).AddParameter('Server', $server).AddParameter('Ping', -not $NoPing).AddParameter('CheckShareAccess', $CheckShareAccess).AddParameter('ExcludedShares', $ExcludedShares).AddParameter('CheckAdmin', $CheckAdmin)
    
            # start job
            $jobs += $ps[$counter].BeginInvoke();
     
            # store wait handles for WaitForAll call   
            $wait += $jobs[$counter].AsyncWaitHandle

        }
        $counter = $counter + 1
    }

    Write-Verbose "Waiting for scanning threads to finish..."

    $waitTimeout = Get-Date

    while ($($jobs | ? {$_.IsCompleted -eq $false}).count -gt 0 -or $($($(Get-Date) - $waitTimeout).totalSeconds) -gt 60) {
            Start-Sleep -milliseconds 500
        } 

    # end async call   
    for ($y = 0; $y -lt $counter; $y++) {     

        try {   
            # complete async job   
            $ps[$y].EndInvoke($jobs[$y])   

        } catch {
            Write-Warning "error: $_"  
        }
        finally {
            $ps[$y].Dispose()
        }    
    }

    $pool.Dispose()
}

function Invoke-SearchFiles {
    <#
    .SYNOPSIS
    Searches a given server/path for files with specific terms in the name.
    
    .DESCRIPTION
    This function recursively searches a given UNC path for files with 
    specific keywords in the name (default of pass, sensitive, secret, admin,
    login and unattend*.xml). The output can be piped out to a csv with the 
    -OutFile flag. By default, hidden files/folders are included in search results.
    .PARAMETER Path
    UNC/local path to recursively search.
    .PARAMETER Terms
    Terms to search for.
    .PARAMETER OfficeDocs
    Search for office documents (*.doc*, *.xls*, *.ppt*)
    .PARAMETER FreshEXES
    Find .EXEs accessed within the last week.
    .PARAMETER AccessDateLimit
    Only return files with a LastAccessTime greater than this date value.
    .PARAMETER WriteDateLimit
    Only return files with a LastWriteTime greater than this date value.
    .PARAMETER CreateDateLimit
    Only return files with a CreationDate greater than this date value.
    .PARAMETER ExcludeFolders
    Exclude folders from the search results.
    .PARAMETER ExcludeHidden
    Exclude hidden files and folders from the search results.
    .PARAMETER CheckWriteAccess
    Only returns files the current user has write access to.
    .PARAMETER OutFile
    Output results to a specified csv output file.
    .OUTPUTS
    The full path, owner, lastaccess time, lastwrite time, and size for
    each found file.
    .EXAMPLE
    > Invoke-SearchFiles -Path \\WINDOWS7\Users\
    Returns any files on the remote path \\WINDOWS7\Users\ that have 'pass',
    'sensitive', or 'secret' in the title.
    .EXAMPLE
    > Invoke-SearchFiles -Path \\WINDOWS7\Users\ -Terms salaries,email -OutFile out.csv
    Returns any files on the remote path \\WINDOWS7\Users\ that have 'salaries'
    or 'email' in the title, and writes the results out to a csv file
    named 'out.csv'
    .EXAMPLE
    > Invoke-SearchFiles -Path \\WINDOWS7\Users\ -AccessDateLimit 6/1/2014
    Returns all files accessed since 6/1/2014.
    .LINK
    http://www.harmj0y.net/blog/redteaming/file-server-triage-on-red-team-engagements/
    #>

    [CmdletBinding()]
    param(
        [string]$Path = ".\",
        $Terms,
        [Switch] $OfficeDocs,
        [Switch] $FreshEXES,
        $AccessDateLimit = "1/1/1970",
        $WriteDateLimit = "1/1/1970",
        $CreateDateLimit = "1/1/1970",
        [Switch] $ExcludeFolders,
        [Switch] $ExcludeHidden,
        [Switch] $CheckWriteAccess,
        [string] $OutFile
    )

    # default search terms
    $SearchTerms = @('pass', 'sensitive', 'admin', 'login', 'secret', 'unattend*.xml', '.vmdk', 'creds', 'credential')

    # check if custom search terms were passed
    if ($Terms){
        if($Terms -isnot [system.array]){
            $Terms = @($Terms)
        }
        $SearchTerms = $Terms
    }

    # append wildcards to the front and back of all search terms
    for ($i = 0; $i -lt $SearchTerms.Count; $i++) {
        $SearchTerms[$i] = "*$($SearchTerms[$i])*"
    }

    # search just for office documents if specified
    if ($OfficeDocs){
        $SearchTerms = @('*.doc', '*.docx', '*.xls', '*.xlsx', '*.ppt', '*.pptx')
    }

    # find .exe's accessed within the last 7 days
    if($FreshEXES){
        # get an access time limit of 7 days ago
        $AccessDateLimit = (get-date).AddDays(-7).ToString("MM/dd/yyyy")
        $SearchTerms = "*.exe"
    }

    # build our giant recursive search command w/ conditional options
    $cmd = "get-childitem $Path -rec $(if(-not $ExcludeHidden){`"-Force`"}) -ErrorAction SilentlyContinue -include $($SearchTerms -join `",`") | where{ $(if($ExcludeFolders){`"(-not `$_.PSIsContainer) -and`"}) (`$_.LastAccessTime -gt `"$AccessDateLimit`") -and (`$_.LastWriteTime -gt `"$WriteDateLimit`") -and (`$_.CreationTime -gt `"$CreateDateLimit`")} | select-object FullName,@{Name='Owner';Expression={(Get-Acl `$_.FullName).Owner}},LastAccessTime,LastWriteTime,Length $(if($CheckWriteAccess){`"| where { `$_.FullName } | where { Invoke-CheckWrite -Path `$_.FullName }`"}) $(if($OutFile){`"| export-csv -Append -notypeinformation -path $OutFile`"})"

    # execute the command
    IEX $cmd
}

function Invoke-FileFinder {
    <#
    .SYNOPSIS
    Finds sensitive files on the domain.

    .DESCRIPTION
    This function finds the local domain name for a host using Get-NetDomain,
    queries the domain for all active machines with Get-NetComputers, grabs
    the readable shares for each server, and recursively searches every
    share for files with specific keywords in the name.
    If a share list is passed, EVERY share is enumerated regardless of
    other options.

    .PARAMETER HostList
    List of hostnames/IPs to search.

    .PARAMETER ShareList
    List if \\HOST\shares to search through.

    .PARAMETER Terms
    Terms to search for.

    .PARAMETER OfficeDocs
    Search for office documents (*.doc*, *.xls*, *.ppt*)

    .PARAMETER FreshEXES
    Find .EXEs accessed within the last week.

    .PARAMETER AccessDateLimit
    Only return files with a LastAccessTime greater than this date value.

    .PARAMETER WriteDateLimit
    Only return files with a LastWriteTime greater than this date value.

    .PARAMETER CreateDateLimit
    Only return files with a CreationDate greater than this date value.

    .PARAMETER IncludeC
    Include any C$ shares in recursive searching (default ignore).

    .PARAMETER IncludeAdmin
    Include any ADMIN$ shares in recursive searching (default ignore).

    .PARAMETER ExcludeFolders
    Exclude folders from the search results.

    .PARAMETER ExcludeHidden
    Exclude hidden files and folders from the search results.

    .PARAMETER CheckWriteAccess
    Only returns files the current user has write access to.

    .PARAMETER OutFile
    Output results to a specified csv output file.

    .PARAMETER Ping
    Ping each host to ensure it's up before enumerating.

    .PARAMETER Delay
    Delay between enumerating hosts, defaults to 0

    .PARAMETER Jitter
    Jitter for the host delay, defaults to +/- 0.3

    .PARAMETER Domain
    Domain to query for machines

    .EXAMPLE
    > Invoke-FileFinder
    Find readable files on the domain with 'pass', 'sensitive', 
    'secret', 'admin', 'login', or 'unattend*.xml' in the name,
    
    .EXAMPLE
    > Invoke-FileFinder -Domain testing
    Find readable files on the 'testing' domain with 'pass', 'sensitive', 
    'secret', 'admin', 'login', or 'unattend*.xml' in the name,
    
    .EXAMPLE
    > Invoke-FileFinder -IncludeC 
    Find readable files on the domain with 'pass', 'sensitive', 
    'secret', 'admin', 'login' or 'unattend*.xml' in the name, 
    including C$ shares.

    .EXAMPLE
    > Invoke-FileFinder -Ping -Terms payroll,ceo
    Find readable files on the domain with 'payroll' or 'ceo' in
    the filename and ping each machine before share enumeration.

    .EXAMPLE
    > Invoke-FileFinder -ShareList shares.txt -Terms accounts,ssn -OutFile out.csv
    Enumerate a specified share list for files with 'accounts' or
    'ssn' in the name, and write everything to "out.csv"

    .LINK
    http://www.harmj0y.net/blog/redteaming/file-server-triage-on-red-team-engagements/
    #>

    [CmdletBinding()]
    param(
        [string]$HostList = "",
        [string]$ShareList = "",
        [Parameter(Mandatory = $False)] [Switch] $OfficeDocs,
        [Parameter(Mandatory = $False)] [Switch] $FreshEXES,
        $Terms,
        $AccessDateLimit = "1/1/1970",
        $WriteDateLimit = "1/1/1970",
        $CreateDateLimit = "1/1/1970",
        [Parameter(Mandatory = $False)] [Switch] $IncludeC,
        [Parameter(Mandatory = $False)] [Switch] $IncludeAdmin,
        [Switch] $ExcludeFolders,
        [Switch] $ExcludeHidden,
        [Switch] $CheckWriteAccess,
        [string] $OutFile,
        [Parameter(Mandatory = $False)] [Switch] $Ping,
        [UInt32]$Delay = 0,
        [UInt32]$Jitter = .3,
        [string]$Domain
    )

    If ($PSBoundParameters['Debug']) {
        $DebugPreference = 'Continue'
    }

    # figure out the shares we want to ignore
    [String[]] $excludedShares = @("C$", "ADMIN$")

    # see if we're specifically including any of the normally excluded sets
    if ($IncludeC.IsPresent){
        if ($IncludeAdmin.IsPresent){
            $excludedShares = @()
        }
        else{
            $excludedShares = @("ADMIN$")
        }
    }
    if ($IncludeAdmin.IsPresent){
        if ($IncludeC.IsPresent){
            $excludedShares = @()
        }
        else{
            $excludedShares = @("C$")
        }
    }

     # delete any existing output file if it already exists
    If ($OutFile -and (Test-Path $OutFile)){ Remove-Item $OutFile }

    # if we are passed a share list, enumerate each with appropriate options, then return
    if($ShareList -ne ""){
        if (Test-Path $ShareList){
            foreach ($Item in Get-Content $ShareList) {
                if (($Item -ne $null) -and ($Item.trim() -ne "")){

                    # exclude any "[tab]- commants", i.e. the output from Invoke-ShareFinder
                    $share = $Item.Split("`t")[0]

                    # get just the share name from the full path
                    $shareName = $share.split("\")[3]

                    $cmd = "Invoke-SearchFiles -Path $share $(if($Terms){`"-Terms $($Terms -join ',')`"}) $(if($ExcludeFolders){`"-ExcludeFolders`"}) $(if($ExcludeHidden){`"-ExcludeHidden`"}) $(if($FreshEXES){`"-FreshEXES`"}) $(if($OfficeDocs){`"-OfficeDocs`"}) $(if($CheckWriteAccess){`"-CheckWriteAccess`"}) $(if($OutFile){`"-OutFile $OutFile`"})"

                    Write-Verbose "[*] Enumerating share $share"
                    IEX $cmd    
                }
            }
        }
        else {
            Write-Warning "`r`n[!] Input file '$ShareList' doesn't exist!`r`n"
            return $null
        }
        return
    }

    # random object for delay
    $randNo = New-Object System.Random

    # get the target domain
    if($Domain){
        $targetDomain = $Domain
    }
    else{
        # use the local domain
        $targetDomain = Get-NetDomain
    }

    Write-Verbose "[*] Running FileFinder on domain $targetDomain with delay of $Delay"

    # if we're using a host list, read the targets in and add them to the target list
    if($HostList -ne ""){
        $servers = @()
        if (Test-Path $HostList){
            foreach ($Item in Get-Content $HostList) {
                if (($Item -ne $null) -and ($Item.trim() -ne "")){
                    $servers += $Item
                }
            }
        }
        else {
            Write-Warning "`r`n[!] Input file '$HostList' doesn't exist!`r`n"
            return $null
        }
    }
    else{
        # otherwise, query the domain for target servers
        Write-Verbose "[*] Querying domain $targetDomain for hosts...`r`n"
        $servers = Get-NetComputers -Domain $targetDomain
    }

    # randomize the server list
    $servers = Get-ShuffledArray $servers

    if (($servers -eq $null) -or ($servers.Count -eq 0)){
        Write-Warning "`r`n[!] No hosts found!"
        return $null
    }
    else{

        # return/output the current status lines
        $counter = 0

        foreach ($server in $servers){

            $counter = $counter + 1

            Write-Verbose "[*] Enumerating server $server ($counter of $($servers.count))"

            # start a new status output array for each server
            $serverOutput = @()

            if ($server -ne ""){
                # sleep for our semi-randomized interval
                Start-Sleep $randNo.Next((1-$Jitter)*$Delay, (1+$Jitter)*$Delay)

                # optionally check if the server is up first
                $up = $true
                if($ping){
                    $up = Test-Server -Server $server
                }
                if($up){
                    # get the shares for this host and display what we find
                    $shares = Get-NetShare -HostName $server
                    foreach ($share in $shares) {
                        Write-Debug "[*] Server share: $share"
                        $netname = $share.shi1_netname
                        $remark = $share.shi1_remark
                        $path = "\\"+$server+"\"+$netname

                        # make sure we get a real share name back
                        if (($netname) -and ($netname.trim() -ne "")){
                            
                            # skip this share if it's in the exclude list
                            if ($excludedShares -notcontains $netname.ToUpper()){

                                # check if the user has access to this path
                                try{
                                    $f=[IO.Directory]::GetFiles($path)

                                    $cmd = "Invoke-SearchFiles -Path $path $(if($Terms){`"-Terms $($Terms -join ',')`"}) $(if($ExcludeFolders){`"-ExcludeFolders`"}) $(if($OfficeDocs){`"-OfficeDocs`"}) $(if($ExcludeHidden){`"-ExcludeHidden`"}) $(if($FreshEXES){`"-FreshEXES`"}) $(if($CheckWriteAccess){`"-CheckWriteAccess`"}) $(if($OutFile){`"-OutFile $OutFile`"})"

                                    Write-Verbose "[*] Enumerating share $path"

                                    IEX $cmd
                                }
                                catch {}

                            } 

                        }

                    }
                }

            }

        }
    }
}

function Convert-LDAPProperty {
    <#
    .SYNOPSIS

    Helper that converts specific LDAP property result fields and outputs
    a custom psobject.

    Author: Will Schroeder (@harmj0y)
    License: BSD 3-Clause
    Required Dependencies: None

    .DESCRIPTION

    Converts a set of raw LDAP properties results from ADSI/LDAP searches
    into a proper PSObject. Used by several of the Get-Net* function.

    .PARAMETER Properties

    Properties object to extract out LDAP fields for display.

    .OUTPUTS

    System.Management.Automation.PSCustomObject

    A custom PSObject with LDAP hashtable properties translated.
    #>

    [OutputType('System.Management.Automation.PSCustomObject')]
    [CmdletBinding()]
    Param(
        [Parameter(Mandatory = $True, ValueFromPipeline = $True)]
        [ValidateNotNullOrEmpty()]
        $Properties
    )

    $ObjectProperties = @{}

    $Properties.PropertyNames | ForEach-Object {
        if (($_ -eq 'objectsid') -or ($_ -eq 'sidhistory')) {
            # convert the SID to a string
            $ObjectProperties[$_] = (New-Object System.Security.Principal.SecurityIdentifier($Properties[$_][0], 0)).Value
        }
        elseif ($_ -eq 'objectguid') {
            # convert the GUID to a string
            $ObjectProperties[$_] = (New-Object Guid (,$Properties[$_][0])).Guid
        }
        elseif ($_ -eq 'ntsecuritydescriptor') {
            $ObjectProperties[$_] = New-Object Security.AccessControl.RawSecurityDescriptor -ArgumentList $Properties[$_][0], 0
        }
        elseif ( ($_ -eq 'lastlogon') -or ($_ -eq 'lastlogontimestamp') -or ($_ -eq 'pwdlastset') -or ($_ -eq 'lastlogoff') -or ($_ -eq 'badPasswordTime') ) {
            # convert timestamps
            if ($Properties[$_][0] -is [System.MarshalByRefObject]) {
                # if we have a System.__ComObject
                $Temp = $Properties[$_][0]
                [Int32]$High = $Temp.GetType().InvokeMember('HighPart', [System.Reflection.BindingFlags]::GetProperty, $null, $Temp, $null)
                [Int32]$Low  = $Temp.GetType().InvokeMember('LowPart',  [System.Reflection.BindingFlags]::GetProperty, $null, $Temp, $null)
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
                Write-Verbose $_
                [Int32]$High = $Temp.GetType().InvokeMember('HighPart', [System.Reflection.BindingFlags]::GetProperty, $null, $Temp, $null)
                [Int32]$Low  = $Temp.GetType().InvokeMember('LowPart',  [System.Reflection.BindingFlags]::GetProperty, $null, $Temp, $null)
                $ObjectProperties[$_] = [Int64]("0x{0:x8}{1:x8}" -f $High, $Low)
            }
            catch {
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

    New-Object -TypeName PSObject -Property $ObjectProperties
}

$Mod = New-InMemoryModule -ModuleName Win32

# all of the Win32 API functions we need
$FunctionDefinitions = @(
    (func netapi32 NetShareEnum ([Int]) @([string], [Int], [IntPtr].MakeByRefType(), [Int], [Int32].MakeByRefType(), [Int32].MakeByRefType(), [Int32].MakeByRefType())),
    (func netapi32 NetApiBufferFree ([Int]) @([IntPtr]))
)

# the NetShareEnum result structure
$SHARE_INFO_1 = struct $Mod SHARE_INFO_1 @{
    shi1_netname = field 0 String -MarshalAs @('LPWStr')
    shi1_type = field 1 UInt32
    shi1_remark = field 2 String -MarshalAs @('LPWStr')
}


$Types = $FunctionDefinitions | Add-Win32Type -Module $Mod -Namespace 'Win32'
$Netapi32 = $Types['netapi32']
