function Test-Condition
{
    param
    (
        [Parameter(Mandatory = $true)]
        [bool]
        $Result,

        [Parameter(Mandatory = $true)]
        [string]
        $Message
    )

    if( $Result )
    {
        Write-Success -Message $Message
    }
    else
    {
        Write-Fail -Message $Message
    }
}

function Write-Context
{
    param
    (
        [Parameter(Mandatory = $true)]
        [string]
        $Message
    )

    Write-Host "  Context: $($Message)" -ForegroundColor Magenta
}

function Write-Success
{
    param
    (
        [Parameter(Mandatory = $true)]
        [string]
        $Message
    )

    Write-Host "    [+] $($Message)" -ForegroundColor Green
}

function Write-Fail
{
    param
    (
        [Parameter(Mandatory = $true)]
        [string]
        $Message
    )

    Write-Host "    [-] $($Message)" -ForegroundColor Red
}

function Test-KerberosTicketGrantingTicket
{
    param
    (
        [Parameter(Mandatory = $true, ValueFromPipeline = $true)]
        [psobject]
        $Ticket
    )

    process
    {
        foreach($ticket in $Ticket)
        {
            Write-Host -ForegroundColor Magenta "Describing Ticket Granting Ticket (TGT)"
            Write-Context -Message 'Encryption Type'
            Test-Condition -Result ($ticket.SessionKeyType -eq 'aes256_cts_hmac_sha1_96') -Message 'should be aes256_cts_hmac_sha1_96'

            Write-Context -Message 'Ticket Validity'
            Test-Condition -Result (($ticket.EndTime - $ticket.StartTime).TotalHours -le 10) -Message 'should be valid for 10 hours'
            Test-Condition -Result (($ticket.RenewUntil - $ticket.StartTime).TotalDays -le 8) -Message 'should renew for approx. 7 days'

            Write-Context -Message 'Ticket Client (User)'
            Test-Condition -Result ($ticket.ClientName -eq $ticket.SessionUserName) -Message 'should match the Session User Name'
            if($ticket.SessionUserPrincipalName -ne '')
            {
                Test-Condition -Result ("$($ticket.ClientName)@$($ticket.DomainName)" -eq $ticket.SessionUserPrincipalName) -Message 'should match the Session User Principal Name'
            }

            Write-Context -Message 'Session Authentication Package'
            if($ticket.SessionLogonId -eq 999 -or $ticket.SessionLogonId -eq 996)
            {
                Test-Condition -Result ($ticket.SessionAuthenticationPackage -eq 'Negotiate') -Message 'should be Negotiate'
            }
            else
            {
                Test-Condition -Result ($ticket.SessionAuthenticationPackage -eq 'Kerberos') -Message 'should be Kerberos'
            }

            Write-Output $ticket
        }
    }
}