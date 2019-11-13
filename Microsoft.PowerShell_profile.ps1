## Connect to Office 365 Exchange Tenant ##
function Connect-ExchangeOnline()
{
  $UserCredential = Get-Credential
  $Session = New-PSSession -ConfigurationName Microsoft.Exchange -ConnectionUri https://outlook.office365.com/powershell-liveid/ -Credential $UserCredential -Authentication Basic -AllowRedirection
  Import-PSSession $Session -DisableNameChecking
}

function Connect-ExchangeOnlineModern ($account)
{
    Connect-EXOPSSession -UserPrincipalName $account
}

function Connect-SkypeForBusiness ($userCredential)
{
    Import-Module SkypeOnlineConnector
    $userCredential = Get-Credential
    $sfbSession = New-CsOnlineSession -Credential $userCredential
    Import-PSSession $sfbSession
}

## Modern Auth Enablements ##
function Exchange-ModernAuthStatus()
{
    Get-OrganizationConfig | Format-Table -Auto Name,OAuth*
}

function Exchange-EnableModernAuth() 
{
    Set-OrganizationConfig -OAuth2ClientProfileEnabled $true
}

function Skype-ModernAuthStatus()
{
    Get-CsOAuthConfiguration | Format-Table -auto Identity,ClientAdalAuthOverride
}

function Skype-EnableModernAuth() 
{
    Set-CsOAuthConfiguration -ClientAdalAuthOverride Allowed
}

function Clear-Session()
{
    Get-PSSession | Remove-PSSession
}

####################################################
# Creates an authentication policy for             #
# O365 user accounts. Creates the policy and sets  #
# authentication policy as the O365 tenant default #
####################################################
function CreatePolicy-BlockBasicAuth() {
    ## Create new policy ##
    New-AuthenticationPolicy -Name "Block Basic Auth" 
}

####################################################
# Creates a separate authentication policy for     #
# O365 admin account. Create the policy and then   #
# applies that policy to the administrator account #
# specified in function paramater.                 #
####################################################
function CreatePolicy-BasicAuthPS($AdminAccount) {
    ## Create new policy ##
    New-AuthenticationPolicy -Name "Allow Powershell"
    ## Set authentication policy to allow Basic Auth ONLY for Powershell ##
    Set-AuthenticationPolicy "Allow Powershell" -AllowBasicAuthPowershell
    ## Apply authentication policy to admin account specified in function parameter ##
    Set-User -Identity $AdminAccount -AuthenticationPolicy "Allow Powershell"
}

####################################################
# Creates a separate authentication policy for     #
# scan to email accounts. Creates the policy and   #
# applies that policy to the print/scanner account #
# specified in function paramater.                 #
####################################################
function CreatePolicy-BasicAuthSMTP($PrinterAccount) {
    ## Create new policy, blocks all Basic Auth protocols ##
    New-AuthenticationPolicy -Name "Allow SMTP"
    ## Allows basic auth for SMTP for scan to email ##
    Set-AuthenticationPolicy "Allow SMTP" -AllowBasicAuthSMTP
    ## Applies authentication policy to print/scanner account speicifed in function paramter ##
    Set-User -Identity $PrinterAccount -AuthenticationPolicy "Allow SMTP"
}

####################################################
# Takes a in a text file containing a list         #
# of all users to apply the policy to.             #
# Text file must contain user UPNs, no spaces      #
# with one user account on each line               #
####################################################
function DisableBasicAuth($filename) {
    ## Takes in the filename specified in function paramater ##
    $userlist = Get-Content $filename
    ## Disables basic authentication for all users specified in text file ##
    $userlist | foreach {Set-User -Identity $_ -AuthenticationPolicy "Block Basic Auth"}
    ## Applies the policy immediately to specified users ##
    $userlist | foreach {Set-User -Identity $_ -STSRefreshTokensValidFrom $([System.DateTime]::UtcNow)}
}

function SetDefaultAuthPolicy($policy) {
    ## Set polciy specified in function paramater as tenant default ##
    Set-OrganizationConfig -DefaultAuthenticationPolicy $policy
}

function ViewBasicAuthPolicy() {
    Get-AuthenticationPolicy -Identity "Block Basic Auth"
}

function ViewAuthPolicies() {
    Get-AuthenticationPolicy | Format-Table Name -Auto
}

function RemoveMembership($user) {
    if (-not (Get-Module ActiveDirectory)){
        Import-Module ActiveDirectory -ErrorAction Stop
    }
    Write-host `n... $user is member of these AD Groups -fore Yellow
    Get-ADPrincipalGroupMembership -Identity  $user | Format-Table -Property name
    Write-host ...Removing the Group Membership -fore DarkYellow
    $ADGroups = Get-ADPrincipalGroupMembership -Identity  $user | where {$_.Name -ne "Domain Users"}
    Remove-ADPrincipalGroupMembership -Identity  $user -MemberOf $ADGroups -Confirm:$false -verbose
}

function CreateVPNProfile(){
    $Name = Read-Host "Enter Client VPN Name"
    $ServerAddress = Read-Host "Enter the IP Address/hostname of the VPN client"
    $Secret = Read-Host "Enter the client secret to establish the connection"
    Add-VpnConnection -Name $Name -ServerAddress $ServerAddress -TunnelType L2tp -EncryptionLevel Optional -L2tpPsk $Secret -AuthenticationMethod Pap -Force
}

function KB4-Whitelist() {
    New-TransportRule -Name "KnowBe4 IP Address Whitelist" -SenderIPRanges 23.21.109.197,23.21.109.212,147.160.167.0/24,52.144.62.2 -setheadername "X-MS-Exchange-Organization-BypassClutter" -SetHeaderValue "true" -setscl "-1" -Priority 0 -Comments "Rev 10/10/2019 Added by Worksighted to bypass filtering for KnowBe4 and Worksighted Emails by IP address"
    Write-host "`nCreated rule: KnowBe4 IP Address Whitelist`n"
    New-TransportRule -Name "KnowBe4 Skip Junk Filtering" -SenderIPRanges 23.21.109.197,23.21.109.212,147.160.167.0/24,52.144.62.2 -setheadername "X-Forefront-Antispam-Report" -SetHeaderValue "SKV:SKI;" -Priority 1 -Comments "Rev 10/10/2019 Added by Worksighted to bypass Junk folder for KnowBe4 and Worksighted emails by IP address"
    Write-host "`nCreated rule: KnowBe4 Skip Junk Filtering`n"
    New-TransportRule -Name "KnowBe4 Bypass Clutter & Spam - Header" -HeaderContainsMessageHeader "X-PHISHTEST" -HeaderContainsWords "KnowBe4" -setheadername "X-MS-Exchange-Organization-BypassClutter" -SetHeaderValue "true" -setscl "-1" -priority 2 -Comments "Rev 10/10/2019 Added by Worksighted to bypass spam filtering for KnowBe4 Emails by header"
    Write-host "`nCreated rule: KnowBe4 Bypass Clutter & Spam - Header`n"
    New-TransportRule -Name "KnowBe4 Skip Junk Filtering - Header" -HeaderContainsMessageHeader "X-PHISHTEST" -HeaderContainsWords "KnowBe4" -setheadername "X-Forefront-Antispam-Report" -SetHeaderValue "SKV:SKI;" -priority 3 -Comments "Rev 10/10/2019 Added by Worksighted to bypass Junk folder for KnowBe4 emails by header"
    Write-host "`nCreated rule: KnowBe4 Skip Junk Filtering - Header`n"
    New-TransportRule -Name "KnowBe4 Skip ATP Attachment Scanning - IP Address" -SenderIPRanges 23.21.109.197,23.21.109.212,147.160.167.0/24,52.144.62.2 -setheadername X-MS-Exchange-Organization-SkipSafeAttachmentProcessing -SetHeaderValue "1" -Priority 4 -Comments "Rev 10/10/2019 Added by Worksighted to bypass ATP Attachment Scanning for KnowBe4 emails by IP address"
    Write-host "`nCreated rule: KnowBe4 Skip ATP Attachment Scanning - IP Address`n"
    New-TransportRule -Name "ATP Link Inspection Bypass" -SenderIPRanges 23.21.109.197,23.21.109.212,147.160.167.0/24,52.144.62.2 -setheadername "X-MS-Exchange-Organization-SkipSafeLinksProcessing" -SetHeaderValue 1 -Priority 5 -Comments "Rev 10/10/2019 Added by Worksighted to exclude certain emails from Link Scanning"
    Write-host "`nCreated rule: KnowBe4 ATP Link Inspection Bypass`n"
    Set-HostedConnectionFilterPolicy "Default" -IPAllowList @{Add="23.21.109.197","23.21.109.212","147.160.167.0/24"}
    Write-host "`nAdded KnowBe4 IPs to Default Connection Filter Policy`n"
}
