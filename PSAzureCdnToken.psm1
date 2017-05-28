Add-Type -Path "$PSScriptRoot\ecencryptstdlib.dll"

<#
.SYNOPSIS
This function allows to create expiring CDN encryption tokens

.DESCRIPTION
https://docs.microsoft.com/en-us/azure/cdn/cdn-token-auth

.EXAMPLE
New-AzureCDNToken -Key 'Test' -ExpirationTimeSpan (New-TimeSpan -Days 1)
#>

function New-AzureCDNToken
{
    [CmdletBinding()]
    param(
        # Encyption Secret
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string] 
        $Key,
        
        # Timespan from UTCNow when token should expire
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [TimeSpan] 
        $ExpirationTimeSpan,
        
        # Restricts access to specified requester's IP address. Both IPV4 and IPV6 are supported. You can specify single request IP address or IP subnet Example: "13.141.12.2/20" 
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string] 
        $ClientIPAddress = $null,
        
        # Comma separated list or null, Example: "US,FR"
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string[]] 
        $AllowedCountries = $null,
        
        # Comma separated list of countries you want to block or null, Example: "US,FR"
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string[]] 
        $DeniedCountries = $null,
        
        # Comma separated list of allowed referrers , Example: "www.contoso.com,*.consoto.com,missing" 
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string[]] 
        $AllowedReferrers = $null,
        
        # Comma separated list of denied referrers , Example: "www.contoso.com,*.consoto.com,missing"
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string[]] 
        $DeniedReferrers = $null,
        
        # Only allows requests from specified protocol, Example: "http" or "https"
        [Parameter(Mandatory = $false)]
        [ValidateSet('http', 'https')]
        [string] 
        $AllowedProtocol = $null,
        
        # Denies requests from specified protocol, Example: "http" or "https"
        [Parameter(Mandatory = $false)]
        [ValidateSet('http', 'https')]
        [string] 
        $DeniedProtocol = $null,
        
        # Allows you to tailor tokens to a particular asset or path. It restricts access to requests whose URL start with a specific relative path. You can input multiple paths separating each path with a comma. URLs are case-sensitive. Depending on the requirement, you can set up different value to provide different level of access
        [Parameter(Mandatory = $false)]
        [ValidateNotNullOrEmpty()]
        [string[]] 
        $AllowedUrls = $null
    )    
    
    $tokenGenerator = New-Object -TypeName ecencryptstdlib.ECTokenGenerator

    [string]$cdnToken = $tokenGenerator.EncryptV3($Key,
        $ExpirationTimeSpan, 
        $ClientIPAddress, 
        $AllowedCountries -join ',', 
        $DeniedCountries -join ',',  
        $AllowedReferrers -join ',',  
        $DeniedReferrers -join ',', 
        $AllowedProtocol -join ',', 
        $DeniedProtocol -join ',', 
        $AllowedUrls -join ','
    )

    if ($cdnToken.Length -eq 0)
    {
        throw "Error encrypting token"
    }

    [PSCustomObject]@{Token = $cdnToken}
}

<#
.SYNOPSIS
Decrypts Azure CDN token

.DESCRIPTION
https://docs.microsoft.com/en-us/azure/cdn/cdn-token-auth

.EXAMPLE
Expand-AzureCDNToken -Key 'Test' -Token $token.Token

#>

function Expand-AzureCDNToken
{
    [CmdletBinding()]
    param(
        # Encyption Secret
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string] 
        $Key,
        
        # Token to dencrypt
        [Parameter(Mandatory = $true)]
        [ValidateNotNullOrEmpty()]
        [string] 
        $Token
    )
    
    $tokenGenerator = New-Object -TypeName ecencryptstdlib.ECTokenGenerator

    [string]$tokenProperties = $tokenGenerator.DecryptV3($Key, $Token, $true)

    if ($tokenProperties.Length -eq 0)
    {
        throw "Error decrypting token"
    }

    # Convert returning string into object
    [PSCustomObject]($tokenProperties -replace '&',[System.Environment]::NewLine|ConvertFrom-StringData)
    
}




