<#PSScriptInfo
.VERSION 1.0.5
.GUID 785aef2a-8a16-4183-896b-851d9872bfab
.AUTHOR Network 1 Consulting
.COMPANYNAME Network 1 Consulting
.COPYRIGHT (c) Network 1 Consulting. All rights reserved.
.DESCRIPTION
    This is a custom function used to retrieve a user's Entra roles when they log into CIPP.
    This function is required to facilitate group-based role assignment in CIPP.

    The default invite-based authentication method also has a user limit and setting up custom authentication allows
    us to bypass that limit.

    This function is only part of the overall implementation. Other elements of the configuration can be found in the
    following locations:

        CIPP Static Web App:
            Settings:
                Authentication:
                    # This enables custom authentication and tells the SWA where this "GetRoles" function is
                    - Mode: Custom
                    - API Path: /api/GetEntraRoles
                Environment variables:
                    # These variables match placeholder names in the CIPP SWA's staticwebapp.config.json file
                    - AZURE_CLIENT_ID=<< Custom Entra App's client ID >>
                    - AZURE_CLIENT_SECRET=<< Custom Entra App's client secret >>

        Entra Admin Portal:
            App Registrations:
                Register an application:
                    Name: CIPP-CustomAADAuth
                    Supported Account Type: Single tenant
                    Redirect Uri: [Web] https://<CIPP_DOMAIN>/.auth/login/aad/callback
                CIPP-CustomAADAuth:
                    Manage:
                        Authentication:
                            Implicit grant and hybrid flows:
                                ID Tokens: true
                        Certificates & secrets:
                            New client secret:
                                - Set value for AZURE_CLIENT_SECRET SWA environment variable

        network1-admin @ https://github.com/network1consulting/CIPP/blob/main/staticwebapp.config.json:
            Add "auth" property to root object (just inside the open brace at the top of the file):
            ```
            {
                "auth": {
                    "rolesSource": "/api/auth/GetEntraRoles",
                    "identityProviders": {
                        "azureActiveDirectory": {
                            "registration": {
                                "openIdIssuer": "https://login.microsoftonline.com/<INTERNAL_TENANT_ID>/v2.0",
                                "clientIdSettingName": "AZURE_CLIENT_ID",
                                "clientSecretSettingName": "AZURE_CLIENT_SECRET"
                            },
                            "login": {
                                "loginParameters": [
                                    "resource=https://graph.microsoft.com"
                                ]
                            }
                        }
                    }
            }, ...
            ```
.LINK
    https://learn.microsoft.com/en-us/azure/static-web-apps/authentication-custom?tabs=aad%2Cfunction#configure-a-function-for-assigning-roles
#>

using namespace System.Net

param($Request, $TriggerMetadata)

########################################################################################################################
# Role to Group ID Mappings (CIPP Role Name --> Entra Group ID)
########################################################################################################################

$roleGroupMappings = @{
    # CIPP Read Only Users: Only allowed to read and list items and send push messages to users
    readonly = '8c68f6ec-11b2-4964-8789-be746a3f2f2b'
    # CIPP Editors: Allowed to perform everything, except change system settings
    editor = '6da6d947-0053-41e5-ae31-cab7bd33eb59'
    # CIPP Administrators: Allowed to perform everything
    admin = '88563abb-31cd-4510-ba80-94323563c374'
    # No Group: A role that is only allowed to access the settings menu for specific high-privilege settings
    #superadmin = $null
}

########################################################################################################################
# FUNCTIONS
########################################################################################################################

function Test-UserInGroup {
    # Helper function for Graph API calls
    param (
        [string] $GroupId,
        [string] $BearerToken
    )

    # transitiveMemberOf looks through all nested group memberships without returning non-group object types.
    #   Unless additional permissions are added to our app registration, you will see a Graph API permissions error
    #   without including "@odata.type eq '#microsoft.graph.group'" in the query filter.
    $baseUrl = 'https://graph.microsoft.com/v1.0'
    $url = "$baseUrl/me/transitiveMemberOf/microsoft.graph.group?`$count=true&`$filter=id eq '$GroupId'&`$select=id"
    $headers = @{
        'Authorization' = "Bearer $BearerToken"
        'ConsistencyLevel' = 'eventual' # Required for advanced filters
    }

    try {
        # Using -ErrorAction Stop to ensure catch block triggers on 401/403
        $response = Invoke-RestMethod -Uri $url -Headers $headers -ContentType 'application/json' -ErrorAction Stop

        # If any object is returned, the user has membership (direct or transitive)
        return ($response.value.Count -gt 0)
    } catch {
        if ($_.Exception.Message -match 'Request_ResourceNotFound') {
            Write-Warning "Group '$GroupId' not found: $_"
        } else {
            # Log error to the Azure Function console for debugging
            Write-Error "Graph API call failed: $_"
        }
        return $false
    }
}

function ConvertFrom-Jwt {
    [CmdletBinding()]
    param (
        [Parameter(Mandatory)]
        [ValidateScript({
                # Validate according to https://tools.ietf.org/html/rfc7519 (access and ID tokens only)
                if (! $_.Contains('.') -or ! $_.StartsWith('eyJ') ) { throw 'Invalid token' }
                return $true
            })]
        [string] $Token
    )

    $payload = $Token.Split('.')[1].Replace('-', '+').Replace('_', '/')
    # Fix padding as needed, keep adding "=" until string length modulus 4 reaches 0
    while ($payload.Length % 4) {
        # Invalid length for a Base-64 char array or string, adding =
        $payload += '='
    }
    $byteArray = [System.Convert]::FromBase64String($payload)
    $jsonString = [System.Text.Encoding]::ASCII.GetString($byteArray)
    $convertedToken = $jsonString | ConvertFrom-Json

    $header = $Token.Split('.')[0].Replace('-', '+').Replace('_', '/')
    # Fix padding as needed, keep adding "=" until string length modulus 4 reaches 0
    while ($header.Length % 4) {
        # Invalid length for a Base-64 char array or string, adding =
        $header += '='
    }

    # Append metadata containing header and conversions for ease of use
    $metadata = [pscustomobject] @{
        Header = [System.Text.Encoding]::ASCII.GetString([System.Convert]::FromBase64String($header)) | ConvertFrom-Json
        ExpiresAt = Get-Date -UnixTimeSeconds $convertedToken.exp
    }
    $convertedToken | Add-Member -MemberType NoteProperty -Name '_metadata' -Value $metadata

    return $convertedToken
}

########################################################################################################################
# MAIN
########################################################################################################################

# 1. Parse the user object from the request body
$user = $Request.Body
$roles = @()

$hasAccessToken = $false
if ($user.accessToken) {
    if ($user.accessToken -match '\.') {
        $jwt = ConvertFrom-Jwt -Token $user.accessToken -ErrorAction SilentlyContinue
    }

    if ($jwt) {
        $hasAccessToken = $true
        $upn = $jwt.upn
        $ipaddr = $jwt.ipaddr
        $ver = $jwt.ver
        Write-Information "[GetEntraRoles] SUCCESS: Valid JWT (v$ver) detected from IP '$ipaddr' for user '$upn' with scopes '$($jwt.scp)'"
    } else {
        Write-Warning "[GetEntraRoles] Invalid JWT detected with a length of '$($user.accessToken.Length)'"
    }
} else {
    Write-Warning '[GetEntraRoles] No access token found in the request body'
}

# Extract groups from the claims (since they are already present in the request body)
$userGroups = $user.claims | Where-Object { $_.typ -eq 'groups' } | Select-Object -ExpandProperty val
Write-Information "[GetEntraRoles] Found $($userGroups.Count) group claims in the request body. Checking membership..."

# 2. Check group membership
foreach ($thisRole in $roleGroupMappings.Keys) {
    $targetGroupId = $roleGroupMappings[$thisRole]

    # Check if the group is in the claims OR check via Graph for transitive support
    if ($userGroups -contains $targetGroupId) {
        $roles += $thisRole
    } elseif ($hasAccessToken -and (Test-UserInGroup -GroupId $targetGroupId -BearerToken $user.accessToken)) {
        $roles += $thisRole
    }
}

Write-Information "[GetEntraRoles] Matched $($roles.Count) roles"

# 3. Return the roles in the required JSON format
Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
        StatusCode = [HttpStatusCode]::OK
        Body = @{ roles = $roles }
        Headers = @{ 'Content-Type' = 'application/json' }
    })
