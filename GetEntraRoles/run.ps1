<#PSScriptInfo
.VERSION 1.0.0
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
                    "rolesSource": "/api/GetEntraRoles",
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
                },
            ...
            ```
.LINK
    https://learn.microsoft.com/en-us/azure/static-web-apps/authentication-custom?tabs=aad%2Cfunction#configure-a-function-for-assigning-roles
#>

using namespace System.Net

param($Request, $TriggerMetadata)

function Test-UserInGroup {
    # Helper function for Graph API calls
    param(
        [string] $GroupId,
        [string] $BearerToken
    )

    # transitiveMemberOf looks through all nested group memberships
    $url = "https://graph.microsoft.com/v1.0/me/transitiveMemberOf?`$filter=id eq '$GroupId'&`$select=id"
    $headers = @{
        'Authorization' = "Bearer $BearerToken"
        'ConsistencyLevel' = 'eventual' # Required for certain advanced OData filters in Graph
    }

    try {
        # Using -ErrorAction Stop to ensure catch block triggers on 401/403
        $response = Invoke-RestMethod -Uri $url -Headers $headers -ErrorAction Stop

        # If any object is returned, the user has membership (direct or transitive)
        return ($response.value.Count -gt 0)
    } catch {
        # Log error to the Azure Function console for debugging
        Write-Error "Graph API Error: $_"
        return $false
    }
}

# Role to Group ID mappings (CIPP Role Name --> Entra Group ID)
$roleGroupMappings = @{
    # Only allowed to read and list items and send push messages to users
    readonly = '8c68f6ec-11b2-4964-8789-be746a3f2f2b'  # CIPP Read Only Users
    # Allowed to perform everything, except change system settings
    editor = '6da6d947-0053-41e5-ae31-cab7bd33eb59'  # CIPP Editors
    # Allowed to perform everything
    admin = '88563abb-31cd-4510-ba80-94323563c374'  # CIPP Administrators
    # A role that is only allowed to access the settings menu for specific high-privilege settings
    #superadmin = $null
}

# 1. Parse the user object from the request body
$user = $Request.Body
$accessToken = $user.accessToken
$roles = @()

# 2. Check group membership for each mapped role
if ($accessToken) {
    foreach ($thisRole in $roleGroupMappings.Keys) {
        $groupId = $roleGroupMappings[$thisRole]

        if (Test-UserInGroup -GroupId $groupId -BearerToken $accessToken) {
            $roles += $thisRole
        }
    }
}

# 3. Return the roles in the required JSON format
Push-OutputBinding -Name Response -Value ([HttpResponseContext]@{
        StatusCode = [HttpStatusCode]::OK
        Body = @{ roles = $roles }
        Headers = @{ 'Content-Type' = 'application/json' }
    })
