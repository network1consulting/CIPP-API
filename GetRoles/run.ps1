# Custom Azure Function to enable custom Azure Active Directory authentication to bypass the built-in 25 user limit

using namespace System.Net

Param ($Request, $TriggerMetadata)

# Define the role-group mappings
$roleGroupMappings = @{
    'admin' = '88563abb-31cd-4510-ba80-94323563c374' # CIPP Administrators
    'editor' = '6da6d947-0053-41e5-ae31-cab7bd33eb59' # CIPP Editors
    'readonly' = '8c68f6ec-11b2-4964-8789-be746a3f2f2b' # CIPP Read Only Users
}

# Define the function to check if a user is in a group
function Test-GroupMembership {
    Param ($GroupId, $AccessToken)

    $url = "https://graph.microsoft.com/v1.0/me/memberOf?`$filter=id eq '$GroupId'"
    $headers = @{
        'Authorization' = "Bearer $AccessToken"
    }

    try {
        $graphResponse = Invoke-WebRequest -Uri $url -Headers $headers -Method Get -UseBasicParsing
        if ($graphResponse.StatusCode -ne 200) { return $false }
    } catch {
        Write-Error $_.Exception.Message
        return $false
    }

    $matchingGroups = $graphResponse.value | Where-Object { $_.id -eq $GroupId }
    return ($matchingGroups.Count -gt 0)
}

# Define the main function
function Get-CustomAppRole {
    Param ($User)

    $roles = @()
    foreach ($entry in $roleGroupMappings.GetEnumerator()) {
        $role = $entry.Key
        $groupId = $entry.Value

        $isUserInGroup = Test-GroupMembership -GroupId $groupId -AccessToken $User.accessToken
        if ($isUserInGroup) {
            $roles += $role
        }
    }

    return @{ 'roles' = $roles }
}

# Call the main function with a test user
$rolesJson = Get-CustomAppRole -User $Request.Body | ConvertTo-Json -Compress

$response = ([HttpResponseContext] @{
    StatusCode = [HttpStatusCode]::OK
    Body = $rolesJson
    ContentType = 'application/json'
})

Push-OutputBinding -Name 'Response' -Value $response