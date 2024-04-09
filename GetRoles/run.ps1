# // Custom Azure Function to enable custom Azure Active Directory authentication to bypass the built-in 25 user limit

# const fetch = require('node-fetch').default;

# // add role names to this object to map them to group ids in your AAD tenant
# const roleGroupMappings = {
#   'admin': '88563abb-31cd-4510-ba80-94323563c374', // CIPP Administrators
#   'editor': '6da6d947-0053-41e5-ae31-cab7bd33eb59', // CIPP Editors
#   'readonly': '8c68f6ec-11b2-4964-8789-be746a3f2f2b' // CIPP Read Only Users
# };

# module.exports = async function (context, req) {
#     const user = req.body || {};
#     const roles = [];

#     for (const [role, groupId] of Object.entries(roleGroupMappings)) {
#         if (await isUserInGroup(groupId, user.accessToken)) {
#             roles.push(role);
#         }
#     }

#     context.res.json({
#         roles
#     });
# }

# async function isUserInGroup(groupId, bearerToken) {
#     const url = new URL('https://graph.microsoft.com/v1.0/me/memberOf');
#     url.searchParams.append('$filter', `id eq '${groupId}'`);
#     const response = await fetch(url, {
#         method: 'GET',
#         headers: {
#             'Authorization': `Bearer ${bearerToken}`
#         },
#     });

#     if (response.status !== 200) {
#         return false;
#     }

#     const graphResponse = await response.json();
#     const matchingGroups = graphResponse.value.filter(group => group.id === groupId);
#     return matchingGroups.length > 0;
# }

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
    $response = Invoke-RestMethod -Uri $url -Headers $headers -Method Get

    if ($response.status -ne 200) {
        return $false
    }

    $matchingGroups = $response.value | Where-Object { $_.id -eq $GroupId }
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