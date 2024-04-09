// Custom Azure Function to enable custom Azure Active Directory authentication to bypass the built-in 25 user limit

const fetch = require('node-fetch').default;

// add role names to this object to map them to group ids in your AAD tenant
const roleGroupMappings = {
  'admin': '88563abb-31cd-4510-ba80-94323563c374', // CIPP Administrators
  'editor': '6da6d947-0053-41e5-ae31-cab7bd33eb59', // CIPP Editors
  'readonly': '8c68f6ec-11b2-4964-8789-be746a3f2f2b' // CIPP Read Only Users
};

module.exports = async function (context, req) {
    const user = req.body || {};
    const roles = [];

    for (const [role, groupId] of Object.entries(roleGroupMappings)) {
        if (await isUserInGroup(groupId, user.accessToken)) {
            roles.push(role);
        }
    }

    context.res.json({
        roles
    });
}

async function isUserInGroup(groupId, bearerToken) {
    const url = new URL('https://graph.microsoft.com/v1.0/me/memberOf');
    url.searchParams.append('$filter', `id eq '${groupId}'`);
    const response = await fetch(url, {
        method: 'GET',
        headers: {
            'Authorization': `Bearer ${bearerToken}`
        },
    });

    if (response.status !== 200) {
        return false;
    }

    const graphResponse = await response.json();
    const matchingGroups = graphResponse.value.filter(group => group.id === groupId);
    return matchingGroups.length > 0;
}
