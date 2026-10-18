import os
import msal
import requests
from dotenv import load_dotenv

load_dotenv()

TENANT_ID = os.getenv("PEARSON_TENANT_ID")
CLIENT_ID = os.getenv("PEARSON_CLIENT_ID")
CLIENT_SECRET = os.getenv("PEARSON_CLIENT_SECRET")
GRAPH = "https://graph.microsoft.com/v1.0"
GLOBAL_ADMIN_TEMPLATE = "62e90394-69f5-4237-9190-012177145e10"


def get_token() -> str:
    app = msal.ConfidentialClientApplication(
        CLIENT_ID,
        authority=f"https://login.microsoftonline.com/{TENANT_ID}",
        client_credential=CLIENT_SECRET,
    )
    result = app.acquire_token_for_client(
        scopes=["https://graph.microsoft.com/.default"]
    )
    if "access_token" not in result:
        raise RuntimeError(result.get("error_description", result))
    return result["access_token"]


def graph_get(path: str) -> list:
    """GET a Graph path and follow paging."""
    headers = {"Authorization": f"Bearer {get_token()}"}
    url, items = f"{GRAPH}{path}", []
    while url:
        r = requests.get(url, headers=headers, timeout=30)
        r.raise_for_status()
        data = r.json()
        items += data.get("value", [])
        url = data.get("@odata.nextLink")
    return items


def get_users():
    return graph_get(
        "/users?$select=displayName,userPrincipalName,userType,accountEnabled"
    )


def get_global_admins():
    return graph_get(
        f"/directoryRoles(roleTemplateId='{GLOBAL_ADMIN_TEMPLATE}')/members"
    )


def get_ca_policies():
    return graph_get("/identity/conditionalAccess/policies")

#############################
def get_guests():
    return graph_get("/users?$filter=userType eq 'Guest'&$select=displayName,userPrincipalName")


def get_mfa_status():
    return graph_get(
        "/reports/authenticationMethods/userRegistrationDetails"
        "?$select=userPrincipalName,isMfaRegistered,isAdmin"
    )


def get_service_principals():
    return graph_get("/servicePrincipals?$select=displayName,appId,servicePrincipalType")

def check_legacy_auth_blocked():
    """True if an enabled CA policy blocks legacy clients for all users."""
    for p in get_ca_policies():
        cond = p.get("conditions", {})
        grant = p.get("grantControls") or {}
        legacy = {"exchangeActiveSync", "other"} <= set(cond.get("clientAppTypes", []))
        blocks = "block" in grant.get("builtInControls", [])
        all_users = "All" in cond.get("users", {}).get("includeUsers", [])
        if p.get("state") == "enabled" and legacy and blocks and all_users:
            return {"blocked": True, "policy": p["displayName"]}
    return {"blocked": False, "policy": None}

GRAPH_APP_ID = "00000003-0000-0000-c000-000000000000"
HIGH_RISK = {
    "RoleManagement.ReadWrite.Directory", "Directory.ReadWrite.All",
    "Application.ReadWrite.All", "AppRoleAssignment.ReadWrite.All",
    "User.ReadWrite.All", "Group.ReadWrite.All", "Mail.ReadWrite",
    "Files.ReadWrite.All", "Policy.ReadWrite.ConditionalAccess",
}


def get_risky_service_principals():
    """Own-tenant service principals holding high-risk Graph app permissions."""
    graph_sp = graph_get(
        f"/servicePrincipals?$filter=appId eq '{GRAPH_APP_ID}'&$select=id,appRoles"
    )[0]
    role_names = {r["id"]: r["value"] for r in graph_sp["appRoles"]}

    sps = graph_get(
        "/servicePrincipals?$select=id,displayName,appId,appOwnerOrganizationId,"
        "passwordCredentials,keyCredentials"
    )
    findings = []
    for sp in sps:
        if sp.get("appOwnerOrganizationId") != TENANT_ID:
            continue  # skip Microsoft and third-party apps
        assigns = graph_get(f"/servicePrincipals/{sp['id']}/appRoleAssignments")
        perms = [role_names.get(a["appRoleId"], a["appRoleId"])
                 for a in assigns if a["resourceId"] == graph_sp["id"]]
        risky = sorted(set(perms) & HIGH_RISK)
        if risky:
            findings.append({
                "name": sp["displayName"],
                "appId": sp["appId"],
                "risky_permissions": risky,
   
                "secrets": len(sp.get("passwordCredentials", [])),
                "certificates": len(sp.get("keyCredentials", [])),
            })
    return findings

def check_admin_mfa_policy():
    """Is there an enabled CA policy requiring MFA for all users or Global Admins?"""
    for p in get_ca_policies():
        if p.get("state") != "enabled":
            continue
        grant = p.get("grantControls") or {}
        needs_mfa = "mfa" in grant.get("builtInControls", []) or grant.get("authenticationStrength")
        users = p.get("conditions", {}).get("users", {})
        covers_all = "All" in users.get("includeUsers", [])
        covers_admins = GLOBAL_ADMIN_TEMPLATE in users.get("includeRoles", [])
        if needs_mfa and (covers_all or covers_admins):
            return {"covered": True, "policy": p["displayName"]}
    return {"covered": False, "policy": None}

def get_security_defaults():
    r = requests.get(
        f"{GRAPH}/policies/identitySecurityDefaultsEnforcementPolicy",
        headers={"Authorization": f"Bearer {get_token()}"}, timeout=30,
    )
    r.raise_for_status()
    return {"security_defaults_enabled": r.json().get("isEnabled")}

def get_user_owned_objects(upn: str):
    user = graph_get(f"/users/{upn}")
    # Graph SDK-style owned objects isn't a plain GET path; use directoryObjects
    return graph_get(f"/users/{upn}/ownedObjects")

def get_sp_role_assignments(sp_id: str):
    """What app roles a service principal has been granted on other resources, and who/what holds roles on it."""
    return {
        "granted_to_this_sp": graph_get(f"/servicePrincipals/{sp_id}/appRoleAssignments"),
        "assigned_on_this_sp": graph_get(f"/servicePrincipals/{sp_id}/appRoleAssignedTo"),
        "oauth2_grants": graph_get(f"/oauth2PermissionGrants?$filter=clientId eq '{sp_id}'"),
    }
    
def get_user_owned_devices(upn: str):
    return graph_get(f"/users/{upn}/ownedDevices?$select=displayName,deviceId,operatingSystem,trustType,accountEnabled")

def get_user_owned_groups(upn: str):
    return graph_get(f"/users/{upn}/ownedObjects/microsoft.graph.group?$select=displayName,id")

def get_sp_directory_roles(sp_id: str):
    assignments = graph_get(f"/roleManagement/directory/roleAssignments?$filter=principalId eq '{sp_id}'&$expand=roleDefinition")
    return [a["roleDefinition"]["displayName"] for a in assignments]

def get_role_members(role_name: str):
    """List users and service principals holding a given directory role, by role display name."""
    roles = graph_get(f"/roleManagement/directory/roleDefinitions?$filter=displayName eq '{role_name}'")
    if not roles:
        return {"error": f"No role found named '{role_name}'"}
    role_id = roles[0]["id"]
    assignments = graph_get(
        f"/roleManagement/directory/roleAssignments?$filter=roleDefinitionId eq '{role_id}'&$expand=principal"
    )
    return [
        {
            "name": a["principal"].get("displayName") or a["principal"].get("appId"),
            "type": a["principal"].get("@odata.type", "").split(".")[-1],
            "id": a["principal"]["id"],
        }
        for a in assignments
    ]
    
############################


if __name__ == "__main__":
    print("Users:", len(get_users()))
    print("Global Admins:", [a["userPrincipalName"] for a in get_global_admins()])
    print("CA policies:", [p["displayName"] for p in get_ca_policies()])