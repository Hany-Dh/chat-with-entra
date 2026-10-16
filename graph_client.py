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
#############################


if __name__ == "__main__":
    print("Users:", len(get_users()))
    print("Global Admins:", [a["userPrincipalName"] for a in get_global_admins()])
    print("CA policies:", [p["displayName"] for p in get_ca_policies()])