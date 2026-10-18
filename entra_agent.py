import os, json
from dotenv import load_dotenv
from openai import AzureOpenAI
import graph_client as g

load_dotenv()
client = AzureOpenAI(
    azure_endpoint=os.getenv("AZURE_OPENAI_ENDPOINT"),
    api_key=os.getenv("AZURE_OPENAI_KEY"),
    api_version="2025-04-01-preview",
)
MODEL = os.getenv("AZURE_OPENAI_DEPLOYMENT")

SYSTEM_PROMPT = (
    "You are an Entra ID security analyst. Answer only from tool results, never guess. "
    "If a tool errors, say so. For each finding explain why it is a risk and how to fix it."
    "Report every finding as: Finding, Risk, Fix, Severity (High/Medium/Low). "
    "Before reporting missing Conditional Access coverage, call get_security_defaults, "
    "since Security Defaults also enforce MFA and block legacy authentication."
)

def to_json(data, limit=12000):
    text = json.dumps(data, default=str)
    return text if len(text) <= limit else text[:limit] + '..."[truncated]"'

def admins_without_mfa():
    return [m["userPrincipalName"] for m in g.get_mfa_status()
            if m["isAdmin"] and not m["isMfaRegistered"]]

# name -> (function, description)
REGISTRY = {
    "get_users": (g.get_users, "List all users in the tenant."),
    "get_guests": (g.get_guests, "List guest (external) users."),
    "get_global_admins": (g.get_global_admins, "List members of the Global Administrator role."),
    "get_ca_policies": (g.get_ca_policies, "List Conditional Access policies."),
    "get_admins_without_mfa": (admins_without_mfa, "List admins with no MFA registered."),
    "get_service_principals": (g.get_service_principals, "List service principals."),
    "check_legacy_auth_blocked": (g.check_legacy_auth_blocked, "Check whether legacy authentication is blocked by Conditional Access."),
    "get_risky_service_principals": (g.get_risky_service_principals, "List own-tenant service principals holding high-risk Graph permissions."),
    "check_admin_mfa_policy": (g.check_admin_mfa_policy, "Check whether a Conditional Access policy requires MFA for admins."),
    "get_security_defaults": (g.get_security_defaults, "Check whether Security Defaults are enabled."),
    "get_user_owned_objects": (lambda upn="david.martinez@wwlx961259.onmicrosoft.com": g.get_user_owned_objects(upn), "List objects owned by a given user (by UPN)."),
    "get_sp_role_assignments": (g.get_sp_role_assignments, "Get app role assignments and OAuth2 grants for a service principal by its object id."),
    "get_user_owned_devices": (g.get_user_owned_devices, "List devices owned by a given user, by UPN."),
    "get_user_owned_groups": (g.get_user_owned_groups, "List groups owned by a given user, by UPN."),
    "get_sp_directory_roles": (g.get_sp_directory_roles, "List directory roles a service principal is a member of, by its object id."),
    "get_role_members": (g.get_role_members, "List users and service principals holding a given directory role, by role display name."),
    
}

CUSTOM_SCHEMA_TOOLS = {
    "get_sp_role_assignments", "get_user_owned_devices",
    "get_user_owned_groups", "get_sp_directory_roles", "get_role_members",
    
}

tools = [{
    "type": "function",
    "function": {
        "name": name, "description": desc,
        "parameters": {"type": "object", "properties": {}},
    },
} for name, (_, desc) in REGISTRY.items() if name not in CUSTOM_SCHEMA_TOOLS]

tools.append({
    "type": "function",
    "function": {
        "name": "get_sp_role_assignments",
        "description": REGISTRY["get_sp_role_assignments"][1],
        "parameters": {
            "type": "object",
            "properties": {
                "sp_id": {"type": "string", "description": "The service principal's object id (not appId)."}
            },
            "required": ["sp_id"],
        },
    },
})

tools.append({
    "type": "function",
    "function": {
        "name": "get_user_owned_devices",
        "description": REGISTRY["get_user_owned_devices"][1],
        "parameters": {
            "type": "object",
            "properties": {
                "upn": {"type": "string", "description": "User principal name, e.g. david.martinez@wwlx961259.onmicrosoft.com"}
            },
            "required": ["upn"],
        },
    },
})

tools.append({
    "type": "function",
    "function": {
        "name": "get_user_owned_groups",
        "description": REGISTRY["get_user_owned_groups"][1],
        "parameters": {
            "type": "object",
            "properties": {
                "upn": {"type": "string", "description": "User principal name, e.g. david.martinez@wwlx961259.onmicrosoft.com"}
            },
            "required": ["upn"],
        },
    },
})

tools.append({
    "type": "function",
    "function": {
        "name": "get_sp_directory_roles",
        "description": REGISTRY["get_sp_directory_roles"][1],
        "parameters": {
            "type": "object",
            "properties": {
                "sp_id": {"type": "string", "description": "The service principal's object id (not appId)."}
            },
            "required": ["sp_id"],
        },
    },
})

tools.append({
    "type": "function",
    "function": {
        "name": "get_role_members",
        "description": REGISTRY["get_role_members"][1],
        "parameters": {
            "type": "object",
            "properties": {
                "role_name": {"type": "string", "description": "Exact directory role display name, e.g. 'Privileged Authentication Administrator'"}
            },
            "required": ["role_name"],
        },
    },
})

###########################

messages = [{"role": "system", "content": SYSTEM_PROMPT}]

while True:
    user_input = input("You: ")
    if user_input.lower() == "exit":
        break
    messages.append({"role": "user", "content": user_input})

    while True:
        response = client.chat.completions.create(
            model=MODEL, messages=messages, tools=tools,
            max_completion_tokens=8000,
        )
        msg = response.choices[0].message
        # print("finish_reason:", response.choices[0].finish_reason)  # debug 
        # print("usage:", response.usage)                             # debug
        messages.append(msg)

        if not msg.tool_calls:
            print(f"AI: {msg.content}\n")
            break

        for call in msg.tool_calls:
            print(f"[tool called: {call.function.name}]")
            try:
                args = json.loads(call.function.arguments or "{}")          # updated
                result = to_json(REGISTRY[call.function.name][0](**args))   # updated
            except Exception as e:
                result = f"ERROR: {e}"
            messages.append({"role": "tool", "tool_call_id": call.id, "content": result})