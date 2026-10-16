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
}

tools = [{
    "type": "function",
    "function": {
        "name": name, "description": desc,
        "parameters": {"type": "object", "properties": {}},
    },
} for name, (_, desc) in REGISTRY.items()]

messages = [{"role": "system", "content": SYSTEM_PROMPT}]

while True:
    user_input = input("You: ")
    if user_input.lower() == "exit":
        break
    messages.append({"role": "user", "content": user_input})

    while True:
        response = client.chat.completions.create(
            model=MODEL, messages=messages, tools=tools,
            max_completion_tokens=4000,
        )
        msg = response.choices[0].message
        messages.append(msg)

        if not msg.tool_calls:
            print(f"AI: {msg.content}\n")
            break

        for call in msg.tool_calls:
            print(f"[tool called: {call.function.name}]")
            try:
                result = to_json(REGISTRY[call.function.name][0]())
            except Exception as e:
                result = f"ERROR: {e}"
            messages.append({"role": "tool", "tool_call_id": call.id, "content": result})