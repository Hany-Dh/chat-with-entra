import os, json
from datetime import datetime
from zoneinfo import ZoneInfo
from dotenv import load_dotenv
from openai import AzureOpenAI

load_dotenv()
client = AzureOpenAI(
    azure_endpoint=os.getenv("AZURE_OPENAI_ENDPOINT"),
    api_key=os.getenv("AZURE_OPENAI_KEY"),
    api_version="2025-04-01-preview",
)
MODEL = os.getenv("AZURE_OPENAI_DEPLOYMENT")

# 1. The real function
def get_current_time(timezone="Europe/Berlin"):
    return datetime.now(ZoneInfo(timezone)).strftime("%Y-%m-%d %H:%M:%S %Z")

# 2. The tool definition the model sees
tools = [{
    "type": "function",
    "function": {
        "name": "get_current_time",
        "description": "Get the current date and time in a given IANA timezone.",
        "parameters": {
            "type": "object",
            "properties": {
                "timezone": {"type": "string", "description": "e.g. Europe/Berlin, America/New_York"}
            },
            "required": [],
        },
    },
}]
available = {"get_current_time": get_current_time}

messages = [{"role": "system", "content": "You are a helpful assistant. Use tools when needed."}]

while True:
    user_input = input("You: ")
    if user_input.lower() == "exit":
        break
    messages.append({"role": "user", "content": user_input})

    while True:
        response = client.chat.completions.create(
            model=MODEL, messages=messages, tools=tools,
            max_completion_tokens=2000,
        )
        msg = response.choices[0].message
        messages.append(msg)

        if not msg.tool_calls:
            print(f"AI: {msg.content}\n")
            break

        for call in msg.tool_calls:
            args = json.loads(call.function.arguments or "{}")
            result = available[call.function.name](**args)
            print(f"[tool called: {call.function.name} {args}]")
            messages.append({
                "role": "tool",
                "tool_call_id": call.id,
                "content": result,
            })