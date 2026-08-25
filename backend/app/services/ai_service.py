import os
import json
from dotenv import load_dotenv
from litellm import completion

load_dotenv()

# Path to the templates folder relative to this file
TEMPLATES_DIR = os.path.abspath(os.path.join(os.path.dirname(__file__), "../templates"))

def generate_hardening_plan(user_prompt: str, metadata: dict) -> dict:
    # 1. Dynamically read existing .sql.j2 filenames on disk
    if os.path.exists(TEMPLATES_DIR):
        available_templates = [
            f.replace(".sql.j2", "") 
            for f in os.listdir(TEMPLATES_DIR) 
            if f.endswith(".sql.j2")
        ]
    else:
        available_templates = []

    formatted_list = "\n".join([f"- {t}" for t in available_templates])

    # 2. Tell the LLM strictly which templates exist
    system_prompt = f"""
You are a database security expert. Analyze the user request and database metadata to select appropriate hardening templates.

AVAILABLE TEMPLATES (You MUST ONLY select template names from this list):
{formatted_list}

Return ONLY a single valid JSON object in this exact format:
{{
  "template_ids": ["create_read_only_role"],
  "parameters": {{
    "role_name": "readonly_user"
  }}
}}
"""

    messages = [
        {"role": "system", "content": system_prompt},
        {"role": "user", "content": f"Request: {user_prompt}\nMetadata: {metadata}"}
    ]

    response = completion(
        model="ollama_chat/gpt-oss:20b-cloud",
        messages=messages,
        api_base="https://ollama.com",
        api_key=os.getenv("OLLAMA_API_KEY"),
    )

    content_str = response.choices[0].message.content.strip()

    if content_str.startswith("```"):
        content_str = content_str.split("```")[1]
        if content_str.startswith("json"):
            content_str = content_str[4:]
        content_str = content_str.strip()

    return json.loads(content_str)