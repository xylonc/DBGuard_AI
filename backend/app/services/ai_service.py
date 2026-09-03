"""LLM decision engine — selects templates based on user prompt + RAG context."""

import os
import json
from litellm import completion

from app.config import settings


def generate_hardening_plan(
    user_prompt: str,
    metadata: dict,
    retrieved_templates: list[dict] = None
) -> dict:
    """
    Ask the LLM to select which templates to apply based on:
    1. The user's natural language request
    2. The database metadata
    3. Templates retrieved via RAG (semantic similarity search)
    """

    if retrieved_templates:
        # RAG mode: LLM receives context about retrieved templates
        templates_context = "\n".join([
            f"- {t['template_name']}: {t['description']}"
            for t in retrieved_templates
        ])
        system_prompt = f"""
You are a database security expert. Analyze the user request and select the appropriate hardening templates.

RETRIEVED TEMPLATES (from semantic search, ranked by relevance):
{templates_context}

Return ONLY a single valid JSON object in this exact format:
{{
  "template_ids": ["create_read_only_rule"],
  "parameters": {{
    "role_name": "readonly_auditor",
    "database_name": "mydb"
  }},
  "reasoning": "Brief explanation of why these templates were selected"
}}
"""
    else:
        # Fallback: use hardcoded list
        system_prompt = """
You are a database security expert. Select from the available templates below.

AVAILABLE TEMPLATES:
- create_read_only_rule — Creates a read-only auditor role with SELECT-only access
- revoke_public_access — Revokes all permissions from PUBLIC on a schema

Return ONLY a single valid JSON object:
{
  "template_ids": ["create_read_only_rule"],
  "parameters": {
    "role_name": "readonly_user"
  },
  "reasoning": "Why this template was selected"
}
"""

    user_message = f"""Request: {user_prompt}
Database metadata: {json.dumps(metadata)}"""

    try:
        completion_kwargs = dict(
            model=settings.llm_model,
            messages=[
                {"role": "system", "content": system_prompt},
                {"role": "user", "content": user_message}
            ],
            temperature=0.3
        )
        if settings.openai_api_key:
            completion_kwargs["api_key"] = settings.openai_api_key
        elif settings.ollama_api_base:
            completion_kwargs["api_base"] = settings.ollama_api_base
            completion_kwargs["api_key"] = settings.ollama_api_key or "ollama"

        response = completion(**completion_kwargs)

        content = response.choices[0].message.content.strip()

        # Strip markdown code blocks if present
        if content.startswith("```"):
            lines = content.split("\n")
            lines = lines[1:]  # remove ```json or ```
            if lines[0].startswith("json"):
                lines = lines[1:]
            content = "\n".join(lines).rstrip("```").strip()

        return json.loads(content)

    except (json.JSONDecodeError, KeyError, Exception) as e:
        return {
            "template_ids": [],
            "parameters": {},
            "reasoning": f"LLM error: {str(e)}",
            "error": str(e)
        }
