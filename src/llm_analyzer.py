import re
import json
import logging
from typing import List, Dict, Any, Optional
from ollama_provider import OllamaProvider, BaseLLMProvider

logger = logging.getLogger(__name__)


class LLMAnalyzer:
    """llm analyzer main class that incorporates various providers"""

    def __init__(self, provider: Optional[BaseLLMProvider] = None):
        self.provider = provider or OllamaProvider(auto_start=True)

    def analyze_chunk(self, content: str, patterns: List[Any]) -> List[Dict[str, Any]]:
        """Calls the LLM and parses the response"""
        try:
            response_text = self._call_llm(content, patterns)
            findings = self._parse_llm_response(response_text)
            return findings
        except Exception as e:
            logger.error(f"LLM analysis failed: {e}")
            return []

    def _call_llm(self, content: str, patterns: List[Any]) -> str:
        """Calls the LLM with the prompt"""
        pattern_descriptions = "\n".join(
            [f"- {p.name}: {p.description}" for p in patterns]
        )
        # escaping special characters
        safe_content = content[:3000].replace("{", "{{").replace("}", "}}")

        prompt = (
            """You are a security expert. Analyze code for secrets and respond with ONLY valid JSON.
        IMPORTANT: Your response must be ONLY a JSON array. No explanations, no markdown, just JSON.

        Focus on detecting:
        """
            + pattern_descriptions
            + """

        Content to analyze:
        ```
        """
            + safe_content[:3000]
            + """
        ```

        Response format (EXACTLY like this):
        [
        {{"line": 5, "snippet": "api_key='abc123'", "type": "api_key", "confidence": "high", "rationale": "Hardcoded API key"}},
        {{"line": 7, "snippet": "password='secret'", "type": "password", "confidence": "medium", "rationale": "Hardcoded password"}}
        ]
        Rules:
        1. ONLY return valid JSON array
        2. Use double quotes for all strings
        3. confidence must be: "high", "medium", or "low"
        4. If no secrets found, return: []
        5. Do not include markdown code blocks
        6. Do not add explanations
        
        Response:
        """
        )

        response_text = self.provider.analyze(prompt)
        logger.debug(f"Raw LLM message: {response_text[:500]}")
        return response_text

    def _parse_llm_response(self, response_text: str) -> List[Dict[str, Any]]:
        """Parse the LLM response and extracts valid JSON"""
        response_text = response_text.strip()

        # remove markdown
        response_text = re.sub(r"```json\s*", "", response_text)
        response_text = re.sub(r"```\s*", "", response_text)

        # fixes double braces
        response_text = response_text.replace("{{", "{").replace("}}", "}")

        # extraction of the JSON from the LLM response
        json_patterns = [
            r"```json\s*(\[.*?\])\s*```",  # Complete JSON in a code block
            r"```\s*(\[.*?\])\s*```",  # Complete JSON
            r"(\[\s*\{.*?\}\s*\])",  # Complete JSON array
            r"(\[\s*\{.*)",  # incomplete JSON e.g. no closing ]
        ]

        for pattern in json_patterns:
            json_match = re.search(pattern, response_text, re.DOTALL)
            if json_match:
                json_str = (
                    json_match.group(1) if json_match.lastindex else json_match.group()
                )
                if not json_str.rstrip().endswith("]"):
                    logger.warning("Detected incomplete JSON, attempting to fix...")
                    # last complete object is found, then closed
                    last_brace = json_str.rfind("}")
                    if last_brace != -1:
                        json_str = json_str[: last_brace + 1] + "\n]"

                # logger.debug(f"Extracted JSON: {json_str[:200]}")

                try:
                    findings = json.loads(json_str)
                    if isinstance(findings, list):
                        return findings
                except json.JSONDecodeError:
                    continue

        logger.warning("No valid JSON found in response")
        return []

    def cleanup(self):
        """cleans up the resources"""

        if hasattr(self.provider, "cleanup"):
            self.provider.cleanup()
