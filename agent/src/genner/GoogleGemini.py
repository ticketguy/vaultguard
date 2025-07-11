import re
from typing import Callable, List, Tuple
from loguru import logger
from result import Err, Ok, Result

try:
    import google.generativeai as genai
    GOOGLE_AI_AVAILABLE = True
except ImportError:
    GOOGLE_AI_AVAILABLE = False

from src.helper import extract_content
from src.types import ChatHistory
from .Base import Genner


class GoogleGeminiGenner(Genner):
    """Direct Google Gemini API genner"""
    
    def __init__(self, api_key: str, config, stream_fn: Callable[[str], None] | None):
        if not GOOGLE_AI_AVAILABLE:
            raise ImportError("Install: pip install google-generativeai")
        
        super().__init__("google_gemini", True if stream_fn else False)
        self.config = config
        self.stream_fn = stream_fn
        
        genai.configure(api_key=api_key)
        self.model = genai.GenerativeModel(
            model_name=config.model,
            generation_config=genai.types.GenerationConfig(
                max_output_tokens=config.max_tokens,
                temperature=getattr(config, 'temperature', 0.7),
            )
        )

    def ch_completion(self, messages: ChatHistory) -> Result[str, str]:
        try:
            # Convert to Gemini format
            prompt_parts = []
            for message in messages.as_native():
                role = message.get("role", "user")
                content = message.get("content", "")
                if role == "system":
                    prompt_parts.append(f"System: {content}\n")
                elif role == "user":
                    prompt_parts.append(f"User: {content}\n")
                elif role == "assistant":
                    prompt_parts.append(f"Assistant: {content}\n")
            
            full_prompt = "".join(prompt_parts)
            
            if self.do_stream and self.stream_fn:
                response = self.model.generate_content(full_prompt, stream=True)
                final_response = ""
                for chunk in response:
                    if chunk.text:
                        final_response += chunk.text
                        self.stream_fn(chunk.text)
                return Ok(final_response.strip())
            else:
                response = self.model.generate_content(full_prompt)
                return Ok(response.text.strip()) if response.text else Err("Empty response")
                    
        except Exception as e:
            return Err(f"GoogleGeminiGenner error: {str(e)}")

    def generate_code(self, messages: ChatHistory, blocks: List[str] = [""]) -> Result[Tuple[List[str], str], str]:
        completion_result = self.ch_completion(messages)
        if err := completion_result.err():
            return Err(f"GoogleGeminiGenner.generate_code: {err}")
        
        raw_response = completion_result.unwrap()
        extract_result = self.extract_code(raw_response, blocks)
        
        if err := extract_result.err():
            return Ok((None, raw_response))
        
        return Ok((extract_result.unwrap(), raw_response))

    def generate_list(self, messages: ChatHistory, blocks: List[str] = [""]) -> Result[Tuple[List[List[str]], str], str]:
        completion_result = self.ch_completion(messages)
        if err := completion_result.err():
            return Err(f"GoogleGeminiGenner.generate_list: {err}")
        
        raw_response = completion_result.unwrap()
        extract_result = self.extract_list(raw_response, blocks)
        
        if err := extract_result.err():
            return Err(f"GoogleGeminiGenner.generate_list: {err}")
        
        return Ok((extract_result.unwrap(), raw_response))

    @staticmethod
    def extract_code(response: str, blocks: List[str] = [""]) -> Result[List[str], str]:
        extracts: List[str] = []
        for block in blocks:
            try:
                response = extract_content(response, block)
                python_matches = re.findall(r"```python\n([\s\S]*?)```", response, re.DOTALL)
                if python_matches:
                    extracts.extend([match.strip() for match in python_matches])
                else:
                    generic_matches = re.findall(r"```\n([\s\S]*?)```", response, re.DOTALL)
                    if generic_matches:
                        extracts.extend([match.strip() for match in generic_matches])
            except Exception as e:
                return Err(f"extract_code error: {str(e)}")
        
        return Ok(extracts) if extracts else Err("No code blocks found")

    @staticmethod
    def extract_list(response: str, blocks: List[str] = [""]) -> Result[List[List[str]], str]:
        extracts: List[List[str]] = []
        for block in blocks:
            try:
                response = extract_content(response, block)
                yaml_match = re.search(r"```yaml\n(.*?)```", response, re.DOTALL)
                if yaml_match:
                    import yaml
                    yaml_content = yaml.safe_load(yaml_match.group(1).strip())
                    if isinstance(yaml_content, list):
                        extracts.append(yaml_content)
            except Exception as e:
                return Err(f"extract_list error: {str(e)}")
        
        return Ok(extracts)
