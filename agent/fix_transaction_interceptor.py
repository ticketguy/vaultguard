# Fix for transaction_interceptor.py
import re

# Read the file with UTF-8 encoding
with open('src/api/transaction_interceptor.py', 'r', encoding='utf-8') as f:
    content = f.read()

# Fix the RAGClient initialization
old_line = "rag = RAGClient(rag_service_url)"
new_lines = """# Generate unique IDs for this API instance
        import time
        agent_id = f"api_security_agent_{int(time.time())}"
        session_id = f"api_session_{int(time.time())}"
        rag = RAGClient(agent_id, session_id, rag_service_url)"""

content = content.replace(old_line, new_lines)

# Write back with UTF-8 encoding
with open('src/api/transaction_interceptor.py', 'w', encoding='utf-8') as f:
    f.write(content)

print("✅ Fixed RAGClient initialization!")