import sys
sys.path.insert(0, '/home/kei/llm_vault/hermes_qwen_cti')
from rag_manager import query_similar, format_results_for_agent

results = query_similar("Carnival Cruise data breach 6 million ShinyHunters", n_results=5)
print(format_results_for_agent(results))
