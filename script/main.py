from script.agent.pt_agent import PTAgent
from script.llm.lmstudio_client import LMStudioClient

def main():
    llm_client = LMStudioClient()
    agent = PTAgent(base_url="http://localhost:3000", llm_client=llm_client)
    agent.run()

if __name__ == "__main__":
    main()