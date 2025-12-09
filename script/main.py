import os
import sys
from dotenv import load_dotenv

# 假设你的项目结构中 script 文件夹在 PYTHONPATH 下
# 如果报错找不到模块，可能需要调整 import 路径，例如: from script.utils.local_llm_client ...
from script.agent.pt_agent import PTAgent
from script.utils.llm.local_llm_client import LocalLLMClient


def main():
    # 1. 加载环境变量 (这会读取 .env 文件)
    load_dotenv()

    # 2. 从环境变量获取配置 (如果 .env 里没写，就使用后面的默认值)
    target_url = os.getenv("TARGET_URL", "http://localhost:3000")
    backend = os.getenv("LOCAL_BACKEND_TYPE")
    model = os.getenv("LOCAL_MODEL_NAME")

    # 3. 初始化 LLM 客户端
    # 这里不需要传参，因为它会自动去读取 .env 中的 LOCAL_BACKEND_TYPE 和 LOCAL_MODEL_NAME
    print("[*] Initializing Local LLM Client...")
    llm_client = LocalLLMClient(backend, model)

    # 4. 初始化并运行渗透测试 Agent
    print(f"[*] Starting PTAgent targeting: {target_url}")
    agent = PTAgent(base_url=target_url, llm_client=llm_client)

    try:
        agent.run()
    except KeyboardInterrupt:
        print("\n[!] User aborted.")
        sys.exit(0)


if __name__ == "__main__":
    main()