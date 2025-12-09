from analysis.asset_triager import AssetTriager
from analysis.owasp_llm_analyzer import OwaspTop10LLMAnalyzer
from attacker.exploitation_engine import ExploitationEngine
from attacker.xss_attacker import XSSAttacker
from scanner.page_asset import AuthCredentials
from script.scanner.site_scanner import SiteScanner
import os
import pickle
import hashlib # 用于生成基于 URL 的唯一文件名
from typing import Any # 用于类型提示

from utils.browser_manager import BrowserManager


class PTAgent:
    def __init__(self, base_url: str, llm_client):
        self.base_url = base_url
        self.scanner = SiteScanner(
            base_url=base_url,
            max_depth=2,  # 可以先从 1 或 2 开始试
            headless=True,
            same_origin_only=True,
        )
        self.llm_analyzer = OwaspTop10LLMAnalyzer(llm_client)
        # self.browser = browser_manager

        # --- NEW: 实例化 ExploitationEngine ---
        # 1. 定义可用的攻击策略类（只包含 XSSAttacker）
        attacker_classes = {
            'XSSAttacker': XSSAttacker  # 假设 XSSAttacker 类已导入
            # 'SQLiAttacker': SQLiAttacker, # 暂不启用
        }

        # 2. 实例化攻击执行引擎
        self.exploitation_engine = ExploitationEngine(
            llm_proxy=llm_client,
            attacker_classes=attacker_classes
        )

        # --- NEW: 缓存配置 ---
        self._cache_dir = "ptagent_cache"
        os.makedirs(self._cache_dir, exist_ok=True)
        # 使用 base_url 的哈希值作为缓存文件的唯一前缀
        self._cache_key = self._get_cache_key(base_url)

    def run(self):
        print(f"[*] Initializing PTAgent for target: {self.base_url}")

        # =================================================
        # Step 0: 手动凭证注入 (Manual Credential Injection)
        # =================================================
        creds = self._load_cache("auth_creds")

        if not creds :
            creds = self._prompt_for_credentials()
            print("[*] Credentials loaded successfully!")
            self._save_cache(creds, "auth_creds")

        if creds:
            print("[*] Applying credentials to SiteScanner...")
            # 调用扫描器的新方法，将凭证注入到 Playwright 上下文
            self.scanner.set_auth_context(creds)

        # =================================================
        # Step 1: 游客视角扫描 (Guest Scan)
        # =================================================
        site_asset = self._load_cache("scan_result")

        if site_asset is None:
            print("\n[Phase 1] Starting Guest Scan...")

            # --- 执行扫描 ---
            site_asset = self.scanner.scan()

            # --- 缓存扫描结果 ---
            self._save_cache(site_asset, "scan_result")
        else:
            print("\n[Phase 1] Skipped Scan. Loaded SiteAsset from cache.")

        self._print_scan_summary(site_asset, phase="Guest")

        print("\n=== Site scan finished ===")
        print(f"Base URL: {site_asset.base_url}")
        print(f"Total pages: {len(site_asset.pages)}\n")

        for url in site_asset.auth_required_urls:
            print(f"- Auth Required Page: {url}")
        print()

        for url, page in site_asset.pages.items():
            print(f"- Page: {url}")
            print(f"  title: {page.title}")
            print(f"  inputs: {len(page.inputs)}")
            print(f"  clickables: {len(page.clickables)}")
            print(f"  scripts: {len(page.scripts)}")
            print(f"  api_calls: {len(page.api_calls)}")
            print("=== cleaned HTML ===")
            print(page.cleaned_html)
            print()

        # Step 3. 分诊 (Triage)
        triager = AssetTriager(site_asset)
        triaged_data = triager.triage()

        print(f"分诊完成:")
        print(f"- 交互型页面: {len(triaged_data['interactive'])}")
        print(f"- 线索型页面: {len(triaged_data['clues'])}")
        print(f"- 纯文本、无交互页面: {len(triaged_data['static'])}")
        print(f"- 独立 API: {len(triaged_data['standalone_apis'])}")

        # # Step 4. 智能分析 (LLM Analysis)
        # # 如果你初始化了 llm_analyzer
        # if self.llm_analyzer:
        #     print("\n[Phase 4] Starting LLM Vulnerability Analysis...")
        #     analysis_result = self.llm_analyzer.analyze(triaged_data)
        # Step 4. 智能分析 (LLM Analysis)
        analysis_result = self._load_cache("analysis_result")

        if analysis_result is None:
            if self.llm_analyzer:
                print("\n[Phase 4] Starting LLM Vulnerability Analysis...")

                # --- 执行分析 ---
                analysis_result = self.llm_analyzer.analyze(triaged_data)

                # --- 缓存分析结果 ---
                self._save_cache(analysis_result, "analysis_result")
            else:
                print("[FATAL] LLM Analyzer not initialized. Skipping Phase 4.")
                return  # 无法继续
        else:
            print("\n[Phase 4] Skipped Analysis. Loaded AnalysisResult from cache.")

        print(f"\n=== LLM Analysis Report ===")
        for issue in analysis_result.issues:
            print(f"[{issue.owasp_category}] {issue.location}")
            print(f"  Risk: {issue.risk_reason}")
            print(f"  Tests: {issue.suggested_tests}")
            print("-" * 30)

        # =================================================
        # Step 5. 攻击执行 (Exploitation)
        # =================================================
        if not self.exploitation_engine:
            print("[FATAL] Exploitation Engine not initialized. Skipping Phase 5.")
            return

        print("\n[Phase 5] Starting Targeted Exploitation...")

        # --- 关键点：获取授权会话上下文 ---
        # 即使凭证是手动输入的，这一步也是必须的，因为要获取活动的客户端/Headers/Cookies
        try:
            # 假设 scanner 知道如何根据当前状态返回所需的上下文
            session_context = self.scanner.get_current_session_context()
        except AttributeError:
            print("[ERROR] Scanner must implement get_current_session_context() method.")
            return

        all_attack_results = []

        # --- 遍历 LLM 发现的问题并执行攻击 ---
        for issue in analysis_result.issues:
            # 聚焦于 XSS 漏洞的判断逻辑
            # (根据 ExploitationEngine 中 _ATTACK_MAPPING 的键进行判断)
            is_xss_category = issue.owasp_category in ['XSS', 'A03: Cross-Site Scripting (XSS)']

            # 仅在 XSS 漏洞且置信度高或中时进行攻击
            if is_xss_category and issue.confidence in ["High", "Medium"]:
                print("-" * 50)
                print(f"[*] Targeting XSS at {issue.location} (Confidence: {issue.confidence})")

                # 调用 ExploitationEngine，它会负责：
                # 1. 映射 AttackTarget (InputField)
                # 2. 路由到 XSSAttacker
                # 3. 执行攻击，并使用 session_context 发送请求
                attack_result = self.exploitation_engine.run_attack_from_issue(
                    issue=issue,
                    site_asset=site_asset,
                    session_context=session_context  # 传入活动的会话上下文
                )

                all_attack_results.append(attack_result)

                if attack_result.success:
                    print(f"[!!! XSS FOUND !!!] PoC: {attack_result.proof_of_concept[:50]}...")
                    print(f"  Details: {attack_result.details}")
                else:
                    print(f"[-] XSS attack failed. Details: {attack_result.details}")

        print("-" * 50)
        print(f"--- Phase 5 Finished. Total attacks run: {len(all_attack_results)} ---")

        # --- 攻击全部结束后，关闭浏览器资源 ---
        self.scanner.close()


    def _prompt_for_credentials(self) -> AuthCredentials | None:
        """
        在控制台提示用户输入凭证。
        """
        print("\n" + "=" * 50)
        print(" CREDENTIAL INPUT (Press Enter to skip)")
        print(" Tip: Copy from DevTools -> Network -> Request Headers")
        print("=" * 50)

        # 1. 获取 Authorization Header
        auth_header = input("Paste 'Authorization' header value (e.g. Bearer ...): ").strip()

        # 2. 获取 Cookie String
        # 直接粘贴浏览器里的 cookie 字符串: "key=value; key2=value2"
        cookie_str = input("Paste 'Cookie' string (key=value; ...): ").strip()

        if not auth_header and not cookie_str:
            print("[*] No credentials provided. Running in GUEST mode only.")
            return None

        # 3. 解析 Cookie
        cookies_list = []
        if cookie_str:
            try:
                # 简单的解析逻辑
                for item in cookie_str.split(";"):
                    if "=" in item:
                        k, v = item.strip().split("=", 1)
                        # Playwright 的 add_cookies 需要 url 或 domain
                        cookies_list.append({
                            "name": k,
                            "value": v,
                            "url": self.base_url
                        })
            except Exception as e:
                print(f"[!] Failed to parse cookie string: {e}")

        # 4. 构造 Headers
        headers_dict = {}
        if auth_header:
            # 有些 header 可能自带 "Bearer "，有些可能不带，这里直接作为 value 使用
            headers_dict["Authorization"] = auth_header

        print("[*] Credentials loaded successfully!")
        return AuthCredentials(
            cookies=cookies_list,
            headers=headers_dict
        )

    def _print_scan_summary(self, site_asset, phase="Scan"):
        print(f"\n=== {phase} Summary ===")
        print(f"Total pages tracked: {len(site_asset.pages)}")

        # 统计一下发现的 API
        total_apis = sum(len(p.api_calls) for p in site_asset.pages.values())
        print(f"Total API interactions captured: {total_apis}")
        print(f"Discovered (Standalone) APIs: {len(site_asset.discovered_apis)}")

        if site_asset.auth_required_urls:
            print(f"Auth Required URLs pending: {len(site_asset.auth_required_urls)}")

    # =================================================
    # 辅助方法：缓存管理
    # =================================================
    def _get_cache_key(self, base_url: str) -> str:
        """根据 base_url 生成一个一致且安全的缓存键。"""
        # 使用 SHA256 确保 URL 中包含的特殊字符不会影响文件名
        return hashlib.sha256(base_url.encode('utf-8')).hexdigest()

    def _get_cache_path(self, step: str) -> str:
        """返回特定步骤的缓存文件完整路径。"""
        # 文件名格式: <URL哈希>_<步骤名>.pkl
        return os.path.join(self._cache_dir, f"{self._cache_key}_{step}.pkl")

    def _load_cache(self, step: str) -> Any | None:
        """尝试加载缓存数据。"""
        path = self._get_cache_path(step)
        if os.path.exists(path):
            print(f"[*] 尝试加载缓存数据 for '{step}'...")
            try:
                with open(path, 'rb') as f:
                    data = pickle.load(f)
                print(f"[+] 成功加载缓存 for '{step}'.")
                return data
            except Exception as e:
                print(f"[WARN] 加载缓存失败 ({e})，文件可能已损坏，将重新运行。")
                os.remove(path)  # 移除损坏的缓存文件
        return None

    def _save_cache(self, data: Any, step: str):
        """保存数据到缓存文件。"""
        path = self._get_cache_path(step)
        print(f"[*] 正在保存 '{step}' 结果到缓存: {path}")
        try:
            with open(path, 'wb') as f:
                pickle.dump(data, f)
        except Exception as e:
            print(f"[WARN] 缓存保存失败: {e}")