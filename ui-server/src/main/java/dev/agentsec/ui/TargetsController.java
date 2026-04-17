package dev.agentsec.ui;

import org.springframework.web.bind.annotation.GetMapping;
import org.springframework.web.bind.annotation.RestController;

import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Catalog IDs must stay aligned with {@code scanner/agentsec/targets.py} TARGET_CATALOG.
 */
@RestController
public class TargetsController {

    @GetMapping("/api/targets")
    public List<Map<String, String>> listTargets() {
        return List.of(
                t("cursor", "Cursor", "Cursor IDE rules, hooks, MCP configs", "IDE"),
                t("copilot", "GitHub Copilot", "Copilot instructions and GitHub agent surfaces", "IDE"),
                t("cline", "Cline", "Cline / .clinerules", "IDE"),
                t("mcp", "MCP servers", "Model Context Protocol configs and remote tools", "Tools"),
                t("agents_md", "AGENTS.md / agent docs", "Repo-level agent instruction files", "Docs"),
                t("langchain", "LangChain / LangGraph", "langchain, langgraph, langsmith in Python or JS", "Framework"),
                t("autogen", "AutoGen / AgentChat", "Microsoft AutoGen, pyautogen, autogen-agentchat", "Framework"),
                t("crewai", "CrewAI", "crewai multi-agent framework", "Framework"),
                t("semantic_kernel", "Semantic Kernel", ".NET / Python Semantic Kernel", "Framework"),
                t("litellm", "LiteLLM", "LiteLLM proxy / gateway usage", "Framework"),
                t("vertex_ai", "Google Vertex AI", "vertexai, google-cloud-aiplatform", "Cloud"),
                t("bedrock", "AWS Bedrock", "boto3 bedrock, amazon bedrock agents", "Cloud"),
                t("ci_github", "GitHub Actions", "Workflows that may run agents or LLM steps", "CI"),
                t("ci_gitlab", "GitLab CI", ".gitlab-ci.yml pipelines", "CI"),
                t("node", "Node / npm", "package.json present", "Runtime"),
                t("python", "Python", "Python packaging present", "Runtime"),
                t("jvm", "JVM (Maven/Gradle)", "Java/Kotlin build files", "Runtime")
        );
    }

    private static Map<String, String> t(String id, String label, String description, String category) {
        Map<String, String> m = new LinkedHashMap<>();
        m.put("id", id);
        m.put("label", label);
        m.put("description", description);
        m.put("category", category);
        return m;
    }
}
