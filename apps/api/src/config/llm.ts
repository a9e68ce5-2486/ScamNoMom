export type LlmProvider = "openai" | "ollama" | "auto" | "fallback";

export function getLlmConfig() {
  return {
    provider: (process.env.LLM_PROVIDER?.trim().toLowerCase() || "auto") as LlmProvider,
    openai: {
      apiKey: process.env.OPENAI_API_KEY?.trim() || "",
      model: process.env.OPENAI_MODEL?.trim() || "gpt-5.2"
    },
    ollama: {
      baseUrl: process.env.OLLAMA_BASE_URL?.trim() || "http://127.0.0.1:11434",
      model: process.env.OLLAMA_MODEL?.trim() || "qwen3:8b"
    }
  };
}

export function hasOpenAiConfig(): boolean {
  return Boolean(getLlmConfig().openai.apiKey);
}

export function hasOllamaConfig(): boolean {
  const { baseUrl, model } = getLlmConfig().ollama;
  return Boolean(baseUrl && model);
}
