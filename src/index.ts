export interface CypherScanPayloadConfig {
  apiKey: string;
  apiUrl?: string;
}

export function cypherScanPayload(
  config: CypherScanPayloadConfig,
) {
  const apiUrl =
    config.apiUrl ?? "https://api.cyphernetsecurity.com";

  return {
    name: "cypherscan-payload",
    config,
    apiUrl,
  };
}