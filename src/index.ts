import type { Config } from "payload";

type CypherScanVerdict = "clean" | "suspicious" | "malicious" | "unknown";

type CypherScanPluginResponse = {
  ok?: boolean;
  verdict?: CypherScanVerdict | string;
  scanId?: string;
  findings?: unknown[];
  warnings?: string[];
  error?: string;
  code?: string;
};

export type CypherScanPayloadOptions = {
  apiKey: string;
  apiUrl?: string;
  collections?: string[];
  blockVerdicts?: CypherScanVerdict[];
  failOpen?: boolean;
};

function normalizeVerdict(value: unknown): CypherScanVerdict {
  const verdict = String(value ?? "unknown").toLowerCase();

  if (verdict === "clean") return "clean";
  if (verdict === "suspicious") return "suspicious";
  if (verdict === "malicious") return "malicious";

  return "unknown";
}

export const cypherScanPayload =
  (options: CypherScanPayloadOptions) =>
  (config: Config): Config => {
    const apiUrl =
      options.apiUrl ??
      "https://cyphernetsecurity.com/api/v1/plugin/payload/scan";

    const blockVerdicts = options.blockVerdicts ?? [
      "suspicious",
      "malicious",
    ];

    const failOpen = options.failOpen ?? true;

    return {
      ...config,
      collections: (config.collections ?? []).map((collection) => {
        if (!collection.upload) return collection;

        if (
          options.collections &&
          !options.collections.includes(collection.slug)
        ) {
          return collection;
        }

        return {
          ...collection,
          hooks: {
            ...collection.hooks,
            beforeChange: [
              ...(collection.hooks?.beforeChange ?? []),
              async ({ data, req, operation }) => {
                const file = (req as any).file;

                if (!file?.data) {
                  req.payload.logger.info(
                    `[cypherscan-payload] no new upload file for ${collection.slug} (${operation})`,
                  );

                  return data;
                }

                const fileName =
                  file.name || data?.filename || "payload-upload.bin";

                const mimeType =
                  file.mimetype ||
                  data?.mimeType ||
                  "application/octet-stream";

                req.payload.logger.info(
                  `[cypherscan-payload] scanning ${fileName} (${mimeType})`,
                );

                try {
                  const formData = new FormData();

                  const blob = new Blob([file.data], {
                    type: mimeType,
                  });

                  formData.append("file", blob, fileName);
                  formData.append("apiKey", options.apiKey);

                  const response = await fetch(apiUrl, {
                    method: "POST",
                    headers: {
                      "x-cypherscan-api-key": options.apiKey,
                    },
                    body: formData,
                  });

                  const result =
                    (await response.json()) as CypherScanPluginResponse;

                  if (!response.ok || result.ok === false) {
                    const message =
                      result.error ||
                      result.code ||
                      `CypherScan API returned HTTP ${response.status}`;

                    throw new Error(message);
                  }

                  const verdict = normalizeVerdict(result.verdict);

                  req.payload.logger.info(
                    `[cypherscan-payload] verdict for ${fileName}: ${verdict}`,
                  );

                  if (blockVerdicts.includes(verdict)) {
                    throw new Error(
                      `Upload blocked by CypherScan. Verdict: ${verdict}`,
                    );
                  }

                  return data;
                } catch (error) {
                  const message =
                    error instanceof Error
                      ? error.message
                      : "Unknown CypherScan error";

                  const isBlockingError = message.startsWith(
                    "Upload blocked by CypherScan",
                  );

                  if (isBlockingError || !failOpen) {
                    throw error;
                  }

                  req.payload.logger.warn(
                    `[cypherscan-payload] scan failed; allowing upload because failOpen=true. Reason: ${message}`,
                  );

                  return data;
                }
              },
            ],
          },
        };
      }),
    };
  };