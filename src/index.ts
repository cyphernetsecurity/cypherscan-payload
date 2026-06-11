import type { Config } from "payload";

export type CypherScanPayloadOptions = {
  apiKey: string;
  apiUrl?: string;
  collections?: string[];
};

export const cypherScanPayload =
  (options: CypherScanPayloadOptions) =>
  (config: Config): Config => {
    const apiUrl = options.apiUrl ?? "https://cyphernetsecurity.com/api/scan";

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
                req.payload.logger.info(
                  `[cypherscan-payload] scan hook triggered for ${collection.slug} (${operation})`,
                );

                // TODO: locate uploaded file in req.files / upload data
                // TODO: send file to CypherScan API
                // TODO: block upload if verdict is malicious

                return data;
              },
            ],
          },
        };
      }),
    };
  };