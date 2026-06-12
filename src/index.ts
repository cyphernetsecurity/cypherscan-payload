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

                if (!data) {
                  req.payload.logger.info(
                    `[cypherscan-payload] no data received for ${collection.slug} (${operation})`,
                  );

                  return data;
                }

                const file = (req as any).file;

                req.payload.logger.info("=== CYPHERSCAN DEBUG ===");
                req.payload.logger.info(`collection: ${collection.slug}`);
                req.payload.logger.info(`operation: ${operation}`);
                req.payload.logger.info(`apiUrl: ${apiUrl}`);
                req.payload.logger.info(`data: ${JSON.stringify(data)}`);
                req.payload.logger.info(
                  `req keys: ${Object.keys(req).join(", ")}`,
                );
                req.payload.logger.info(
                  `req.file meta: ${JSON.stringify(
                    file
                      ? {
                          name: file.name,
                          mimetype: file.mimetype,
                          size: file.size,
                          md5: file.md5,
                          tempFilePath: file.tempFilePath,
                          hasData: Boolean(file.data),
                          dataLength: file.data?.length,
                        }
                      : null,
                  )}`,
                );
                req.payload.logger.info("========================");

                // TODO: locate uploaded file in req.file / upload data
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