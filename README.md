# CypherScan Payload

CypherScan upload security plugin for Payload CMS.

Scan uploaded files before they are accepted by Payload and automatically block suspicious or malicious content.

Learn more: https://cyphernetsecurity.com

## Installation

```bash
npm install cypherscan-payload
```

## API Key

Create a CypherScan API key from:

```text
https://cyphernetsecurity.com/dashboard/api-keys
```

Then configure the plugin using your API key.

## Usage

```ts
import { cypherScanPayload } from "cypherscan-payload";

export default buildConfig({
  plugins: [
    cypherScanPayload({
      apiKey: process.env.CYPHERSCAN_API_KEY!,
    }),
  ],
});
```

## Configuration

```ts
cypherScanPayload({
  apiKey: process.env.CYPHERSCAN_API_KEY!,
  apiUrl: "https://cyphernetsecurity.com/api/v1/plugin/payload/scan",
  collections: ["media"],
  blockVerdicts: ["suspicious", "malicious"],
  failOpen: true,
});
```

## Options

| Option        | Description                                      |
| ------------- | ------------------------------------------------ |
| apiKey        | CypherScan API key                               |
| apiUrl        | Custom CypherScan endpoint                       |
| collections   | Restrict scanning to specific upload collections |
| blockVerdicts | Verdicts that should block uploads               |
| failOpen      | Allow uploads if CypherScan is unavailable       |

## Features

* Upload scanning
* Malware detection
* Secret detection
* Upload blocking
* Payload CMS integration
* Configurable fail-open behavior
* Collection targeting

## Verdicts

| Verdict    | Behavior                                   |
| ---------- | ------------------------------------------ |
| clean      | Upload allowed                             |
| suspicious | Upload blocked (default)                   |
| malicious  | Upload blocked (default)                   |
| unknown    | Upload allowed unless configured otherwise |

## Example

Upload:

```text
invoice.zip
```

Result:

```text
Verdict: suspicious
Action: upload blocked
```

## Links

Website:

```text
https://cyphernetsecurity.com
```

GitHub:

```text
https://github.com/cyphernetsecurity/cypherscan-payload
```

## License

MIT
