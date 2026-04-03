---
title: SDKs
nav_order: 4
has_children: true
---

# SDKs

Official client libraries for AIProxyGuard. Both SDKs work with the self-hosted proxy and the cloud API.

| SDK | Package | Description |
|-----|---------|-------------|
| [Python](python-sdk) | `aiproxyguard` | Sync/async, decorators, batch operations |
| [JavaScript](javascript-sdk) | `@aiproxyguard/sdk` | TypeScript, Express middleware, native fetch |

## Which to Use?

- **Self-hosted proxy**: Point your existing OpenAI/Anthropic SDK at the proxy URL. Use our SDKs for direct `/check` calls or advanced features.
- **Cloud API**: Use our SDKs for the simplest integration - no proxy deployment needed.
