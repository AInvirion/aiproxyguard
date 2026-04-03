---
title: SDKs
nav_order: 4
has_children: true
---

# SDKs

Official client libraries for AIProxyGuard. Both SDKs work with the self-hosted proxy and the cloud API.

| SDK | Package | Description |
|-----|---------|-------------|
| [Python](python-sdk) | `aiproxyguard-python-sdk` | Sync/async, decorators, batch operations |
| [JavaScript](javascript-sdk) | `@ainvirion/aiproxyguard-npm-sdk` | TypeScript, Express middleware, native fetch |

## Which to Use?

Both options are **free**:

- **Self-hosted proxy**: Deploy your own proxy and point your existing OpenAI/Anthropic SDK at it. No API key required. Use our SDKs for direct `/check` calls or advanced features.
- **Cloud API**: Use our SDKs with a free API key at `aiproxyguard.com` - no proxy deployment needed. When creating your API key, enable the `check` scope in permissions.
