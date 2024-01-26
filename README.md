# Overview

Generic token based authorization

# Features

- Configure the plugin with a secret key
- Call the protected token issuance endpoint ('/authz') with a trusted client and an authorization predicate (containing "scope", "operator", "value") and an expiry duration (in seconds)
- Kong uses the generated token to make authorization decisions in-context

# Installation

```
luarocks install kong-authz-proxy
```

# Configuration

TODO. Se kong.yml declarative config
