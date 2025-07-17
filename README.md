# F5 PROXY Protocol Gateway: Bridging TCP and HTTP Client IP Preservation

When load balancers and proxies handle traffic, preserving the original client IP address becomes a challenge. Different systems use different methods: some use TCP PROXY Protocol (v1 or v2), others use HTTP headers like X-Forwarded-For.

[F5 BIG-IP does not have native support for PROXY protocol](https://my.f5.com/manage/s/article/K40512493). I developed the **F5 PROXY Protocol Gateway iRule** so that BIG-IP can receive and correctly interpret TCP PROXY Protocol (v1 or v2), and translate to HTTP headers such as X-Forwarded-For.

## Why This Matters

Modern infrastructure often involves multiple layers of load balancing and proxying. A request might flow through:
- A cloud provider's network load balancer (using PROXY Protocol)
- Your F5 BIG-IP (expecting HTTP headers)
- Backend applications (reading specific headers)

Without translation, you lose visibility into the real client IP at some point in this chain. This affects security logging, rate limiting, geolocation, and any feature that depends on knowing the actual client address.

We previously explored this challenge in ["Solving for true-source IP with global load balancers in Google Cloud"](https://community.f5.com/kb/technicalarticles/solving-for-true-source-ip-with-global-load-balancers-in-google-cloud/329397). The F5 PROXY Protocol Gateway iRule solves this problem by providing flexible transformation between different IP preservation methods.

## What the iRule Does

The F5 PROXY Protocol Gateway iRule provides:

1. **Detection** of incoming client IP information from:
   - TCP PROXY Protocol v1 (text-based)
   - TCP PROXY Protocol v2 (binary format)
   - HTTP headers (X-Forwarded-For, X-Real-IP, CF-Connecting-IP)

2. **Transformation** between formats:
   - PROXY Protocol (v1/v2) → HTTP header
   - HTTP header → HTTP header
   - _Future: HTTP → PROXY Protocol (see community question below)_

3. **Diagnostic headers** for troubleshooting the transformation process

4. **Flexible operation modes**:
   - Transparent mode: Detect and log only
   - Transform mode: Actively convert between formats

## Cloud Load Balancer Proxy Protocol Support

Here's the current state of PROXY Protocol support across major cloud providers:

| Cloud Provider | Load Balancer Type | PP v1 | PP v2 | X-Forwarded-For | Notes | Documentation |
|----------------|-------------------|-------|-------|-----------------|--------|---------------|
| **F5 Distributed Cloud (XC)** | | | | | | |
| | Load Balancer | ✓ | ✓ | ✓ | Enable proxy protocol for upstream connections | [TCP LB Feature Request](https://www.f5cloudideas.com/ideas/MESH-I-242), [HTTP LB Feature Request](https://www.f5cloudideas.com/ideas/MESH-I-243) |
| **AWS** | | | | | | |
| | Network Load Balancer (NLB) | ✗ | ✓ | ✗ | Enable proxy protocol v2 on target groups | [NLB Proxy Protocol v2 Guide](https://aws.amazon.com/blogs/networking-and-content-delivery/preserving-client-ip-address-with-proxy-protocol-v2-and-network-load-balancer/), [NLB Target Groups](https://docs.aws.amazon.com/elasticloadbalancing/latest/network/load-balancer-target-groups.html) |
| | Classic Load Balancer (CLB) | ✓ | ✗ | ✓ | PP v1 for TCP listeners, XFF for HTTP listeners | [CLB Proxy Protocol](https://docs.aws.amazon.com/elasticloadbalancing/latest/classic/enable-proxy-protocol.html) |
| | Application Load Balancer (ALB) | ✗ | ✗ | ✓ | Layer 7 only, automatically adds XFF headers | [ALB Overview](https://docs.aws.amazon.com/elasticloadbalancing/latest/application/) |
| **Azure** | | | | | | |
| | Load Balancer | ✗ | ✗ | ✗ | Layer 4, preserves source IP directly | [Azure Load Balancer Overview](https://docs.microsoft.com/en-us/azure/load-balancer/load-balancer-overview) |
| | Application Gateway | ✗ | ✗ | ✓ | Adds XFF headers for HTTP/HTTPS traffic | [Application Gateway Overview](https://docs.microsoft.com/en-us/azure/application-gateway/overview) |
| | Private Link Service | ✗ | ✓ | ✗ | TCP Proxy v2 support for backend visibility | [Private Link Proxy Protocol](https://learn.microsoft.com/en-us/azure/private-link/private-link-service-overview#proxy-protocol), [TCP Proxy v2 Deep Dive](https://techcommunity.microsoft.com/t5/fasttrack-for-azure/tcp-proxy-protocol-v2-with-azure-private-link-service-deep-dive/ba-p/3574968) |
| **Google Cloud** | | | | | | |
| | External Proxy Network LB (Global) | ✓ | ✗ | ✗ | Enable via target proxy configuration | [Classic Proxy NLB Setup](https://cloud.google.com/load-balancing/docs/tcp/setting-up-tcp#proxy-protocol) |
| | External Proxy Network LB (Regional) | ✓ | ✗ | ✗ | TCP traffic only | [External Proxy NLB Overview](https://cloud.google.com/load-balancing/docs/tcp/) |
| | External Application LB | ✗ | ✗ | ✓ | Layer 7, automatically adds XFF headers | [Application LB Overview](https://cloud.google.com/load-balancing/docs/https) |
| | Network LB (Pass-through) | ✗ | ✗ | ✗ | Preserves client IP directly | [Network LB Overview](https://cloud.google.com/load-balancing/docs/network/) |
| **Oracle Cloud Infrastructure** | | | | | | |
| | Network Load Balancer | ✗ | ✓ | ✗ | Enable proxy protocol v2 for TCP listeners | [NLB Proxy Protocol](https://docs.oracle.com/en-us/iaas/Content/NetworkLoadBalancer/NetworkLoadBalancers/network-load-balancer-management.htm#proxy-protocol) |
| | Load Balancer | ✓ | ✓ | ✓ | Supports both v1 and v2 for TCP listeners | [LB Proxy Protocol](https://docs.oracle.com/en-us/iaas/Content/Balance/Tasks/managingloadbalancer.htm#proxy-protocol) |
| **Akamai** | | | | | | |
| | NodeBalancer | ✓ | ✓ | ✗ | Enable for TCP protocol configurations | [NodeBalancer Proxy Protocol](https://techdocs.akamai.com/cloud-computing/docs/using-proxy-protocol-with-nodebalancers) |
| | Application Load Balancer | ✗ | ✗ | ✓ | Layer 7 load balancing with header support | [ALB Overview](https://techdocs.akamai.com/cloudlets/docs/what-app-load-balancer) |
| **Cloudflare** | | | | | | |
| | Load Balancer (Proxied) | ✗ | ✗ | ✓ | Layer 7 proxy automatically adds headers | [LB Proxy Modes](https://developers.cloudflare.com/load-balancing/understand-basics/proxy-modes/) |
| | Spectrum (Layer 4) | ✗ | ✗ | ✗ | Layer 4 pass-through, preserves client IP | [Spectrum Overview](https://developers.cloudflare.com/spectrum/) |

If an intermediate network device _does not_ manipulate TCP layer 4 traffic, then Proxy Protocol values _should_ be preserved. For example: layer 3 routers and stateful network firewalls.

## Deployment Guide

### Prerequisites

- F5 BIG-IP with LTM module
- Virtual Server configured for HTTP traffic
- Access to the iRule editor in the F5 management interface

### Step 1: Create the iRule

1. Navigate to **Local Traffic > iRules > iRule List**
2. Click **Create**
3. Name it `proxy_protocol_gateway`
4. Copy the entire iRule code into the editor
5. Click **Finished**

### Step 2: Configure the iRule

The iRule configuration is controlled by variables in the `RULE_INIT` event. Key settings:

```tcl
# Set operation mode
set ::PP_MODE "transform"  # or "transparent" for detection only

# Define transformation rule
set ::PP_TRANSFORM_RULE "ppv2 => X-Forwarded-For"
```

Example transformation rules:
- `"ppv1 => X-Forwarded-For"` - Convert PP v1 to HTTP header
- `"ppv2 => X-Real-IP"` - Convert PP v2 to HTTP header
- `"X-Forwarded-For => X-Real-IP"` - Convert between HTTP headers

### Step 3: Apply to Virtual Server

1. Navigate to your Virtual Server
2. Go to the **Resources** tab
3. Under **iRules**, click **Manage**
4. Move `proxy_protocol_gateway` to the **Enabled** list
5. Click **Finished**

### Step 4: Configure Diagnostic Options

For initial testing, ensure these are enabled:

```tcl
set ::PP_ADD_DIAGNOSTICS 1        # Add diagnostic headers
set ::PP_LOG_TRANSFORMATIONS 1    # Log transformations
```

## Testing the iRule

### Test Setup

You'll need:
- A client machine with `netcat` or `socat`
- Access to the F5 logs (`/var/log/ltm`)
- A backend web server that echoes headers
- Standard virtual server must have an HTTP profile applied
- Standard virtual server with or without an SSL Client profile applied

### Test 1: PROXY Protocol v1

Configure the rule for ppv1 to X-Forwarded-For header transformation:

```tcl
set ::PP_TRANSFORM_RULE "ppv1 => X-Forwarded-For"
```

Send a PP v1 request:

```bash
# Create PP v1 header + HTTP request
echo -e "PROXY TCP4 192.168.1.100 10.0.0.1 56789 80\r\nGET / HTTP/1.1\r\nHost: example.com\r\n\r\n" | \
  nc YOUR_F5_VIP 80
```

Expected log entry:
```
PP v1 parsed: 192.168.1.100:56789
Transformed ppv1 => X-Forwarded-For (value: 192.168.1.100)
```

### Test 2: PROXY Protocol v2

Configure the rule for ppv2 to X-Forwarded-For header transformation:

```tcl
set ::PP_TRANSFORM_RULE "ppv2 => X-Forwarded-For"
```

Send a PP v2 request:

```bash
#!/bin/bash
# Single command test
{
    printf '\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A\x21\x11\x00\x0C\xC0\xA8\x01\x64\x0A\x00\x00\x01\x30\x39\x00\x50'
    printf 'GET / HTTP/1.1\r\nHost: example.com\r\nConnection: close\r\n\r\n'
} | nc YOUR_F5_VIP 80
```

Expected log entry:
```
PP v2 IPv4 parsed successfully: 192.168.1.100:56789 -> 10.0.0.1:80
Transformed ppv2 => X-Forwarded-For (value: 192.168.1.100)
```

### Test 3: X-Forwarded-For

Configure the rule for HTTP header transformation:
```tcl
set ::PP_TRANSFORM_RULE "X-Forwarded-For => X-Real-IP"
```

Test with curl:
```bash
curl -H "X-Forwarded-For: 203.0.113.99" http://YOUR_F5_VIP/
```

Expected log entry:
```
Transformed X-Forwarded-For => X-Real-IP (value: 203.0.113.99)
```

### Viewing Logs

Monitor the F5 logs in real-time:
```bash
tail -f /var/log/ltm | grep "F5_Proxy_Protocol_Gateway"
```

Key log messages to look for:
- `"Transform rule parsed successfully"` - Configuration is valid
- `"PP v1 parsed:"` or `"PP v2 IPv4 parsed successfully:"` - Incoming PP detected
- `"Transformed X => Y"` - Transformation applied
- Warning messages indicate parsing failures

### Diagnostic Headers

When `PP_ADD_DIAGNOSTICS` is enabled, the iRule adds headers to help troubleshooting:

- `X-iRule-PP-Status`: Detection status (e.g., "tcp-proxy-protocol-v2-detected")
- `X-iRule-PP-Original-IP`: The detected client IP
- `X-F5-PP-Transform-Rule`: The active transformation rule
- `X-F5-PP-Transform-Source`: What was detected
- `X-F5-PP-Transform-Target`: What it was transformed to

## Community Question: Where Should We Target PROXY Protocol?

The current version transforms *from* PROXY Protocol to HTTP headers, but not the reverse. We're curious about use cases where you'd want to transform *to* PROXY Protocol:

- Converting X-Forwarded-For → PP v1/v2 for backend servers that expect it?
- Chaining F5 with other proxy servers that only accept PROXY Protocol?
- Integration with specific applications or services?

Share your use cases in the comments!

## Performance Considerations

The iRule uses efficient parsing techniques:
- Binary operations for PP v2 parsing
- Minimal string operations
- Early detection to avoid unnecessary processing
- Single-pass parsing where possible

For high-traffic deployments, consider:
- Starting with transparent mode to assess overhead
- Monitoring CPU impact during peak traffic
- Disabling diagnostic headers in production

## Get Involved

We'd love to hear about your experience with the PROXY Protocol Gateway:

- **Success stories**: Comment below if the iRule solved your integration challenge
- **Feature requests, bug reports:** [Open an issue on GitHub](https://github.com/tmarfil/f5-proxy-protocol-gateway-irule/issues) 

## Conclusion

Start with transparent mode to understand your traffic patterns, then enable transformations as needed. The diagnostic features make troubleshooting straightforward, and the modular design allows for future enhancements based on community needs.
