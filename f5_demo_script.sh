#!/bin/bash

# F5 Proxy Protocol Gateway Demo Script
# For asciinema recording - Terminal Demo
# Duration: ~2 minutes

# ============================================================================
# DEMO TIMING CONFIGURATION
# ============================================================================
# Customize pause durations for different demo speeds
# Usage: ./script.sh [speed_preset]
# Speed presets: fast, normal, slow, manual
# Or set custom timing with environment variables

# Parse command line speed preset or use environment variables
SPEED_PRESET="${1:-normal}"

case "$SPEED_PRESET" in
    "fast")
        HEADER_PAUSE=${HEADER_PAUSE:-1}
        STEP_PAUSE=${STEP_PAUSE:-0.5}
        CODE_PAUSE=${CODE_PAUSE:-1}
        TYPING_DELAY=${TYPING_DELAY:-0.02}
        RESULT_PAUSE=${RESULT_PAUSE:-1.5}
        ;;
    "slow")
        HEADER_PAUSE=${HEADER_PAUSE:-4}
        STEP_PAUSE=${STEP_PAUSE:-2}
        CODE_PAUSE=${CODE_PAUSE:-3}
        TYPING_DELAY=${TYPING_DELAY:-0.08}
        RESULT_PAUSE=${RESULT_PAUSE:-4}
        ;;
    "manual")
        HEADER_PAUSE=${HEADER_PAUSE:-0}
        STEP_PAUSE=${STEP_PAUSE:-0}
        CODE_PAUSE=${CODE_PAUSE:-0}
        TYPING_DELAY=${TYPING_DELAY:-0.01}
        RESULT_PAUSE=${RESULT_PAUSE:-0}
        MANUAL_MODE=1
        ;;
    "normal"|*)
        HEADER_PAUSE=${HEADER_PAUSE:-2}
        STEP_PAUSE=${STEP_PAUSE:-1}
        CODE_PAUSE=${CODE_PAUSE:-2}
        TYPING_DELAY=${TYPING_DELAY:-0.05}
        RESULT_PAUSE=${RESULT_PAUSE:-3}
        ;;
esac

# Colors and formatting
BOLD='\033[1m'
RED='\033[0;31m'
GREEN='\033[0;32m'
BLUE='\033[0;34m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color
CLEAR='\033[2J\033[H'

# Demo configuration
F5_VIP="10.1.1.100"
DEMO_PORT="80"

# Utility functions
wait_for_input() {
    if [[ $MANUAL_MODE -eq 1 ]]; then
        echo -e "${BLUE}[Press ENTER to continue...]${NC}"
        read -r
    fi
}

print_header() {
    echo -e "${CLEAR}"
    echo -e "${BOLD}${BLUE}════════════════════════════════════════════════════════════════${NC}"
    echo -e "${BOLD}${YELLOW}  $1${NC}"
    echo -e "${BOLD}${BLUE}════════════════════════════════════════════════════════════════${NC}"
    echo ""
    wait_for_input
    sleep $HEADER_PAUSE
}

print_step() {
    echo -e "${BOLD}${GREEN}▶ $1${NC}"
    echo ""
    wait_for_input
    sleep $STEP_PAUSE
}

simulate_typing() {
    local text="$1"
    local delay=${2:-$TYPING_DELAY}
    for (( i=0; i<${#text}; i++ )); do
        echo -n "${text:$i:1}"
        sleep $delay
    done
    echo ""
}

show_code_snippet() {
    local title="$1"
    local file="$2"
    local pattern="$3"
    echo -e "${BOLD}${YELLOW}$title${NC}"
    echo -e "${BLUE}─────────────────────────────────────────────────────────────────${NC}"
    if command -v bat >/dev/null 2>&1; then
        grep -A5 -B2 "$pattern" "$file" | bat --language=tcl --style=plain --color=always 2>/dev/null || \
        grep -A5 -B2 "$pattern" "$file" | head -8
    else
        grep -A5 -B2 "$pattern" "$file" | head -8
    fi
    echo -e "${BLUE}─────────────────────────────────────────────────────────────────${NC}"
    echo ""
    wait_for_input
    sleep $CODE_PAUSE
}

# Main demo script
main() {
    print_header "F5 Proxy Protocol Gateway iRule Demo"
    
    echo "🚀 Bridging TCP Proxy Protocol and HTTP Headers on F5 BIG-IP"
    echo ""
    sleep 2

    # Part 1: Show the iRule configuration
    print_header "1️⃣  iRule Configuration"
    
    print_step "Transform Rule: Proxy Protocol v2 → X-Forwarded-For"
    show_code_snippet "All Transform Rule Possibilities:" "f5_proxy_protocol_gateway_v0_01_00.tcl" 'Examples:'
    
    print_step "Operation Mode: Transform (Active)"
    show_code_snippet "Mode Setting:" "f5_proxy_protocol_gateway_v0_01_00.tcl" 'PP_MODE.*"transform"'

    # Part 2: Test Proxy Protocol v2
    print_header "2️⃣  Proxy Protocol v2 to X-Forwarded-For Transformation"
    
    print_step "Sending PP v2 binary header + HTTP request"
    echo "Client IP: 192.168.1.100:56789 → Server: 10.0.0.1:80"
    echo ""
    
    echo -e "${YELLOW}Command:${NC}"
    simulate_typing "printf '\\x0D\\x0A\\x0D\\x0A\\x00\\x0D\\x0A\\x51\\x55\\x49\\x54\\x0A\\x21\\x11\\x00\\x0C\\xC0\\xA8\\x01\\x64\\x0A\\x00\\x00\\x01\\x30\\x39\\x00\\x50' > /tmp/ppv2_header"
    
    sleep 1
    printf '\x0D\x0A\x0D\x0A\x00\x0D\x0A\x51\x55\x49\x54\x0A\x21\x11\x00\x0C\xC0\xA8\x01\x64\x0A\x00\x00\x01\x30\x39\x00\x50' > /tmp/ppv2_header
    
    simulate_typing "echo 'GET / HTTP/1.1' > /tmp/http_request"
    echo 'GET / HTTP/1.1' > /tmp/http_request
    
    simulate_typing "echo 'Host: example.com' >> /tmp/http_request"
    echo 'Host: example.com' >> /tmp/http_request
    
    simulate_typing "echo -e '\\r\\n' >> /tmp/http_request"
    echo -e '\r\n' >> /tmp/http_request
    
    simulate_typing "cat /tmp/ppv2_header /tmp/http_request | nc $F5_VIP $DEMO_PORT"
    echo ""
    
    # Simulate F5 response
    echo -e "${GREEN}✓ F5 BIG-IP Response:${NC}"
    echo "HTTP/1.1 200 OK"
    echo "Server: nginx/1.20.1"
    echo -e "${BOLD}X-Forwarded-For: 192.168.1.100${NC}  ← 🎯 Transformed!"
    echo "X-iRule-PP-Status: tcp-proxy-protocol-v2-ipv4-detected"
    echo "X-F5-PP-Transform-Rule: ppv2 => X-Forwarded-For"
    echo ""
    wait_for_input
    sleep $RESULT_PAUSE

    # Part 3: Show logs
    print_header "3️⃣  F5 BIG-IP Transformation Logs"
    
    print_step "Real-time iRule processing logs"
    echo -e "${YELLOW}tail -f /var/log/ltm | grep F5_Proxy_Protocol_Gateway${NC}"
    echo ""
    
    echo -e "${GREEN}Log Output:${NC}"
    echo "$(date '+%b %d %H:%M:%S') F5_Proxy_Protocol_Gateway: PP v2 signature detected, parsing..."
    echo "$(date '+%b %d %H:%M:%S') F5_Proxy_Protocol_Gateway: PP v2 IPv4 parsed successfully: 192.168.1.100:56789 -> 10.0.0.1:80"
    echo -e "${BOLD}$(date '+%b %d %H:%M:%S') F5_Proxy_Protocol_Gateway: Transformed ppv2 => X-Forwarded-For (value: 192.168.1.100)${NC}"
    echo ""
    wait_for_input
    sleep $STEP_PAUSE

    # Part 4: Test Proxy Protocol v1
    print_header "4️⃣  Bonus: Proxy Protocol v1 Support"
    
    print_step "Quick test with PP v1 text format"
    echo -e "${YELLOW}Command:${NC}"
    simulate_typing "echo -e 'PROXY TCP4 203.0.113.50 10.0.0.1 45678 80\\r\\nGET / HTTP/1.1\\r\\nHost: test.com\\r\\n\\r\\n' | nc $F5_VIP $DEMO_PORT"
    echo ""
    
    echo -e "${GREEN}✓ Result:${NC}"
    echo -e "${BOLD}X-Forwarded-For: 203.0.113.50${NC}  ← 🎯 Also works!"
    echo ""
    wait_for_input
    sleep $STEP_PAUSE

    # Part 5: F5 Distributed Cloud Integration
    print_header "5️⃣  F5 Distributed Cloud (XC) Integration"
    
    print_step "Perfect companion to F5 Distributed Cloud Services"
    echo "🌐 F5 Distributed Cloud Load Balancer supports:"
    echo "   ✅ Proxy Protocol v1 (text format)"
    echo "   ✅ Proxy Protocol v2 (binary format)" 
    echo "   ✅ X-Forwarded-For headers"
    echo ""
    echo "🔗 Learn more: https://www.f5.com/products/distributed-cloud-services"
    echo ""
    echo "💡 Use Case: XC → BIG-IP → Backend"
    echo "   XC sends PP v2 → iRule transforms → Backend gets X-Forwarded-For"
    echo ""
    wait_for_input
    sleep $RESULT_PAUSE

    # Part 6: Community Engagement
    print_header "6️⃣  Join the F5 DevCentral Community"
    
    print_step "Share your success stories and use cases!"
    echo "🤝 We want to hear from you:"
    echo ""
    echo "   📋 Success Stories:"
    echo "      • How did this iRule solve your integration challenge?"
    echo "      • What cloud + F5 combinations are you using?"
    echo ""
    echo "   🚀 Feature Requests:"
    echo "      • HTTP/2 support for modern applications?"
    echo "      • PP v1/v2 as transformation *targets*?"
    echo "      • Feature request? Bug reports? Open a GitHub issue:"
    echo "        https://github.com/tmarfil/f5-proxy-protocol-gateway-irule/issues"
    echo ""
    echo "🌐 Join the discussion: https://community.f5.com/"
    echo ""
    wait_for_input
    sleep $RESULT_PAUSE

    # Final summary
    print_header "🎉  Demo Complete!"
    
    echo "🔗 Key Features Demonstrated:"
    echo "   • Binary Proxy Protocol v2 parsing"
    echo "   • Automatic transformation to HTTP headers"
    echo "   • Real-time logging and diagnostics"
    echo "   • Multi-protocol support (v1 + v2)"
    echo "   • Cloud load balancer compatibility"
    echo ""
    echo "📖 Full documentation: README.md"
    echo "💾 Download iRule: f5_proxy_protocol_gateway_v0_01_00.tcl"
    echo ""
    wait_for_input
    sleep $STEP_PAUSE
    
    # Cleanup
    rm -f /tmp/ppv2_header /tmp/http_request 2>/dev/null
}

# Check if running in demo mode or sourced
if [[ "${BASH_SOURCE[0]}" == "${0}" ]]; then
    # Direct execution
    echo "🎬 Starting F5 Proxy Protocol Gateway Demo..."
    echo "   Speed preset: $SPEED_PRESET"
    if [[ $MANUAL_MODE -eq 1 ]]; then
        echo "   Manual mode: Press ENTER to advance each step"
    fi
    echo "   Perfect for asciinema recording!"
    echo ""
    sleep 1
    main
else
    # Sourced - provide functions for manual demo
    echo "Demo functions loaded. Available speed presets:"
    echo "  ./script.sh fast    - Quick demo (~1 min)"
    echo "  ./script.sh normal  - Standard demo (~2 min) [default]"
    echo "  ./script.sh slow    - Detailed demo (~3 min)"
    echo "  ./script.sh manual  - Manual advance mode"
    echo ""
    echo "Or set custom timing:"
    echo "  HEADER_PAUSE=1 STEP_PAUSE=0.5 ./script.sh"
    echo ""
    echo "Run: main"
fi
