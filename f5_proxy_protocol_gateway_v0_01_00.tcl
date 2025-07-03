# ============================================================================
# F5 Proxy Protocol Gateway v0.01.00
# ============================================================================
# This iRule provides bidirectional transformation between TCP Proxy Protocol
# (v1/v2) and HTTP headers with stealth operation capabilities.
# ============================================================================

# ============================================================================
# USER CONFIGURATION SECTION
# ============================================================================
# Edit these settings according to your requirements:

when RULE_INIT {
    # OPERATION MODE
    # Values: "transparent" | "transform"
    # - transparent: Detect and log only, no transformations
    # - transform: Apply configured transformations
    set ::PP_MODE "transform"
    
    # TRANSFORMATION RULE 
    # Format: "source => target"
    # Supported sources: ppv1, ppv2, X-Forwarded-For, X-Real-IP, CF-Connecting-IP
    # Supported targets: X-Forwarded-For, X-Real-IP
    # Examples:
    #   "ppv1 => X-Forwarded-For"          # Convert PP v1 to HTTP header
    #   "ppv2 => X-Real-IP"                # Convert PP v2 to HTTP header  
    #   "X-Forwarded-For => X-Real-IP"     # Convert HTTP header to HTTP header

    set ::PP_TRANSFORM_RULE "ppv2 => X-Forwarded-For"
    
    # DIAGNOSTIC OPTIONS
    set ::PP_ADD_DIAGNOSTICS 1           ; # Add all diagnostic headers
    set ::PP_LOG_TRANSFORMATIONS 1       ; # Log all transformations
    set ::PP_NORMALIZE_HEADERS 1         ; # Normalize proxy headers (ONLY in transform mode)
    
    # PROTOCOL SUPPORT
    set static::allowProxyV1 1             ; # Enable Proxy Protocol v1 support
    set static::allowProxyV2 1             ; # Enable Proxy Protocol v2 support  
    set static::allowNoProxy 1             ; # Allow requests without proxy protocol
    
    # HEADER CONFIGURATION
    set ::PP_SOURCE_HEADERS [list "X-Forwarded-For" "X-Real-IP" "CF-Connecting-IP"]
    set ::PP_TARGET_HEADERS [list "X-Forwarded-For" "X-Real-IP"]

    # ========================================================================
    # PROTOCOL CONSTANTS
    # ========================================================================
    
    # Proxy Protocol v2 Binary Constants
    set ::PP_V2_SIGNATURE_HEX "0d0a0d0a000d0a515549540a"
    set ::PP_V2_SIGNATURE_LEN 12
    set ::PP_V2_HEADER_MIN_LEN 16
    set ::PP_V2_ADDR_LEN_IPV4_TCP 12
    set ::PP_V2_VERSION 2
    set ::PP_V2_COMMAND_PROXY 1
    set ::PP_V2_FAMILY_IPV4 1
    set ::PP_V2_PROTOCOL_TCP 1
    set ::PP_V2_ADDR_OFFSET 16
    
    # Proxy Protocol v1 Text Constants  
    set ::PP_V1_SIGNATURE "PROXY"
    set ::PP_V1_SIGNATURE_LEN 5
    set ::PP_V1_MIN_HEADER_LEN 8
    set ::PP_V1_TCP_VERSION "4"
    set ::PP_V1_EXPECTED_FIELDS 5
    
    # Port and IP Validation Constants
    set ::PORT_MIN 1
    set ::PORT_MAX 65535
    set ::PORT_RANGE_MAX 65536  ; # For unsigned conversion (65535 + 1)
    set ::IP_VALIDATION_MASK "255.255.255.255"
    set ::IPV4_MAX_INT 4294967296  ; # For unsigned IP conversion (2^32)
    
    # TCP Collection and Buffer Constants
    set ::TCP_COLLECT_MIN_LEN 6
    set ::TCP_PP_V2_CHECK_LEN 16
    set ::TCP_PP_V1_CHECK_LEN 8
    
    # Binary Parsing Constants
    set ::BYTE_MASK_LOW_4 0x0F    ; # Lower 4 bits mask
    set ::BYTE_MASK_HIGH_4 0xF0   ; # Upper 4 bits mask  
    set ::BYTE_SHIFT_4 4          ; # 4-bit shift for extracting upper nibble
    set ::IP_BYTE_MASK 0xFF       ; # 8-bit mask for IP byte extraction
    set ::IP_SHIFT_24 24          ; # Bit shifts for IP address extraction
    set ::IP_SHIFT_16 16
    set ::IP_SHIFT_8 8

    # ========================================================================
    # END USER CONFIGURATION - Do not modify below this line
    # ========================================================================
    
    # System initialization
    set ::IRULE_VERSION "0.01.00"
    set ::IRULE_NAME "F5_Proxy_Protocol_Gateway"
    
    # Enhanced Transform Rule Parsing
    set ::PP_TRANSFORM_SOURCE ""
    set ::PP_TRANSFORM_TARGET ""
    if {$::PP_TRANSFORM_RULE ne ""} {
        set parse_result [call parse_transform_rule $::PP_TRANSFORM_RULE]
        array set rule_data $parse_result
        
        if {$rule_data(success)} {
            set ::PP_TRANSFORM_SOURCE $rule_data(source)
            set ::PP_TRANSFORM_TARGET $rule_data(target)
            log local0.info "$::IRULE_NAME: Transform rule parsed successfully: $::PP_TRANSFORM_SOURCE => $::PP_TRANSFORM_TARGET"
        } else {
            log local0.error "$::IRULE_NAME: Transform rule parsing failed: $rule_data(error_msg)"
            log local0.error "$::IRULE_NAME: Rule was: '$::PP_TRANSFORM_RULE'"
            log local0.error "$::IRULE_NAME: Falling back to transparent mode for safety"
            set ::PP_MODE "transparent"
        }
    }
    
    # Initialize connection state variables
    set static::tcp_pp_detected 0
    set static::tcp_pp_src_ip ""
    set static::tcp_pp_src_port ""
    set static::tcp_pp_dst_ip ""
    set static::tcp_pp_dst_port ""
    set static::tcp_pp_version ""
    set static::connection_protocol ""
    
    log local0.info "$::IRULE_NAME v$::IRULE_VERSION: TCP Proxy Protocol v1 + v2 support initialized"
    log local0.info "$::IRULE_NAME: Mode=$::PP_MODE, Rule=$::PP_TRANSFORM_RULE"
}

# ============================================================================
# TRANSFORM RULE PARSING PROCEDURE
# ============================================================================

proc parse_transform_rule {rule_string} {
    # Parse and validate transformation rule with comprehensive error checking
    # Returns: dict with keys: success, source, target, error_msg
    
    if {$rule_string eq ""} {
        return [list success 0 error_msg "Empty transform rule"]
    }
    
    # Parse rule format: "source => target"
    if {![regexp {^([^=]+)\s*=>\s*(.+)$} $rule_string -> source_raw target_raw]} {
        return [list success 0 error_msg "Invalid rule format. Expected 'source => target', got: '$rule_string'"]
    }
    
    set source [string trim $source_raw]
    set target [string trim $target_raw]
    
    # Define supported sources and targets (centralized for easy maintenance)
    set supported_sources [list "ppv1" "ppv2" "X-Forwarded-For" "X-Real-IP" "CF-Connecting-IP"]
    set supported_targets [list "ppv1" "ppv2" "X-Forwarded-For" "X-Real-IP" "CF-Connecting-IP"]
    
    # Validate source exists in supported list
    if {[lsearch -exact $supported_sources $source] == -1} {
        return [list success 0 error_msg "Unsupported source '$source'. Supported sources: [join $supported_sources {, }]"]
    }
    
    # Validate target exists in supported list  
    if {[lsearch -exact $supported_targets $target] == -1} {
        return [list success 0 error_msg "Unsupported target '$target'. Supported targets: [join $supported_targets {, }]"]
    }
    
    # Check for same source and target (no-op transformation)
    if {$source eq $target} {
        return [list success 0 error_msg "Source and target cannot be the same: '$source'. This would be a no-op transformation."]
    }
    
    # Additional validation: Check for logical combinations
    set pp_protocols [list "ppv1" "ppv2"]
    set http_headers [list "X-Forwarded-For" "X-Real-IP" "CF-Connecting-IP"]
    
    # Note: Transformations TO ppv1 / ppv2 are planned for future implementation
    if {[lsearch -exact $pp_protocols $source] != -1 && [lsearch -exact $pp_protocols $target] != -1} {
        return [list success 0 error_msg "PP-to-PP transformations ('$source' => '$target') are planned for future implementation. Use PP-to-HTTP or HTTP-to-PP instead."]
    }
    
    # Return success with parsed and validated data
    return [list success 1 source $source target $target]
}

# ============================================================================
# PROXY PROTOCOL PARSING PROCEDURES
# ============================================================================

proc parse_proxy_protocol_v1 {payload} {
    # Parse Proxy Protocol v1 header from TCP payload
    # Returns: dict with keys: success, src_ip, src_port, dst_ip, dst_port, header_length, error_msg
    
    # Check minimum length for "PROXY" + space
    if {[string length $payload] < $::TCP_COLLECT_MIN_LEN} {
        return [list success 0 error_msg "Payload too short for PP v1"]
    }
    
    # Check for PROXY signature
    if {[string range $payload 0 [expr {$::PP_V1_SIGNATURE_LEN - 1}]] ne $::PP_V1_SIGNATURE} {
        return [list success 0 error_msg "No PROXY signature found"]
    }
    
    # Find CRLF terminator
    set crlf_pos [string first "\r\n" $payload]
    if {$crlf_pos <= 0} {
        return [list success 0 error_msg "No CRLF terminator found"]
    }
    
    # Extract header line (without CRLF)
    set header_line [string range $payload 0 [expr {$crlf_pos - 1}]]
    
    # Parse the header: "PROXY TCP4 srcip dstip srcport dstport"
    if {[scan $header_line "PROXY TCP%s %s %s %s %s" tcpver srcip dstip srcport dstport] != $::PP_V1_EXPECTED_FIELDS} {
        return [list success 0 error_msg "Invalid PP v1 format - scan failed"]
    }
    
    # Validate TCP version (should be "4" for IPv4)
    if {$tcpver ne $::PP_V1_TCP_VERSION} {
        return [list success 0 error_msg "Unsupported TCP version: $tcpver"]
    }
    
    # Validate source IP using F5's built-in IP validation
    if {[catch {IP::addr $srcip mask $::IP_VALIDATION_MASK}]} {
        return [list success 0 error_msg "Invalid source IP format: $srcip"]
    }
    
    # Validate destination IP
    if {[catch {IP::addr $dstip mask $::IP_VALIDATION_MASK}]} {
        return [list success 0 error_msg "Invalid destination IP format: $dstip"]
    }
    
    # Validate port numbers using constants
    if {![string is integer -strict $srcport] || $srcport < $::PORT_MIN || $srcport > $::PORT_MAX} {
        return [list success 0 error_msg "Invalid source port: $srcport"]
    }
    
    if {![string is integer -strict $dstport] || $dstport < $::PORT_MIN || $dstport > $::PORT_MAX} {
        return [list success 0 error_msg "Invalid destination port: $dstport"]
    }
    
    # Calculate total header length (including CRLF)
    set header_length [expr {$crlf_pos + 2}]
    
    # Return success with parsed data
    return [list success 1 src_ip $srcip src_port $srcport dst_ip $dstip dst_port $dstport header_length $header_length]
}

proc parse_proxy_protocol_v2 {payload} {
    # Parse Proxy Protocol v2 header from TCP payload
    # Returns: dict with keys: success, src_ip, src_port, dst_ip, dst_port, header_length, error_msg
    
    set payload_len [string length $payload]
    
    # Check minimum length for PP v2 using constant
    if {$payload_len < $::PP_V2_HEADER_MIN_LEN} {
        return [list success 0 error_msg "Payload too short for PP v2 (need $::PP_V2_HEADER_MIN_LEN+ bytes, have $payload_len)"]
    }
    
    # Check for PP v2 signature (first 12 bytes) using constants
    set first_signature_bytes [string range $payload 0 [expr {$::PP_V2_SIGNATURE_LEN - 1}]]
    if {[string length $first_signature_bytes] != $::PP_V2_SIGNATURE_LEN} {
        return [list success 0 error_msg "Cannot extract PP v2 signature bytes"]
    }
    
    # Convert signature to hex and validate using constant
    binary scan $first_signature_bytes H[expr {$::PP_V2_SIGNATURE_LEN * 2}] sig_hex
    if {$sig_hex ne $::PP_V2_SIGNATURE_HEX} {
        return [list success 0 error_msg "Invalid PP v2 signature: $sig_hex"]
    }
    
    # Parse version/command byte (byte 12)
    if {[catch {binary scan [string index $payload $::PP_V2_SIGNATURE_LEN] c ver_cmd_byte}]} {
        return [list success 0 error_msg "Cannot read version/command byte"]
    }
    
    # Parse family/protocol byte (byte 13)  
    if {[catch {binary scan [string index $payload [expr {$::PP_V2_SIGNATURE_LEN + 1}]] c fam_prot_byte}]} {
        return [list success 0 error_msg "Cannot read family/protocol byte"]
    }
    
    # Parse address length (bytes 14-15)
    if {[catch {binary scan [string range $payload [expr {$::PP_V2_SIGNATURE_LEN + 2}] [expr {$::PP_V2_SIGNATURE_LEN + 3}]] S addr_len}]} {
        return [list success 0 error_msg "Cannot read address length"]
    }
    # Ensure positive value for address length
    if {$addr_len < 0} {
        set addr_len [expr {$addr_len + $::PORT_RANGE_MAX}]
    }
    
    # Extract version and command using constants
    set version [expr {$ver_cmd_byte >> $::BYTE_SHIFT_4}]
    set command [expr {$ver_cmd_byte & $::BYTE_MASK_LOW_4}]
    set family [expr {$fam_prot_byte >> $::BYTE_SHIFT_4}]
    set protocol [expr {$fam_prot_byte & $::BYTE_MASK_LOW_4}]
    
    # Validate PP v2 version and command using constants
    if {$version != $::PP_V2_VERSION} {
        return [list success 0 error_msg "Invalid PP v2 version: $version (expected $::PP_V2_VERSION)"]
    }
    
    if {$command != $::PP_V2_COMMAND_PROXY} {
        return [list success 0 error_msg "Invalid PP v2 command: $command (expected $::PP_V2_COMMAND_PROXY for PROXY)"]
    }
    
    # Calculate total header length using constant
    set total_header_len [expr {$::PP_V2_HEADER_MIN_LEN + $addr_len}]
    
    # Check if we have enough data
    if {$payload_len < $total_header_len} {
        return [list success 0 error_msg "Insufficient data: need $total_header_len bytes, have $payload_len"]
    }
    
    # Currently only support IPv4 TCP using constants
    if {$family != $::PP_V2_FAMILY_IPV4} {
        return [list success 0 error_msg "Unsupported address family: $family (only IPv4 family=$::PP_V2_FAMILY_IPV4 supported)"]
    }
    
    if {$protocol != $::PP_V2_PROTOCOL_TCP} {
        return [list success 0 error_msg "Unsupported protocol: $protocol (only TCP protocol=$::PP_V2_PROTOCOL_TCP supported)"]
    }
    
    if {$addr_len != $::PP_V2_ADDR_LEN_IPV4_TCP} {
        return [list success 0 error_msg "Invalid address length for IPv4 TCP: $addr_len (expected $::PP_V2_ADDR_LEN_IPV4_TCP)"]
    }
    
    # Parse IPv4 addresses and ports using constants (12 bytes starting at offset 16)
    if {[catch {binary scan [string range $payload $::PP_V2_ADDR_OFFSET [expr {$::PP_V2_ADDR_OFFSET + 3}]] I src_ip_int}]} {
        return [list success 0 error_msg "Cannot read source IP"]
    }
    # Ensure positive value for IP using constant
    if {$src_ip_int < 0} {
        set src_ip_int [expr {$src_ip_int + $::IPV4_MAX_INT}]
    }
    
    if {[catch {binary scan [string range $payload [expr {$::PP_V2_ADDR_OFFSET + 4}] [expr {$::PP_V2_ADDR_OFFSET + 7}]] I dst_ip_int}]} {
        return [list success 0 error_msg "Cannot read destination IP"]
    }
    # Ensure positive value for IP using constant
    if {$dst_ip_int < 0} {
        set dst_ip_int [expr {$dst_ip_int + $::IPV4_MAX_INT}]
    }
    
    if {[catch {binary scan [string range $payload [expr {$::PP_V2_ADDR_OFFSET + 8}] [expr {$::PP_V2_ADDR_OFFSET + 9}]] S src_port}]} {
        return [list success 0 error_msg "Cannot read source port"]
    }
    # Convert signed to unsigned for ports using constant
    if {$src_port < 0} {
        set src_port [expr {$src_port + $::PORT_RANGE_MAX}]
    }
    
    if {[catch {binary scan [string range $payload [expr {$::PP_V2_ADDR_OFFSET + 10}] [expr {$::PP_V2_ADDR_OFFSET + 11}]] S dst_port}]} {
        return [list success 0 error_msg "Cannot read destination port"]
    }
    # Convert signed to unsigned for ports using constant
    if {$dst_port < 0} {
        set dst_port [expr {$dst_port + $::PORT_RANGE_MAX}]
    }
    
    # Convert IP integers to dotted decimal notation using constants
    set src_ip [format "%d.%d.%d.%d" \
        [expr {($src_ip_int >> $::IP_SHIFT_24) & $::IP_BYTE_MASK}] \
        [expr {($src_ip_int >> $::IP_SHIFT_16) & $::IP_BYTE_MASK}] \
        [expr {($src_ip_int >> $::IP_SHIFT_8) & $::IP_BYTE_MASK}] \
        [expr {$src_ip_int & $::IP_BYTE_MASK}]]
    
    set dst_ip [format "%d.%d.%d.%d" \
        [expr {($dst_ip_int >> $::IP_SHIFT_24) & $::IP_BYTE_MASK}] \
        [expr {($dst_ip_int >> $::IP_SHIFT_16) & $::IP_BYTE_MASK}] \
        [expr {($dst_ip_int >> $::IP_SHIFT_8) & $::IP_BYTE_MASK}] \
        [expr {$dst_ip_int & $::IP_BYTE_MASK}]]
    
    # Validate IPv4 addresses using F5's built-in IP validation with constant
    if {[catch {IP::addr $src_ip mask $::IP_VALIDATION_MASK}]} {
        return [list success 0 error_msg "Invalid source IP format: $src_ip"]
    }
    
    if {[catch {IP::addr $dst_ip mask $::IP_VALIDATION_MASK}]} {
        return [list success 0 error_msg "Invalid destination IP format: $dst_ip"]
    }
    
    # Validate port ranges using constants
    if {$src_port < 0 || $src_port > $::PORT_MAX} {
        return [list success 0 error_msg "Invalid source port: $src_port"]
    }
    
    if {$dst_port < 0 || $dst_port > $::PORT_MAX} {
        return [list success 0 error_msg "Invalid destination port: $dst_port"]
    }
    
    # Return success with parsed data
    return [list success 1 src_ip $src_ip src_port $src_port dst_ip $dst_ip dst_port $dst_port header_length $total_header_len family $family protocol $protocol]
}

# ============================================================================
# iRule EVENT HANDLERS
# ============================================================================

when CLIENT_ACCEPTED {
    set static::tcp_pp_detected 0
    set static::tcp_pp_src_ip ""
    set static::tcp_pp_src_port ""
    set static::tcp_pp_dst_ip ""
    set static::tcp_pp_dst_port ""
    set static::tcp_pp_version ""
    set static::connection_protocol "http"
    
    # TRANSFORMATION STATE
    set static::transform_detected_source ""
    set static::transform_detected_value ""
    set static::transform_applied 0
    TCP::collect
}

when CLIENT_DATA {
    set tcplen [TCP::payload length]
    set proxy_detected 0
    set proxy_header_length 0
    
    # Check for Proxy Protocol v2 signature using constants
    if {$static::allowProxyV2 && $tcplen >= $::TCP_PP_V2_CHECK_LEN} {
        # Quick signature check first (optimization) using constants
        set first_signature_bytes [TCP::payload 0 $::PP_V2_SIGNATURE_LEN]
        if {[string length $first_signature_bytes] == $::PP_V2_SIGNATURE_LEN} {
            binary scan $first_signature_bytes H[expr {$::PP_V2_SIGNATURE_LEN * 2}] sig_hex
            if {$sig_hex eq $::PP_V2_SIGNATURE_HEX} {
                log local0.info "$::IRULE_NAME: PP v2 signature detected, parsing..."
                
                # Use the extracted procedure for parsing
                set pp_v2_result [call parse_proxy_protocol_v2 [TCP::payload]]
                
                # Extract result using array get for clean access
                array set pp_data $pp_v2_result
                
                if {$pp_data(success)} {
                    # Successfully parsed PP v2
                    set static::tcp_pp_detected 1
                    set static::tcp_pp_src_ip $pp_data(src_ip)
                    set static::tcp_pp_src_port $pp_data(src_port)
                    set static::tcp_pp_dst_ip $pp_data(dst_ip)
                    set static::tcp_pp_dst_port $pp_data(dst_port)
                    set static::tcp_pp_version "tcp-pp-v2-ipv4"
                    set proxy_detected 1
                    set proxy_header_length $pp_data(header_length)
                    log local0.info "$::IRULE_NAME: PP v2 IPv4 parsed successfully: $pp_data(src_ip):$pp_data(src_port) -> $pp_data(dst_ip):$pp_data(dst_port)"
                } else {
                    # Log the specific error
                    log local0.warning "$::IRULE_NAME: PP v2 parsing failed: $pp_data(error_msg)"
                }
            }
        }
    }
    
    # Check for Proxy Protocol v1 (if v2 not detected) using constants
    if {!$proxy_detected && $static::allowProxyV1 && $tcplen > $::TCP_PP_V1_CHECK_LEN} {
        if {[TCP::payload 0 $::PP_V1_SIGNATURE_LEN] eq $::PP_V1_SIGNATURE} {
            # Use the extracted procedure for parsing
            set pp_v1_result [call parse_proxy_protocol_v1 [TCP::payload]]
            
            # Extract result using array get for clean access
            array set pp_data $pp_v1_result
            
            if {$pp_data(success)} {
                # Successfully parsed PP v1
                set static::tcp_pp_detected 1
                set static::tcp_pp_src_ip $pp_data(src_ip)
                set static::tcp_pp_src_port $pp_data(src_port)
                set static::tcp_pp_dst_ip $pp_data(dst_ip)
                set static::tcp_pp_dst_port $pp_data(dst_port)
                set static::tcp_pp_version "tcp-pp-v1"
                set proxy_detected 1
                set proxy_header_length $pp_data(header_length)
                log local0.info "$::IRULE_NAME: PP v1 parsed: $pp_data(src_ip):$pp_data(src_port)"
            } else {
                # Log the specific error
                log local0.warning "$::IRULE_NAME: PP v1 parsing failed: $pp_data(error_msg)"
            }
        }
    }
    
    if {$proxy_detected && $proxy_header_length > 0} {
        TCP::payload replace 0 $proxy_header_length ""
    }
    TCP::release
}

when HTTP_REQUEST {
    if {$::PP_ADD_DIAGNOSTICS} {
        HTTP::header insert "X-iRule-Processed" "F5-Proxy-Protocol-Gateway-v$::IRULE_VERSION"
        HTTP::header insert "X-iRule-Original-Client" "[IP::client_addr]:[TCP::client_port]"
    }

    set pp_detected 0
    set pp_original_ip ""
    set pp_version ""
    set pp_status "no-proxy-protocol-detected"
    set pp_source_header ""

    # Check TCP PP first (highest priority)
    if {$static::tcp_pp_detected && $static::tcp_pp_src_ip ne ""} {
        set pp_detected 1
        set pp_original_ip $static::tcp_pp_src_ip
        set pp_version $static::tcp_pp_version
        
        if {$static::tcp_pp_version eq "tcp-pp-v1"} {
            set pp_status "tcp-proxy-protocol-v1-detected"
            set pp_source_header "TCP-Proxy-Protocol-v1"
        } else {
            if {$static::tcp_pp_version eq "tcp-pp-v2-ipv4"} {
                set pp_status "tcp-proxy-protocol-v2-ipv4-detected"
            } else {
                set pp_status "tcp-proxy-protocol-v2-detected"
            }
            set pp_source_header "TCP-Proxy-Protocol-v2"
        }
    }

    # Fallback to HTTP headers
    if {!$pp_detected} {
        foreach header $::PP_SOURCE_HEADERS {
            set value [HTTP::header value $header]
            if {$value ne ""} {
                set first_ip [string trim [lindex [split $value ","] 0]]
                # F5-native IP validation
                if {![catch {IP::addr $first_ip mask $::IP_VALIDATION_MASK}]} {
                    set pp_detected 1
                    set pp_original_ip $first_ip
                    set pp_version "http-header"
                    set pp_status "http-proxy-headers-detected"
                    set pp_source_header $header
                    break
                }
            }
        }
    }

    # ========================================================================
    # Header normalization (transform mode only)
    # ========================================================================
    if {$pp_detected && $::PP_NORMALIZE_HEADERS && $::PP_MODE eq "transform"} {
        foreach target $::PP_TARGET_HEADERS {
            HTTP::header replace $target $pp_original_ip
        }
    }

    # TRANSFORMATION LOGIC (Client => Server) - ONLY in transform mode
    if {$::PP_MODE eq "transform" && $::PP_TRANSFORM_SOURCE ne ""} {
        set transform_source_value ""
        
        # Detect source value
        if {$::PP_TRANSFORM_SOURCE eq "ppv1" && $static::tcp_pp_version eq "tcp-pp-v1"} {
            set transform_source_value $static::tcp_pp_src_ip
            set static::transform_detected_source "ppv1"
        } elseif {$::PP_TRANSFORM_SOURCE eq "ppv2" && [string match "*v2*" $static::tcp_pp_version]} {
            set transform_source_value $static::tcp_pp_src_ip
            set static::transform_detected_source "ppv2"
        } elseif {[string match "X-*" $::PP_TRANSFORM_SOURCE] || [string match "CF-*" $::PP_TRANSFORM_SOURCE]} {
            set header_value [HTTP::header value $::PP_TRANSFORM_SOURCE]
            if {$header_value ne ""} {
                set transform_source_value [string trim [lindex [split $header_value ","] 0]]
                set static::transform_detected_source $::PP_TRANSFORM_SOURCE
            }
        }
        
        # Apply transformation if source detected
        if {$transform_source_value ne ""} {
            set static::transform_detected_value $transform_source_value
            
            # Transform to target
            if {[string match "X-*" $::PP_TRANSFORM_TARGET] || [string match "CF-*" $::PP_TRANSFORM_TARGET]} {
                # Transform to HTTP header
                HTTP::header replace $::PP_TRANSFORM_TARGET $transform_source_value
                set static::transform_applied 1
                if {$::PP_LOG_TRANSFORMATIONS} {
                   log local0.info "$::IRULE_NAME: Transformed ${::PP_TRANSFORM_SOURCE} => ${::PP_TRANSFORM_TARGET} (value: $transform_source_value)"
                }
            }
            # Note: PP target transformations will be handled in SERVER_CONNECTED event
        }
    }
    
    # DIAGNOSTIC HEADERS FOR BACKEND ECHO
    if {$::PP_ADD_DIAGNOSTICS} {
        HTTP::header insert "X-F5-PP-Mode" $::PP_MODE
        # Only add transform-specific headers in transform mode when transformation was applied
        if {$::PP_MODE eq "transform" && $static::transform_applied} {
            HTTP::header insert "X-F5-PP-Transform-Source" "$static::transform_detected_source:$static::transform_detected_value"
            HTTP::header insert "X-F5-PP-Transform-Target" "$::PP_TRANSFORM_TARGET:$static::transform_detected_value"
            HTTP::header insert "X-F5-PP-Transform-Rule" $::PP_TRANSFORM_RULE
        }
    }
    
    # Add comprehensive diagnostics
    if {$::PP_ADD_DIAGNOSTICS} {
        HTTP::header insert "X-iRule-PP-Status" $pp_status
        if {$pp_detected} {
            HTTP::header insert "X-iRule-PP-Version" $pp_version
            HTTP::header insert "X-iRule-PP-Original-IP" $pp_original_ip
            HTTP::header insert "X-iRule-PP-Source-Header" $pp_source_header
            
            # TCP PP specific diagnostics
            if {$static::tcp_pp_version ne ""} {
                HTTP::header insert "X-iRule-PP-TCP-Src" "$static::tcp_pp_src_ip:$static::tcp_pp_src_port"
                HTTP::header insert "X-iRule-PP-TCP-Dst" "$static::tcp_pp_dst_ip:$static::tcp_pp_dst_port"
            }
        }
    }
}

when SERVER_CONNECTED {
    # Handle transformations to PP targets (ppv1/ppv2) - ONLY in transform mode
    # Note: Transformations to ppv1/ppv2 are planned for future implementation
    # Current version focuses on HTTP header targets for maximum compatibility
    if {$::PP_MODE eq "transform" && $static::transform_detected_value ne ""} {
        if {$::PP_TRANSFORM_TARGET eq "ppv1" || $::PP_TRANSFORM_TARGET eq "ppv2"} {
            if {$::PP_LOG_TRANSFORMATIONS} {
                log local0.info "$::IRULE_NAME: PP target transformation ($::PP_TRANSFORM_TARGET) will be available in future releases"
            }
        }
    }
}

when HTTP_RESPONSE {
    if {$::PP_ADD_DIAGNOSTICS} {
        HTTP::header insert "X-iRule-Processed" "F5-Proxy-Protocol-Gateway-v$::IRULE_VERSION"
        HTTP::header insert "X-iRule-PP-Status" "processed-in-request"
        
        # REMOVE DIAGNOSTIC HEADERS (stealth mode)
        HTTP::header remove "X-F5-PP-Mode"
        HTTP::header remove "X-F5-PP-Transform-Source"
        HTTP::header remove "X-F5-PP-Transform-Target"
        HTTP::header remove "X-F5-PP-Transform-Rule"
    }
}
