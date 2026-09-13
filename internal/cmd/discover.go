package cmd

import (
	"context"
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strconv"
	"strings"
	"time"
	"unicode"

	"github.com/router-for-me/CLIProxyAPI/v7/internal/discovery"
)

// DoDiscover executes the LAN AI gateway discovery workflow and outputs results.
// Returns 0 on success, 1 on error.
func DoDiscover(timeout time.Duration, jsonOutput bool) int {
	if timeout <= 0 {
		timeout = 3 * time.Second
	} else if timeout > 60*time.Second {
		timeout = 60 * time.Second
	}

	if !jsonOutput {
		fmt.Printf("Scanning LAN for AI Gateways (%s)... (timeout %v)\n", discovery.DefaultServiceType, timeout)
	}

	ctx, cancel := context.WithTimeout(context.Background(), timeout+1*time.Second)
	defer cancel()

	browser := discovery.NewZeroconfBrowser()
	gateways, err := browser.BrowseWithFallback(ctx, timeout)
	if err != nil {
		if jsonOutput {
			out, _ := json.MarshalIndent(map[string]any{"error": err.Error(), "gateways": []any{}}, "", "  ")
			fmt.Println(string(out))
		} else {
			fmt.Fprintf(os.Stderr, "Error scanning LAN: %v\n", err)
		}
		return 1
	}

	if gateways == nil {
		gateways = []discovery.DiscoveredService{}
	}

	if jsonOutput {
		out, errMarshal := json.MarshalIndent(gateways, "", "  ")
		if errMarshal != nil {
			fmt.Fprintf(os.Stderr, "failed to marshal results: %v\n", errMarshal)
			return 1
		}
		fmt.Println(string(out))
		return 0
	}

	if len(gateways) == 0 {
		fmt.Println("\nNo AI gateways found on local network.")
		fmt.Println("Tips:")
		fmt.Println("  1. Ensure the target CPA instance has 'discovery.enabled: true' in its config.yaml.")
		fmt.Println("  2. Ensure your device is on the same local Wi-Fi / Ethernet subnet (mDNS does not traverse WAN).")
		fmt.Println("  3. Check that your local firewall allows UDP port 5353 multicast traffic.")
		return 0
	}

	fmt.Printf("\nFound %d AI Gateway(s) on local network:\n\n", len(gateways))
	for i, gw := range gateways {
		productLabel := sanitizeTerminal(gw.Product)
		if productLabel == "" {
			productLabel = "generic"
		}
		versionLabel := sanitizeTerminal(gw.Version)
		if versionLabel == "" {
			versionLabel = "unknown"
		}

		instanceLabel := sanitizeTerminal(gw.InstanceName)
		fmt.Printf("[%d] %s (Product: %s, Version: %s)\n", i+1, instanceLabel, productLabel, versionLabel)

		// Primary IP selection
		primaryIP := "127.0.0.1"
		var allIPs []string
		for _, ip := range gw.IPv4 {
			if !ip.IsLoopback() {
				allIPs = append(allIPs, ip.String())
			}
		}
		if len(allIPs) > 0 {
			primaryIP = allIPs[0]
		} else if len(gw.IPv6) > 0 {
			primaryIP = gw.IPv6[0].String()
			for _, ip := range gw.IPv6 {
				allIPs = append(allIPs, ip.String())
			}
		}

		hostPort := net.JoinHostPort(primaryIP, strconv.Itoa(gw.Port))
		hostLabel := sanitizeTerminal(gw.Host)
		fmt.Printf("    Host:      %s (%s)\n", hostLabel, hostPort)
		if len(allIPs) > 1 {
			fmt.Printf("    Addresses: %s\n", strings.Join(allIPs, ", "))
		}

		if len(gw.Protocols) > 0 {
			var safeProtocols []string
			for _, p := range gw.Protocols {
				safeProtocols = append(safeProtocols, sanitizeTerminal(p))
			}
			fmt.Printf("    Protocols: %s\n", strings.Join(safeProtocols, ", "))
		}
		if len(gw.Features) > 0 {
			var safeFeatures []string
			for _, f := range gw.Features {
				safeFeatures = append(safeFeatures, sanitizeTerminal(f))
			}
			fmt.Printf("    Features:  %s\n", strings.Join(safeFeatures, ", "))
		}

		authStatus := "No"
		if gw.AuthRequired {
			authStatus = "Required"
			if len(gw.AuthMethods) > 0 {
				var safeMethods []string
				for _, m := range gw.AuthMethods {
					safeMethods = append(safeMethods, sanitizeTerminal(m))
				}
				authStatus = fmt.Sprintf("Required (%s)", strings.Join(safeMethods, ", "))
			}
		}
		fmt.Printf("    Auth:      %s\n", authStatus)

		// Endpoints display
		scheme := "http"
		if gw.RawTXT["tls"] == "1" {
			scheme = "https"
		}

		fmt.Printf("    Base URLs:\n")
		if openAIPath, ok := gw.Endpoints["openai"]; ok {
			fmt.Printf("      - OpenAI:    %s://%s%s\n", scheme, hostPort, sanitizeTerminal(openAIPath))
		} else {
			fmt.Printf("      - OpenAI:    %s://%s/v1\n", scheme, hostPort)
		}

		if anthropicPath, ok := gw.Endpoints["anthropic"]; ok {
			fmt.Printf("      - Anthropic: %s://%s%s\n", scheme, hostPort, sanitizeTerminal(anthropicPath))
		}
		if geminiPath, ok := gw.Endpoints["gemini"]; ok {
			fmt.Printf("      - Gemini:    %s://%s%s\n", scheme, hostPort, sanitizeTerminal(geminiPath))
		}

		fmt.Println()
	}

	return 0
}

// sanitizeTerminal strips control characters, ANSI escape sequences, Bidi overrides,
// and invisible Unicode format characters to prevent terminal injection and spoofing.
func sanitizeTerminal(s string) string {
	var b strings.Builder
	for _, r := range s {
		if r == '\t' {
			b.WriteRune(' ')
			continue
		}
		// Allow safe printable runes; block Bidi controls, zero-width chars, and line/paragraph separators
		if unicode.IsPrint(r) && !unicode.Is(unicode.Bidi_Control, r) {
			if r != '\u2028' && r != '\u2029' && !(r >= 0x200B && r <= 0x200F) && r != '\uFEFF' && r != 0x00AD {
				b.WriteRune(r)
			}
		}
	}
	return b.String()
}
