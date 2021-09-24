package trustedproxies

import (
	"errors"
	"fmt"
	"net"
	"strings"
)

// ErrInvalidIPSpecification indicates the IP specification is invalid and cannot be parsed.
var ErrInvalidIPSpecification = errors.New("invalid IP specification")

type TrustedProxies struct {
	trustedCIDRs []*net.IPNet
}

// New provides an initialized TrustedProxies
func New() *TrustedProxies {
	return &TrustedProxies{
		trustedCIDRs: []*net.IPNet{},
	}
}

// AddFromString adds a trusted proxy (IP or CIDR) to the list
func (t *TrustedProxies) AddFromString(s string) error {
	ipnet, err := netFromIPOrCIDR(s)
	if err != nil {
		return nil
	}
	t.trustedCIDRs = append(t.trustedCIDRs, ipnet)
	return nil
}

// IsIPTrusted checks if a given IP is trusted. Returns the matching
// net.IPNet or nil if there is no match
func (t *TrustedProxies) IsIPTrusted(ip *net.IP) *net.IPNet {
	for _, ipnet := range t.trustedCIDRs {
		if ipnet.Contains(*ip) {
			return ipnet
		}
	}
	return nil
}

func netFromIPOrCIDR(s string) (*net.IPNet, error) {
	_, ipnet, err := net.ParseCIDR(s)
	if err == nil {
		return ipnet, nil
	}
	ip := net.ParseIP(s)
	if ip == nil {
		return nil, fmt.Errorf("%w: %s", ErrInvalidIPSpecification, s)
	}

	ipv4 := ip.To4()
	if ipv4 != nil {
		ip = ipv4
	}

	mask := net.CIDRMask(8*len(ip), 8*len(ip))
	return &net.IPNet{ip, mask}, nil
}

// DeduceClientIP filters out untrusted information from the header
// and returns the closest approximation of the client IP
func (t *TrustedProxies) DeduceClientIP(remoteAddr net.IP, header string) *net.IP {
	trustedIPs := t.filterOutIPsFromUntrustedSources(remoteAddr, header)
	return trustedIPs[len(trustedIPs)-1]
}

func (t *TrustedProxies) filterOutIPsFromUntrustedSources(remoteAddr net.IP, header string) []*net.IP {
	rv := []*net.IP{}
	ips := headerToIPs(header)

	// We need to consider remoteAddr, too
	ips = append(ips, &remoteAddr)

	// Moving backwards!
	idx := len(ips) - 1
	for {
		ip := ips[idx]
		if ip == nil || *ip == nil {
			break
		}

		rv = append(rv, ip)
		if t.IsIPTrusted(ip) != nil {
			idx--
		} else {
			// If we come across an IP that isn't trusted, we stop processing
			break
		}
	}
	return rv
}

func headerToIPs(headerValue string) []*net.IP {
	rv := []*net.IP{}
	items := strings.Split(headerValue, ",")

	if len(items) == 1 && strings.TrimSpace(items[0]) == "" {
		return rv
	}

	for _, val := range items {
		val = strings.TrimSpace(val)
		ip := net.ParseIP(val)
		rv = append(rv, &ip)
	}
	return rv
}
