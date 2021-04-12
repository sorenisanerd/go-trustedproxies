package trustedproxies

import (
	"fmt"
	"net"
	"reflect"
	"testing"
)

var exampleIPv6Address string = "2001:0db8:85a3:0000:0000:8a2e:0370:7334"

func Test_netFromIPOrCIDR(t *testing.T) {
	tests := []struct {
		name    string
		arg     string
		want    *net.IPNet
		wantErr bool
	}{
		{"IPv4 with mask", "192.168.10.10/25", optimisticParseCIDR("192.168.10.10/25"), false},
		{"IPv6 with mask", "2001:0db8:85a3:0000:0000:8a2e:0370:7334/123", optimisticParseCIDR("2001:0db8:85a3:0000:0000:8a2e:0370:7334/123"), false},
		{"IPv6 in brackets with mask", "[2001:0db8:85a3:0000:0000:8a2e:0370:7334]/123", nil, true},
		{"IPv4 without mask", "192.168.10.10", optimisticParseCIDR("192.168.10.10/32"), false},
		{"IPv6 without mask", "2001:0db8:85a3:0000:0000:8a2e:0370:7334", optimisticParseCIDR("2001:0db8:85a3:0000:0000:8a2e:0370:7334/128"), false},
		{"IPv6 with brackets, without mask", "2001:0db8:85a3:0000:0000:8a2e:0370:7334", optimisticParseCIDR("2001:0db8:85a3:0000:0000:8a2e:0370:7334/128"), false},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got, err := netFromIPOrCIDR(tt.arg)
			if (err != nil) != tt.wantErr {
				t.Errorf("netFromIPOrCIDR() error = %v, wantErr %v", err, tt.wantErr)
				return
			}
			if !reflect.DeepEqual(got, tt.want) {
				t.Errorf("netFromIPOrCIDR() = %v, want %v", got, tt.want)
			}
		})
	}
}

func optimisticParseCIDR(s string) *net.IPNet {
	_, ipnet, err := net.ParseCIDR(s)
	fmt.Print(err)
	return ipnet
}

func TestTrustedProxies(t *testing.T) {
	tests := []struct {
		name       string
		TrustedIPs []string
		IPToCheck  string
		want       *net.IPNet
	}{
		{"Empty trust list, check ipv4", []string{}, "192.168.10.2", nil},
		{"Empty trust list, check ipv6", []string{}, exampleIPv6Address, nil},
		{"Match ipv4", []string{"192.168.10.10/24"}, "192.168.10.2", optimisticParseCIDR("192.168.10.10/24")},
		{"Match ipv4, weird accepted ipnet", []string{"192.168.10.10/24", "this is not valid"}, "192.168.10.2", optimisticParseCIDR("192.168.10.10/24")},
		{"Match ipv6", []string{exampleIPv6Address}, exampleIPv6Address, optimisticParseCIDR(exampleIPv6Address + "/128")},
		{"No match", []string{"192.168.10.10/24"}, "192.168.11.2", nil},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tr := New()
			for _, spec := range tt.TrustedIPs {
				tr.AddFromString(spec)
			}
			ip := net.ParseIP(tt.IPToCheck)

			matchingIPNet := tr.IsIPTrusted(&ip)
			if !reflect.DeepEqual(matchingIPNet, tt.want) {
				t.Errorf("TrustedProxies.IsIPTrusted() = %v, wanted %v", matchingIPNet, tt.want)
			}
		})
	}
}

func Test_headerToIPs(t *testing.T) {
	tests := []struct {
		name        string
		headerValue string
		want        []string
	}{
		{"Empty", "", []string{}},
		{"Almost empty", " ", []string{}},
		{"Single IP", "10.10.10.10", []string{"10.10.10.10"}},
		{"Two IPs", "10.10.10.10, 20.20.20.20", []string{"10.10.10.10", "20.20.20.20"}},
		{"IP + nonsense + IP", "10.10.10.10, ugh, 20.20.20.20", []string{"10.10.10.10", "", "20.20.20.20"}},
		{"IP + empty", "10.10.10.10, , 20.20.20.20", []string{"10.10.10.10", "", "20.20.20.20"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			realWant := getRealWant(tt.want)
			if got := headerToIPs(tt.headerValue); !reflect.DeepEqual(got, realWant) {
				t.Errorf("headerToIPs() = %v, want %v", got, tt.want)
			}
		})
	}
}
func getRealWant(wants []string) []*net.IP {
	realWant := []*net.IP{}
	for _, ip := range wants {
		if ip == "" {
			var nilIP net.IP
			realWant = append(realWant, &nilIP)
			continue
		}
		ipObj := net.ParseIP(ip)
		realWant = append(realWant, &ipObj)
	}
	return realWant
}

func TestTrustedProxies_filterOutIPsFromUntrustedSources(t *testing.T) {
	type args struct {
		remoteAddr net.IP
		header     string
	}
	tests := []struct {
		name         string
		trustedCIDRs []string
		args         args
		want         []string
	}{
		{"No/empty header", []string{}, args{net.ParseIP("10.10.10.10"), ""}, []string{"10.10.10.10"}},
		{"Bogus header, untrusted remote", []string{}, args{net.ParseIP("10.10.10.10"), " 1 2 2 horse 43 2 2 1 "}, []string{"10.10.10.10"}},
		{"Bogus header, trusted remote", []string{"10.10.10.10"}, args{net.ParseIP("10.10.10.10"), " 1 2 2 horse 43 2 2 1 "}, []string{"10.10.10.10"}},
		{"Single IP in header, no one is trusted", []string{}, args{net.ParseIP("10.10.10.10"), "20.20.20.20"}, []string{"10.10.10.10"}},
		{"Single IP in header, remoteAddr is trusted", []string{"10.10.10.10"}, args{net.ParseIP("10.10.10.10"), "20.20.20.20"}, []string{"10.10.10.10", "20.20.20.20"}},
		{"Two IPs in header, remoteAddr is trusted, second header IP is trusted",
			[]string{"10.10.10.10", "20.20.20.20"},
			args{net.ParseIP("10.10.10.10"), "30.30.30.30, 20.20.20.20"},
			[]string{"10.10.10.10", "20.20.20.20", "30.30.30.30"}},
		{"Two IPs in header, remoteAddr is trusted, first header IP is trusted",
			[]string{"10.10.10.10", "30.30.30.30"},
			args{net.ParseIP("10.10.10.10"), "30.30.30.30, 20.20.20.20"},
			[]string{"10.10.10.10", "20.20.20.20"}},
		{"Two IPs in header, remoteAddr is NOT trusted, first header IP is trusted",
			[]string{"30.30.30.30"},
			args{net.ParseIP("10.10.10.10"), "30.30.30.30, 20.20.20.20"},
			[]string{"10.10.10.10"}},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tr := New()
			for _, t := range tt.trustedCIDRs {
				tr.AddFromString(t)
			}
			realWant := getRealWant(tt.want)
			if got := tr.filterOutIPsFromUntrustedSources(tt.args.remoteAddr, tt.args.header); !reflect.DeepEqual(got, realWant) {
				t.Errorf("TrustedProxies.filterOutIPsFromUntrustedSources() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestTrustedProxies_DeduceClientIP(t *testing.T) {
	type args struct {
		remoteAddr net.IP
		header     string
	}
	tests := []struct {
		name         string
		trustedCIDRs []string
		args         args
		want         string
	}{
		{"No/empty header", []string{}, args{net.ParseIP("10.10.10.10"), ""}, "10.10.10.10"},
		{"Single IP in header, no one is trusted", []string{}, args{net.ParseIP("10.10.10.10"), "20.20.20.20"}, "10.10.10.10"},
		{"Single IP in header, remoteAddr is trusted", []string{"10.10.10.10"}, args{net.ParseIP("10.10.10.10"), "20.20.20.20"}, "20.20.20.20"},
		{"Two IPs in header, remoteAddr is trusted, second header IP is trusted",
			[]string{"10.10.10.10", "20.20.20.20"},
			args{net.ParseIP("10.10.10.10"), "30.30.30.30, 20.20.20.20"},
			"30.30.30.30"},
		{"Two IPs in header, remoteAddr is trusted, first header IP is trusted",
			[]string{"10.10.10.10", "30.30.30.30"},
			args{net.ParseIP("10.10.10.10"), "30.30.30.30, 20.20.20.20"},
			"20.20.20.20"},
		{"Two IPs in header, remoteAddr is NOT trusted, first header IP is trusted",
			[]string{"30.30.30.30"},
			args{net.ParseIP("10.10.10.10"), "30.30.30.30, 20.20.20.20"},
			"10.10.10.10"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			tr := New()
			for _, t := range tt.trustedCIDRs {
				tr.AddFromString(t)
			}
			realWant := net.ParseIP(tt.want)
			if got := tr.DeduceClientIP(tt.args.remoteAddr, tt.args.header); !reflect.DeepEqual(got, &realWant) {
				t.Errorf("TrustedProxies.filterOutIPsFromUntrustedSources() = %v, want %v", got, &realWant)
			}
		})
	}
}

func TestFromREADME(t *testing.T) {
	tp := New()
	// Suppose our proxy is 10.10.10.10
	tp.AddFromString("10.10.10.10")

	// There might be another proxy in front of that one, so let's add that, too.
	tp.AddFromString("20.20.20.20")

	XForwardedFor := "40.40.40.40, 30.30.30.30, 20.20.20.20"

	ourProxyAddress := net.ParseIP("10.10.10.10")

	checkedIP := tp.DeduceClientIP(ourProxyAddress, XForwardedFor)

	want := "30.30.30.30"

	if checkedIP.String() != "30.30.30.30" {
		t.Errorf("Test from README failed. got = %v, wanted %v", checkedIP, want)
		return
	}
}
