package main

import (
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestBuildTraceFilters(t *testing.T) {
	tests := []struct {
		name     string
		host     string
		filter   string
		ipv6     bool
		expected []string
		wantErr  bool
	}{
		{name: "filter only", filter: "-p icmp", expected: []string{"-p icmp"}},
		{name: "IPv4 host", host: "10.1.50.11", expected: []string{"-s 10.1.50.11", "-d 10.1.50.11"}},
		{name: "IPv4 host with filter", host: "10.1.50.11", filter: "-p tcp --dport 443", expected: []string{"-s 10.1.50.11 -p tcp --dport 443", "-d 10.1.50.11 -p tcp --dport 443"}},
		{name: "IPv6 host", host: "2001:db8::11", ipv6: true, expected: []string{"-s 2001:db8::11", "-d 2001:db8::11"}},
		{name: "invalid host", host: "not-an-ip", wantErr: true},
		{name: "IPv4 host with IPv6 mode", host: "10.1.50.11", ipv6: true, wantErr: true},
		{name: "IPv6 host with IPv4 mode", host: "2001:db8::11", wantErr: true},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, err := buildTraceFilters(test.host, test.filter, test.ipv6)
			if (err != nil) != test.wantErr {
				t.Fatalf("buildTraceFilters() error = %v, wantErr %v", err, test.wantErr)
			}
			if !cmp.Equal(got, test.expected) {
				t.Errorf("buildTraceFilters() = %v, expected %v", got, test.expected)
			}
		})
	}
}

func TestExtendIptablesPolicyFilters(t *testing.T) {
	policy := []string{
		"*filter",
		":FORWARD ACCEPT [0:0]",
		"COMMIT",
	}
	expectedPolicy := []string{
		"*filter",
		":FORWARD ACCEPT [0:0]",
		"-I FORWARD -s 10.1.50.11 -p icmp -j NFLOG --nflog-prefix \"iptr:7:0\" --nflog-group 22",
		"-I FORWARD -d 10.1.50.11 -p icmp -j NFLOG --nflog-prefix \"iptr:7:1\" --nflog-group 22",
		"COMMIT",
	}
	expectedRuleMap := map[int]iptablesRule{
		0: {Table: "filter", Chain: "FORWARD", ChainEntry: true},
		1: {Table: "filter", Chain: "FORWARD", ChainEntry: true},
	}

	gotPolicy, gotRuleMap, gotMaxLength := extendIptablesPolicyFilters(
		policy, 7, []string{"-s 10.1.50.11 -p icmp", "-d 10.1.50.11 -p icmp"}, 0, 0, false, true, 22,
	)
	if !cmp.Equal(gotPolicy, expectedPolicy) {
		t.Errorf("extendIptablesPolicyFilters() policy = %q, expected %q", gotPolicy, expectedPolicy)
	}
	if !cmp.Equal(gotRuleMap, expectedRuleMap) {
		t.Errorf("extendIptablesPolicyFilters() rule map = %v, expected %v", gotRuleMap, expectedRuleMap)
	}
	if gotMaxLength != len("FORWARD") {
		t.Errorf("extendIptablesPolicyFilters() max length = %d, expected %d", gotMaxLength, len("FORWARD"))
	}
}
