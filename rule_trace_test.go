package main

import (
	"testing"

	"github.com/google/go-cmp/cmp"
)

func TestExtendIptablesPolicyWithHostRuleTracing(t *testing.T) {
	policy := []string{
		"*filter",
		":FORWARD ACCEPT [0:0]",
		":zone_vpn - [0:0]",
		"-A FORWARD -j zone_vpn",
		"-A zone_vpn -o vpn0 -j ACCEPT",
		"COMMIT",
	}
	expectedPolicy := []string{
		"*filter",
		":FORWARD ACCEPT [0:0]",
		":zone_vpn - [0:0]",
		"-A FORWARD -s 10.1.50.10 -j NFLOG --nflog-prefix \"iptr:7:0\" --nflog-group 22",
		"-A FORWARD -d 10.1.50.10 -j NFLOG --nflog-prefix \"iptr:7:1\" --nflog-group 22",
		"-A FORWARD -j zone_vpn",
		"-A zone_vpn -s 10.1.50.10 -o vpn0 -j NFLOG --nflog-prefix \"iptr:7:2\" --nflog-group 22",
		"-A zone_vpn -d 10.1.50.10 -o vpn0 -j NFLOG --nflog-prefix \"iptr:7:3\" --nflog-group 22",
		"-A zone_vpn -o vpn0 -j ACCEPT",
		"-I FORWARD -s 10.1.50.10 -j NFLOG --nflog-prefix \"iptr:7:4\" --nflog-group 22",
		"-I FORWARD -d 10.1.50.10 -j NFLOG --nflog-prefix \"iptr:7:5\" --nflog-group 22",
		"-I zone_vpn -s 10.1.50.10 -j NFLOG --nflog-prefix \"iptr:7:6\" --nflog-group 22",
		"-I zone_vpn -d 10.1.50.10 -j NFLOG --nflog-prefix \"iptr:7:7\" --nflog-group 22",
		"COMMIT",
	}
	expectedRuleMap := map[int]iptablesRule{
		0: {Table: "filter", Chain: "FORWARD", Rule: "-j zone_vpn"},
		1: {Table: "filter", Chain: "FORWARD", Rule: "-j zone_vpn"},
		2: {Table: "filter", Chain: "zone_vpn", Rule: "-o vpn0 -j ACCEPT"},
		3: {Table: "filter", Chain: "zone_vpn", Rule: "-o vpn0 -j ACCEPT"},
		4: {Table: "filter", Chain: "FORWARD", ChainEntry: true},
		5: {Table: "filter", Chain: "FORWARD", ChainEntry: true},
		6: {Table: "filter", Chain: "zone_vpn", ChainEntry: true},
		7: {Table: "filter", Chain: "zone_vpn", ChainEntry: true},
	}

	gotPolicy, gotRuleMap, gotMaxLength := extendIptablesPolicyFilters(
		policy, 7, []string{"-s 10.1.50.10", "-d 10.1.50.10"}, 0, 0, true, 22,
	)
	if !cmp.Equal(gotPolicy, expectedPolicy) {
		t.Errorf("extendIptablesPolicyFilters() policy = %q, expected %q", gotPolicy, expectedPolicy)
	}
	if !cmp.Equal(gotRuleMap, expectedRuleMap) {
		t.Errorf("extendIptablesPolicyFilters() rule map = %v, expected %v", gotRuleMap, expectedRuleMap)
	}
	if gotMaxLength != len("zone_vpn") {
		t.Errorf("extendIptablesPolicyFilters() max length = %d, expected %d", gotMaxLength, len("zone_vpn"))
	}
}

func TestResolveHostRuleFilter(t *testing.T) {
	tests := []struct {
		name     string
		trace    string
		rule     string
		expected string
		ok       bool
	}{
		{name: "deduplicate protocol", trace: "-s 10.1.50.10 -p icmp", rule: "-p icmp -m icmp --icmp-type 8", expected: "-s 10.1.50.10 -p icmp -m icmp --icmp-type 8", ok: true},
		{name: "conflicting protocol", trace: "-s 10.1.50.10 -p icmp", rule: "-p tcp --dport 80"},
		{name: "matching source subnet", trace: "-s 10.1.50.10 -p icmp", rule: "-s 10.1.50.0/24 -j ACCEPT", expected: "-p icmp -s 10.1.50.0/24 -j ACCEPT", ok: true},
		{name: "conflicting source subnet", trace: "-s 10.1.50.10", rule: "-s 192.0.2.0/24"},
		{name: "negated source permits host", trace: "-s 10.1.50.10", rule: "! -s 192.0.2.0/24", expected: "-s 10.1.50.10 ! -s 192.0.2.0/24", ok: true},
		{name: "negated source excludes host", trace: "-s 10.1.50.10", rule: "! -s 10.1.50.0/24"},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			got, ok := resolveHostRuleFilter(test.trace, test.rule)
			if got != test.expected || ok != test.ok {
				t.Errorf("resolveHostRuleFilter(%q, %q) = %q, %v; expected %q, %v", test.trace, test.rule, got, ok, test.expected, test.ok)
			}
		})
	}
}

func TestRuleMatchFilter(t *testing.T) {
	tests := map[string]string{
		"-j ACCEPT":         "",
		"-g zone_vpn":       "",
		"-o vpn0 -j ACCEPT": "-o vpn0",
		"-p icmp -m icmp --icmp-type 8 -j ACCEPT": "-p icmp -m icmp --icmp-type 8",
	}
	for rule, expected := range tests {
		if got := ruleMatchFilter(rule); got != expected {
			t.Errorf("ruleMatchFilter(%q) = %q, expected %q", rule, got, expected)
		}
	}
}
