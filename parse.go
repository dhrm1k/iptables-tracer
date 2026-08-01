package main

import (
	"fmt"
	"log"
	"net"
	"regexp"
	"strconv"
	"strings"
)

var (
	chainRe  = regexp.MustCompile(`^:(\S+)`)
	tableRe  = regexp.MustCompile(`^\*(\S+)`)
	ruleRe   = regexp.MustCompile(`^-[AI]\s+(\S+)\s+(.*)$`)
	commitRe = regexp.MustCompile(`^COMMIT`)

	ruleFilterRe     = regexp.MustCompile(`(.*)\s+-[gj]\s+.*$`)
	ruleFilterMarkRe = regexp.MustCompile(`(!\s+)?--mark\s+\S+`)
)

func extendIptablesPolicy(lines []string, traceID int, traceFilter string, fwMark, packetLimit int, traceRules, traceChains bool, nflogGroup int) ([]string, map[int]iptablesRule, int) {
	return extendIptablesPolicyFilters(lines, traceID, []string{traceFilter}, fwMark, packetLimit, traceRules, traceChains, nflogGroup)
}

func extendIptablesPolicyFilters(lines []string, traceID int, traceFilters []string, fwMark, packetLimit int, traceRules, traceChains bool, nflogGroup int) ([]string, map[int]iptablesRule, int) {
	var newIptablesConfig []string
	maxChainNameLength := 0
	ruleMap := make(map[int]iptablesRule)
	chainMap := make(map[string][]string)

	markFilter := ""
	if fwMark != 0 {
		markFilter = fmt.Sprintf("-m mark --mark 0x%x/0x%x", fwMark, fwMark)
	}

	table := ""
	ruleIndex := 0
	for _, line := range lines {
		if res := chainRe.FindStringSubmatch(line); res != nil {
			if table == "" {
				log.Fatal("Error: found chain definition before initial table definition")
			}
			chainMap[table] = append(chainMap[table], res[1])
			if len(res[1]) > maxChainNameLength {
				maxChainNameLength = len(res[1])
			}
		}
		if res := commitRe.FindStringSubmatch(line); res != nil {
			// We are at the end of a table; add the requested probes to its chains.
			for _, chain := range chainMap[table] {
				if traceChains {
					for _, traceFilter := range traceFilters {
						ruleMap[ruleIndex] = iptablesRule{Table: table, Chain: chain, ChainEntry: true}
						traceRule := buildTraceRule("-I", chain, []string{traceFilter, markFilter}, traceID, ruleIndex, nflogGroup)
						ruleIndex++
						newIptablesConfig = append(newIptablesConfig, traceRule)
						if table == "raw" && chain == "PREROUTING" && fwMark != 0 && (packetLimit != 0 || traceRules) {
							newIptablesConfig = append(newIptablesConfig, buildMarkRule("-I", chain, traceFilter, traceID, packetLimit, fwMark))
						}
					}
				} else if table == "raw" && chain == "PREROUTING" && fwMark != 0 && (packetLimit != 0 || traceRules) {
					for _, traceFilter := range traceFilters {
						newIptablesConfig = append(newIptablesConfig, buildMarkRule("-I", chain, traceFilter, traceID, packetLimit, fwMark))
					}
				}
			}
		}
		if res := tableRe.FindStringSubmatch(line); res != nil {
			table = res[1]
		}
		if res := ruleRe.FindStringSubmatch(line); res != nil && traceRules {
			if table == "" {
				log.Fatal("Error: found rule definition before initial table definition")
			}
			if fwMark == 0 {
				for _, traceFilter := range traceFilters {
					resolvedFilter, ok := resolveTraceRuleFilter(traceFilter, ruleMatchFilter(res[2]))
					if !ok {
						continue
					}
					ruleMap[ruleIndex] = iptablesRule{Table: table, Chain: res[1], Rule: res[2]}
					traceRule := buildTraceRule("-A", res[1], []string{resolvedFilter}, traceID, ruleIndex, nflogGroup)
					ruleIndex++
					newIptablesConfig = append(newIptablesConfig, traceRule)
				}
			} else {
				if resolvedRuleFilter, ok := resolveRuleFilterAndMergeMark(res[2], fwMark); !ok {
					log.Fatalf("Error: fwMark conflicts with the rule: %s, choose another proper value", line)
				} else {
					ruleMap[ruleIndex] = iptablesRule{Table: table, Chain: res[1], Rule: res[2]}
					traceRule := buildTraceRule("-A", res[1], resolvedRuleFilter, traceID, ruleIndex, nflogGroup)
					ruleIndex++
					newIptablesConfig = append(newIptablesConfig, traceRule)
				}
			}
		}
		newIptablesConfig = append(newIptablesConfig, line)
	}

	return newIptablesConfig, ruleMap, maxChainNameLength
}

func clearIptablesPolicy(policy []string, cleanupID int) []string {
	var newIptablesConfig []string
	iptrRe := regexp.MustCompile(`\s+--nflog-prefix\s+"iptr:(\d+):\d+"`)
	limitRe := regexp.MustCompile(`\s+--comment\s+"iptr:(\d+):mark"`)
	for _, line := range policy {
		if res := iptrRe.FindStringSubmatch(line); res != nil {
			if id, _ := strconv.Atoi(res[1]); id == cleanupID || cleanupID == 0 {
				continue
			}
		}
		if res := limitRe.FindStringSubmatch(line); res != nil {
			if id, _ := strconv.Atoi(res[1]); id == cleanupID || cleanupID == 0 {
				continue
			}
		}
		newIptablesConfig = append(newIptablesConfig, line)
	}
	return newIptablesConfig
}

func buildMarkRule(command, chain, traceFilter string, traceID, packetLimit, fwMark int) string {
	rule := []string{command, chain}
	if traceFilter != "" {
		rule = append(rule, traceFilter)
	}
	rule = append(rule, fmt.Sprintf("-m comment --comment \"iptr:%d:mark\"", traceID))
	if packetLimit != 0 {
		rule = append(rule, fmt.Sprintf("-m limit --limit %d/minute --limit-burst 1", packetLimit))
	}
	rule = append(rule, fmt.Sprintf("-j MARK --set-xmark 0x%x/0x%x", fwMark, fwMark))
	return strings.Join(rule, " ")
}

func buildTraceRule(command, chain string, filter []string, traceID, ruleIndex, nflogGroup int) string {
	rule := []string{command, chain}
	for _, f := range filter {
		if f != "" {
			rule = append(rule, f)
		}
	}
	rule = append(rule, fmt.Sprintf("-j NFLOG --nflog-prefix \"iptr:%d:%d\" --nflog-group %d", traceID, ruleIndex, nflogGroup))
	return strings.Join(rule, " ")
}

func resolveTraceRuleFilter(traceFilter, ruleFilter string) (string, bool) {
	traceFields := strings.Fields(traceFilter)
	ruleFields := strings.Fields(ruleFilter)
	for _, selector := range []string{"-s", "-d", "-p", "-i", "-o", "--sport", "--dport", "--icmp-type"} {
		traceValue, _, traceNegated := findSelector(traceFields, selector)
		if traceValue == "" || traceNegated {
			continue
		}
		ruleValue, ruleIndex, ruleNegated := findSelector(ruleFields, selector)
		if ruleValue == "" {
			continue
		}

		matches := selectorValuesIntersect(selector, traceValue, ruleValue)
		if ruleNegated {
			matches = !matches
		}
		if !matches {
			return "", false
		}
		removeFrom := ruleIndex
		if ruleNegated {
			removeFrom--
		}
		ruleFields = append(ruleFields[:removeFrom], ruleFields[ruleIndex+2:]...)
	}
	return strings.TrimSpace(strings.Join(append(traceFields, ruleFields...), " ")), true
}

func findSelector(fields []string, selector string) (string, int, bool) {
	aliases := map[string]string{
		"--source": "-s", "--destination": "-d", "--protocol": "-p",
		"--in-interface": "-i", "--out-interface": "-o",
		"--source-port": "--sport", "--destination-port": "--dport",
	}
	for i, field := range fields {
		if alias, ok := aliases[field]; ok {
			field = alias
		}
		if field == selector && i+1 < len(fields) {
			return fields[i+1], i, i > 0 && fields[i-1] == "!"
		}
	}
	return "", -1, false
}

func selectorValuesIntersect(selector, traceValue, ruleValue string) bool {
	if selector == "-p" {
		return strings.EqualFold(traceValue, ruleValue)
	}
	host := net.ParseIP(traceValue)
	if host == nil {
		return traceValue == ruleValue
	}
	if networkIP := net.ParseIP(ruleValue); networkIP != nil {
		return host.Equal(networkIP)
	}
	_, network, err := net.ParseCIDR(ruleValue)
	return err == nil && network.Contains(host)
}

func ruleMatchFilter(rule string) string {
	ruleFilter := ruleFilterRe.FindStringSubmatch(rule)
	if ruleFilter == nil {
		return ""
	}
	return ruleFilter[1]
}

func resolveRuleFilterAndMergeMark(rule string, fwMark int) ([]string, bool) {
	traceMarkFilter := fmt.Sprintf("-m mark --mark 0x%x/0x%x", fwMark, fwMark)
	ruleFilter := ruleFilterRe.FindStringSubmatch(rule)
	if ruleFilter == nil {
		return []string{traceMarkFilter}, true
	}
	markMerged := false
	markConflict := false
	resolvedFilter := ruleFilterMarkRe.ReplaceAllStringFunc(ruleFilter[1], func(originalMark string) string {
		mergedMarkFilter, ok := resolveMarkFilterAndMerge(originalMark, fwMark)
		if !ok {
			markConflict = true
			return originalMark
		}
		markMerged = true
		return mergedMarkFilter
	})
	switch {
	case markConflict:
		return []string{}, false
	case markMerged:
		return []string{resolvedFilter}, true
	default:
		return []string{resolvedFilter, traceMarkFilter}, true
	}
}

func resolveMarkFilterAndMerge(originalMarkFilter string, fwMark int) (string, bool) {
	negative := false
	scan := originalMarkFilter
	if strings.HasPrefix(originalMarkFilter, "!") {
		negative = true
		scan = originalMarkFilter[strings.Index(originalMarkFilter, "--mark"):]
	}

	var value int
	var mask int
	fmt.Sscanf(scan, "--mark %v/%v", &value, &mask)
	if mask == 0 {
		mask = 0xFFFFFFFF
	}

	if fwMark&mask != 0 {
		return "", false
	}

	if negative {
		return fmt.Sprintf("--mark 0x%x/0x%x", fwMark, fwMark), true
	}
	return fmt.Sprintf("--mark 0x%x/0x%x", value|fwMark, mask|fwMark), true
}
