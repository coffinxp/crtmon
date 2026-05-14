package main

import "strings"

// isDomainMatch returns true only if candidate is exactly the target
// or is a proper subdomain of target (i.e., ends with ".<target>").
//
// This replaces strings.Contains which produces three classes of false positives:
//
//	Class 1 — left-side pollution:
//	  hiaxo.com       matches "axo.com" via Contains but is NOT in scope
//	  iamaxo.com      matches "axo.com" via Contains but is NOT in scope
//
//	Class 2 — right-side pollution:
//	  axo.com.xyz     matches "axo.com" via Contains but is NOT in scope
//	  axo.com.hacker.com  matches "axo.com" via Contains but is NOT in scope
//
//	Class 3 — middle pollution:
//	  dl.cvs.freefiremobile.com.ipserver.viip.cloud  matches "freefiremobile.com"
//	  via Contains but is NOT in scope
//
// isDomainMatch eliminates all three classes with a single dot-boundary rule.
//
// It also safely strips leading wildcard SAN entries (e.g. "*.example.com")
// before matching, so wildcard certs are handled correctly.
func isDomainMatch(candidate, target string) bool {
	candidate = strings.ToLower(strings.TrimSpace(candidate))
	target = strings.ToLower(strings.TrimSpace(target))

	// Strip leading wildcard from SAN entries e.g. "*.example.com" → "example.com"
	if strings.HasPrefix(candidate, "*.") {
		candidate = candidate[2:]
	}

	// Rule 1: exact match (apex domain)
	if candidate == target {
		return true
	}

	// Rule 2: proper subdomain — dot must immediately precede the target
	return strings.HasSuffix(candidate, "."+target)
}
