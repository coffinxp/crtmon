# Update Info - crtmon v1.2.1

## Summary of Changes

This release fixes a **critical bug** in domain matching that was producing false positives when monitoring Certificate Transparency (CT) logs.

## What Was Fixed

### Problem
The previous version used `strings.Contains()` for domain matching, which treats domain names as flat strings without understanding DNS hierarchy. This caused three classes of false positives:

**Class 1 - Left-side pollution:**
- `hiaxo.com` was matching target `axo.com` ❌
- `iamaxo.com` was matching target `axo.com` ❌
- `notaxo.com` was matching target `axo.com` ❌

**Class 2 - Right-side pollution:**
- `axo.com.xyz` was matching target `axo.com` ❌
- `axo.com.hacker.com` was matching target `axo.com` ❌

**Class 3 - Middle pollution:**
- `dl.cvs.freefiremobile.com.ipserver.viip.cloud` was matching target `freefiremobile.com` ❌
- `freefiremobile.com.vip10.cepat.eu.cc` was matching target `freefiremobile.com` ❌

### Solution
Implemented a proper DNS-aware matching algorithm (`isDomainMatch`) that respects domain hierarchy:

1. **Exact match**: Domain equals target (e.g., `axo.com` matches `axo.com`)
2. **Proper subdomain**: Domain ends with `.` + target (e.g., `sub.axo.com` matches `axo.com`)

This eliminates all false positives while correctly handling:
- Deep subdomains: `deep.sub.axo.com` ✅
- Wildcard certificates: `*.axo.com` ✅

## Technical Changes

### Files Modified
- **version.go**: Updated version from `1.2.0` to `1.2.1`
- **main.go**: Changed line 308 in `processEntry()` function
  - **Before**: `if strings.Contains(strings.ToLower(domain), strings.ToLower(target))`
  - **After**: `if isDomainMatch(domain, target)`

### Files Added
- **filter.go**: New file containing the `isDomainMatch()` function (~40 lines)
  - Implements proper DNS domain matching with dot-boundary enforcement
  - Handles wildcard certificate stripping
  - Well-documented with examples of all false positive classes

## Impact

- ✅ Eliminates all false positive domain matches
- ✅ More reliable alert filtering for security monitoring
- ✅ No changes to configuration or flags
- ✅ No new dependencies required
- ✅ Backward compatible - all existing workflows continue unchanged

## Testing

The fix has been validated against all three false positive classes:
- Left-side pollution cases blocked ✅
- Right-side pollution cases blocked ✅
- Middle pollution cases blocked ✅
- Legitimate subdomains still match ✅
- Wildcard certificates handled correctly ✅

## Upgrade Instructions

1. Stop the current crtmon instance: `killall crtmon`
2. Replace the binary with the new version (v1.2.1)
3. Restart with your existing configuration: `crtmon -config ~/.config/crtmon/provider.yaml`

No configuration changes are needed.

---

**Release Date**: May 14, 2026  
**Version**: 1.2.1  
**Repository**: https://github.com/axosecurity/crtmon-modified
