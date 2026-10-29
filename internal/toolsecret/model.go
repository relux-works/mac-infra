// Package toolsecret inspects generic-password metadata and plans ACL changes.
// Its backend deliberately has no operation that returns item contents.
package toolsecret

import (
	"cmp"
	"context"
	"fmt"
	"path/filepath"
	"regexp"
	"slices"
	"strconv"
	"strings"
)

type RequirementClass string

const (
	CDHashOnly         RequirementClass = "cdhash-only"
	IdentifierOnly     RequirementClass = "identifier-only"
	Anchored           RequirementClass = "anchored"
	RequirementUnknown RequirementClass = "requirement_unknown"
	TeamOUForgeable    RequirementClass = "team_ou_forgeable"
)

var (
	quoted       = `"(?:[^"\\]|\\.)*"`
	identifierRE = regexp.MustCompile(`^identifier (?:` + quoted + `|[A-Za-z0-9.]+)$`)
	cdhashRE     = regexp.MustCompile(`^cdhash H"[0-9a-fA-F]+"$`)
	// A deliberately narrow grammar: unfamiliar syntax never establishes trust.
	atomRE           = regexp.MustCompile(`^(identifier (?:` + quoted + `|[A-Za-z0-9.]+)|anchor apple(?: generic)?|anchor = H"[0-9a-fA-F]{40}"|certificate (?:leaf|root|-?[0-9]+)(?: = H"[0-9a-fA-F]{40}"|\[(?:subject\.[A-Za-z]+|field\.[0-9.]+)\](?: = (?:` + quoted + `|[A-Za-z0-9.]+)| exists)?))$`)
	certificatePinRE = regexp.MustCompile(`^(?:certificate (?:leaf|root)|anchor) = H"[0-9a-fA-F]{40}"$`)
	teamOURE         = regexp.MustCompile(`^certificate (?:leaf|root|-?[0-9]+)\[subject\.OU\] = (?:` + quoted + `|[A-Za-z0-9.]+)$`)
	leafTeamRE       = regexp.MustCompile(`^certificate (?:leaf|0)\[subject\.OU\] = (?:"([A-Za-z0-9]+)"|([A-Za-z0-9]+))$`)
)

// ClassifyRequirement uses the stored trust-time requirement, never a path's current DR.
// Only conjunctions of understood positive atoms are accepted as anchored.
func ClassifyRequirement(requirement string) RequirementClass {
	r := strings.TrimSpace(requirement)
	if cdhashRE.MatchString(r) {
		return CDHashOnly
	}
	if identifierRE.MatchString(r) {
		return IdentifierOnly
	}
	atoms, ok := conjunction(r)
	if !ok {
		return RequirementUnknown
	}
	anchor, pinned, ou := false, false, false
	for _, a := range atoms {
		if !atomRE.MatchString(a) {
			return RequirementUnknown
		}
		anchor = anchor || a == "anchor apple" || a == "anchor apple generic"
		pinned = pinned || certificatePinRE.MatchString(a)
		ou = ou || teamOURE.MatchString(a)
	}
	if ou && !pinned {
		return TeamOUForgeable
	}
	if anchor || pinned {
		return Anchored
	}
	return RequirementUnknown
}

// Split only outside quotes; text such as an identifier containing "anchor apple"
// must not be interpreted as a certificate constraint.
func conjunction(s string) ([]string, bool) {
	var atoms []string
	start, inQuote, escape := 0, false, false
	for i := 0; i < len(s); i++ {
		c := s[i]
		if inQuote {
			if escape {
				escape = false
			} else if c == '\\' {
				escape = true
			} else if c == '"' {
				inQuote = false
			}
			continue
		}
		if c == '"' {
			inQuote = true
			continue
		}
		if strings.HasPrefix(s[i:], " and ") {
			atoms = append(atoms, strings.TrimSpace(s[start:i]))
			i += 4
			start = i + 1
		}
	}
	if inQuote {
		return nil, false
	}
	atoms = append(atoms, strings.TrimSpace(s[start:]))
	return atoms, s != ""
}

func GenericReader(path string) bool {
	b := strings.ToLower(filepath.Base(path))
	for _, n := range []string{"security", "sh", "bash", "zsh", "dash", "fish", "osascript", "python", "perl", "ruby", "node", "swift", "java", "php", "lua", "env", "open"} {
		if b == n || (n == "python" && strings.HasPrefix(b, "python")) {
			return true
		}
	}
	return false
}

func requirementIdentifier(atom string) (string, bool) {
	if !identifierRE.MatchString(atom) {
		return "", false
	}
	value := strings.TrimPrefix(atom, "identifier ")
	if strings.HasPrefix(value, `"`) {
		id, err := strconv.Unquote(value)
		return id, err == nil
	}
	return value, true
}

// IsGenericApplication also checks recorded identifiers: moving a generic
// reader or changing its descriptive ACL path must not hide that grant.
func IsGenericApplication(a TrustedApplication) bool {
	if GenericReader(a.Path) {
		return true
	}
	atoms, ok := conjunction(a.Requirement)
	if !ok {
		return false
	}
	for _, atom := range atoms {
		if id, ok := requirementIdentifier(atom); ok && strings.HasPrefix(id, "com.apple.") && GenericReader(strings.TrimPrefix(id, "com.apple.")) {
			return true
		}
	}
	return false
}

type TrustedApplication struct {
	Path        string `json:"path"`
	Requirement string `json:"requirement"`
}

func (a TrustedApplication) Unverified() bool { return strings.TrimSpace(a.Requirement) == "" }

type ReleaseACL struct {
	Authorizations     []string             `json:"authorizations"`
	AnyApplication     bool                 `json:"any_application"`
	Applications       []TrustedApplication `json:"applications"`
	ContentsUnverified bool                 `json:"contents_unverified,omitempty"`
}
type Item struct {
	Service          string       `json:"service"`
	Account          string       `json:"account"`
	Label            string       `json:"label"`
	Creator          uint32       `json:"creator"`
	ReleaseACLs      []ReleaseACL `json:"release_acls"`
	WriterACLs       []ReleaseACL `json:"writer_acls"`
	Partitions       []string     `json:"partitions"`
	PartitionUnknown bool         `json:"partition_unknown"`
}
type Owner struct {
	Path            string   `json:"path"`
	Requirement     string   `json:"requirement"`
	AdHoc           bool     `json:"ad_hoc"`
	HardenedRuntime bool     `json:"hardened_runtime"`
	Entitlements    []string `json:"entitlements"`
	Partition       string   `json:"partition"`
}

var ForbiddenEntitlements = []string{
	"com.apple.security.get-task-allow",
	"com.apple.security.cs.allow-dyld-environment-variables",
	"com.apple.security.cs.disable-library-validation",
	"com.apple.security.cs.allow-unsigned-executable-memory",
}

var PlaintextAuthorizations = [...]string{"decrypt", "export_clear", "export_wrapped"}
var WriterAuthorizations = [...]string{"item_modify", "item_delete", "delete", "change_acl", "change_owner", "encrypt"}

func CanWrite(acl ReleaseACL) bool {
	for _, a := range acl.Authorizations {
		if a == "any" || slices.Contains(WriterAuthorizations[:], a) {
			return true
		}
	}
	return false
}

// An empty explicit application list requires authorization by the owner in a
// system dialog. A NULL list (AnyApplication) grants automatic access to anyone.
func ForeignWriter(acl ReleaseACL, ownerRequirement string) bool {
	if !CanWrite(acl) {
		return false
	}
	if acl.ContentsUnverified || acl.AnyApplication {
		return true
	}
	for _, a := range acl.Applications {
		if ownerRequirement == "" || a.Unverified() || IsGenericApplication(a) || a.Requirement != ownerRequirement {
			return true
		}
	}
	return false
}

func CanReleasePlaintext(acl ReleaseACL) bool {
	for _, a := range acl.Authorizations {
		if a == "any" || slices.Contains(PlaintextAuthorizations[:], a) {
			return true
		}
	}
	return false
}
func OwnerApplication(o Owner) TrustedApplication {
	return TrustedApplication{Path: o.Path, Requirement: o.Requirement}
}
func CertificatePinned(r string) bool {
	atoms, ok := conjunction(r)
	if !ok {
		return false
	}
	for _, a := range atoms {
		if certificatePinRE.MatchString(a) {
			return true
		}
	}
	return false
}

type Refusal struct{ Code, Message string }

func (e *Refusal) Error() string    { return e.Message }
func refuse(code, msg string) error { return &Refusal{code, msg} }

func ValidateOwner(o Owner) error {
	if IsGenericApplication(OwnerApplication(o)) {
		return refuse("generic_reader_owner", "a generic reader cannot own a secret")
	}
	if o.AdHoc {
		return refuse("ad_hoc_owner", "owner signature is ad-hoc")
	}
	if ClassifyRequirement(o.Requirement) != Anchored {
		return refuse("weak_owner_requirement", "owner requires an understood certificate-anchored designated requirement")
	}
	if !CertificatePinned(o.Requirement) {
		return refuse("certificate_pin_required", "owner requirement must pin a leaf or root certificate hash (decision 75)")
	}
	if !o.HardenedRuntime {
		return refuse("missing_hardened_runtime", "owner lacks hardened runtime")
	}
	for _, e := range ForbiddenEntitlements {
		if slices.Contains(o.Entitlements, e) || (e == "com.apple.security.get-task-allow" && slices.Contains(o.Entitlements, "get-task-allow")) {
			return refuse("unsafe_entitlement", "owner has forbidden entitlement: "+e)
		}
	}
	if !strings.HasPrefix(o.Partition, "teamid:") && !strings.HasPrefix(o.Partition, "cdhash:") {
		return refuse("unknown_owner_partition", "cannot establish owner's partition")
	}
	return nil
}

// Closed list: no Apple-internal identifiers have been approved for preservation.
// Adding an identifier requires a reviewed source AND documentation change.
var appleInternalIdentifiers = [...]string{}

func AppleInternal(a TrustedApplication) bool {
	if a.Unverified() || IsGenericApplication(a) || ClassifyRequirement(a.Requirement) != Anchored {
		return false
	}
	atoms, _ := conjunction(a.Requirement)
	identifier := ""
	for _, atom := range atoms {
		if id, ok := requirementIdentifier(atom); ok && strings.HasPrefix(id, "com.apple.") {
			identifier = id
		}
	}
	return slices.Contains(appleInternalIdentifiers[:], identifier) && slices.Contains(atoms, "anchor apple")
}

// InspectForOwner compares a current validated owner with the SAME DR, without
// ever replacing classification of the stored trust-time requirement.
func InspectForOwner(item Item, owner Owner) InventoryItem {
	r := Inspect(item)
	if ValidateOwner(owner) != nil {
		return r
	}
	for _, acl := range item.ReleaseACLs {
		if !CanReleasePlaintext(acl) || acl.ContentsUnverified || acl.AnyApplication {
			continue
		}
		for _, a := range acl.Applications {
			if a.Path == owner.Path && a.Requirement == owner.Requirement && (item.PartitionUnknown || len(item.Partitions) != 1 || item.Partitions[0] != owner.Partition) && !slices.Contains(r.Flags, "partition_mismatch") {
				r.Flags = append(r.Flags, "partition_mismatch")
			}
		}
	}
	return r
}

type ApplicationReport struct {
	TrustedApplication
	Classification RequirementClass `json:"classification"`
	GenericReader  bool             `json:"generic_reader"`
	Unverified     bool             `json:"unverified"`
}
type InventoryItem struct {
	Item
	Applications []ApplicationReport `json:"applications"`
	Writers      []WriterReport      `json:"writers"`
	Flags        []string            `json:"flags"`
}
type WriterReport struct {
	ReleaseACL
	ForeignWriter bool `json:"foreign_writer"`
}

// Default inventory can infer an owner only from one unambiguous pinned reader
// requirement. Writer grants never establish their own ownership.
func inferredOwnerRequirement(item Item) string {
	requirement := ""
	for _, acl := range item.ReleaseACLs {
		if !CanReleasePlaintext(acl) || acl.ContentsUnverified || acl.AnyApplication {
			continue
		}
		for _, a := range acl.Applications {
			if ClassifyRequirement(a.Requirement) != Anchored || !CertificatePinned(a.Requirement) || IsGenericApplication(a) || AppleInternal(a) {
				continue
			}
			if requirement != "" && requirement != a.Requirement {
				return ""
			}
			requirement = a.Requirement
		}
	}
	return requirement
}

func Inspect(item Item) InventoryItem {
	r := InventoryItem{Item: item, Applications: []ApplicationReport{}, Writers: []WriterReport{}, Flags: []string{}}
	flag := func(f string) {
		if !slices.Contains(r.Flags, f) {
			r.Flags = append(r.Flags, f)
		}
	}
	for _, acl := range item.ReleaseACLs {
		if !CanReleasePlaintext(acl) {
			continue
		}
		if acl.AnyApplication {
			flag("any_application")
		}
		if acl.ContentsUnverified {
			flag("unverified")
			flag("requirement_unknown")
		}
		for _, a := range acl.Applications {
			c, g := ClassifyRequirement(a.Requirement), IsGenericApplication(a)
			r.Applications = append(r.Applications, ApplicationReport{a, c, g, a.Unverified()})
			if g {
				flag("generic_reader")
			}
			if c == CDHashOnly || c == IdentifierOnly {
				flag("weak_requirement")
			}
			if c == TeamOUForgeable {
				flag("team_ou_forgeable")
			}
			if a.Unverified() {
				flag("unverified")
			}
			if c == RequirementUnknown {
				flag("requirement_unknown")
			}
		}
	}
	ownerRequirement := inferredOwnerRequirement(item)
	for _, acl := range item.WriterACLs {
		if !CanWrite(acl) {
			continue
		}
		foreign := ForeignWriter(acl, ownerRequirement)
		r.Writers = append(r.Writers, WriterReport{acl, foreign})
		if foreign {
			flag("foreign_writer")
		}
		if acl.ContentsUnverified {
			flag("unverified")
		}
		for _, a := range acl.Applications {
			if a.Unverified() {
				flag("unverified")
			}
		}
	}
	if slices.Contains(r.Flags, "generic_reader") {
		s := strings.ToLower(item.Service + " " + item.Label)
		for _, marker := range []string{"rollback", "backup", "migration", ".old", "-old", "_old"} {
			if strings.Contains(s, marker) {
				flag("rollback_leftover")
			}
		}
	}
	if item.PartitionUnknown {
		flag("partition_mismatch")
	}
	if slices.Contains(item.Partitions, "apple:") || slices.Contains(item.Partitions, "apple-tool:") {
		flag("partition_mismatch")
	}
	// With no --owner, infer a team only from an unambiguous anchored decrypt DR.
	var inferred []string
	for _, a := range r.Applications {
		if a.Classification == Anchored && !a.GenericReader {
			atoms, _ := conjunction(a.Requirement)
			for _, atom := range atoms {
				if m := leafTeamRE.FindStringSubmatch(atom); m != nil {
					inferred = append(inferred, "teamid:"+m[1]+m[2])
				}
			}
		}
	}
	for _, p := range inferred {
		if len(item.Partitions) != 1 || item.Partitions[0] != p {
			flag("partition_mismatch")
		}
	}
	return r
}

type Plan struct {
	Before        Item     `json:"before"`
	After         Item     `json:"after"`
	Owner         Owner    `json:"owner"`
	Keep          []string `json:"keep"`
	KeepOwners    []Owner  `json:"keep_owners"`
	OwnerDecision string   `json:"owner_decision,omitempty"`
}

type BindOptions struct {
	Keep          []string
	KeepOwners    map[string]Owner
	OwnerDecision string
}

func PlanBind(item Item, owner Owner, opts BindOptions) (Plan, error) {
	keep := opts.Keep
	p := Plan{Before: item, After: item, Owner: owner, Keep: append([]string{}, keep...), KeepOwners: []Owner{}, OwnerDecision: opts.OwnerDecision}
	if err := ValidateOwner(owner); err != nil {
		return p, err
	}
	if item.PartitionUnknown {
		return p, refuse("partition_unknown", "cannot parse partition ACL")
	}
	apps := []TrustedApplication{OwnerApplication(owner)}
	found := map[string]bool{}
	for _, acl := range item.ReleaseACLs {
		if !CanReleasePlaintext(acl) {
			continue
		}
		if acl.ContentsUnverified {
			return p, refuse("requirement_unknown", "plaintext-release ACL contents are unverified")
		}
		for _, a := range acl.Applications {
			if a.Unverified() || ClassifyRequirement(a.Requirement) == RequirementUnknown {
				return p, refuse("requirement_unknown", "stored plaintext-release requirement is unknown; no current-binary fallback")
			}
			if slices.Contains(keep, a.Path) {
				found[a.Path] = true
				current, ok := opts.KeepOwners[a.Path]
				var check error
				if !ok {
					check = fmt.Errorf("cannot validate kept application")
				} else if current.Path != a.Path || current.Requirement != a.Requirement {
					check = fmt.Errorf("kept application's stored and current requirements differ")
				} else {
					check = ValidateOwner(current)
				}
				if check != nil && opts.OwnerDecision == "" {
					return p, refuse("unsafe_keep", "--keep requires owner-grade signing and hardening checks, or --owner-decision REF: "+a.Path)
				}
				if ok && current.Path == a.Path && !slices.ContainsFunc(p.KeepOwners, func(o Owner) bool { return o.Path == current.Path }) {
					p.KeepOwners = append(p.KeepOwners, current)
				}
			}
			if a.Requirement != owner.Requirement && (AppleInternal(a) || slices.Contains(keep, a.Path)) && !slices.Contains(apps, a) {
				apps = append(apps, a)
			}
		}
	}
	for _, path := range keep {
		if !found[path] {
			return p, refuse("keep_not_found", "--keep path is absent from plaintext-release ACLs: "+path)
		}
	}
	slices.SortFunc(apps, func(a, b TrustedApplication) int {
		if order := cmp.Compare(a.Path, b.Path); order != 0 {
			return order
		}
		return cmp.Compare(a.Requirement, b.Requirement)
	})
	p.After.ReleaseACLs = []ReleaseACL{}
	for _, auth := range PlaintextAuthorizations {
		p.After.ReleaseACLs = append(p.After.ReleaseACLs, ReleaseACL{Authorizations: []string{auth}, Applications: apps})
	}
	p.After.Partitions = []string{owner.Partition}
	// Removing wildcard plaintext entries also removes their writer authority.
	// Other writer grants are preserved and remain subject to strict verify.
	if item.WriterACLs != nil {
		p.After.WriterACLs = []ReleaseACL{}
		for _, acl := range item.WriterACLs {
			if !slices.Contains(acl.Authorizations, "any") {
				p.After.WriterACLs = append(p.After.WriterACLs, acl)
			}
		}
	}
	return p, nil
}

func Verify(item Item, owner Owner) []string {
	var reasons []string
	if err := ValidateOwner(owner); err != nil {
		reasons = append(reasons, err.Error())
	}
	owners := 0
	for _, acl := range item.WriterACLs {
		if ForeignWriter(acl, owner.Requirement) {
			reasons = append(reasons, "foreign_writer")
		}
	}
	for _, acl := range item.ReleaseACLs {
		if !CanReleasePlaintext(acl) {
			continue
		}
		if acl.AnyApplication {
			reasons = append(reasons, "any_application")
		}
		if acl.ContentsUnverified {
			reasons = append(reasons, "unverified")
		}
		for _, a := range acl.Applications {
			if a.Unverified() {
				reasons = append(reasons, "unverified")
			}
			c := ClassifyRequirement(a.Requirement)
			if c != Anchored {
				reasons = append(reasons, string(c))
			}
			if IsGenericApplication(a) {
				reasons = append(reasons, "generic_reader")
			}
			if a.Requirement == owner.Requirement {
				owners++
			} else if !AppleInternal(a) {
				reasons = append(reasons, "unexpected decrypt owner: "+a.Path)
			}
		}
	}
	if owners < 1 {
		reasons = append(reasons, fmt.Sprintf("owner requirement count is %d, expected at least 1", owners))
	}
	if item.PartitionUnknown || len(item.Partitions) != 1 || item.Partitions[0] != owner.Partition {
		reasons = append(reasons, "partition_mismatch")
	}
	return reasons
}

type Backend interface {
	Startup(context.Context) error
	Inventory(context.Context, string) ([]Item, error)
	Owner(context.Context, string) (Owner, error)
	Apply(context.Context, string, Plan, bool) error
}
