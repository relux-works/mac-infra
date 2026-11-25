//go:build darwin && cgo

package toolsecret

import (
	"bytes"
	"context"
	"encoding/json"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"sort"
	"strconv"
	"strings"
	"testing"
	"time"
)

type nativeACLContractCase struct {
	name       string
	auths      []string
	appMode    string
	aclCopies  int
	opaque     bool
	wantAccept bool
	wantTarget int
}

func nativeACLAuthorizationContractCases() []nativeACLContractCase {
	secretForms := nonEmptyAuthorizationSubsets([]string{"derive", "mac", "sign"})
	releaseForms := nonEmptyAuthorizationSubsets([]string{"decrypt", "export_clear", "export_wrapped"})
	cases := make([]nativeACLContractCase, 0, len(secretForms)*len(releaseForms)*2+40)
	add := func(name string, auths []string, appMode string, copies int, opaque, wantAccept bool, wantTarget int) {
		cases = append(cases, nativeACLContractCase{
			name: name, auths: append([]string(nil), auths...), appMode: appMode,
			aclCopies: copies, opaque: opaque, wantAccept: wantAccept, wantTarget: wantTarget,
		})
	}
	for _, secret := range secretForms {
		for _, appMode := range []string{"null", "empty"} {
			name := "key-use-" + strings.Join(secret, "-")
			if len(secret) == 3 {
				name = "key-use-only"
			}
			if appMode == "empty" {
				name += "-explicit-empty"
			}
			targets := 0
			if appMode == "null" {
				targets = 1
			}
			add(name, secret, appMode, 0, false, true, targets)
		}
	}
	for _, release := range releaseForms {
		for _, appMode := range []string{"null", "empty"} {
			name := "release-" + strings.Join(release, "-")
			if len(release) == 3 {
				name = "release-only"
			}
			if appMode == "empty" {
				name += "-explicit-empty"
			}
			add(name, release, appMode, 0, false, true, 0)
		}
	}
	for _, release := range releaseForms {
		for _, secret := range secretForms {
			for _, appMode := range []string{"null", "empty"} {
				auths := append(append([]string(nil), release...), secret...)
				name := "overlap-" + strings.Join(release, "-") + "-with-" + strings.Join(secret, "-")
				if len(release) == 3 && len(secret) == 3 {
					name = "inventory-overlap"
				}
				if appMode == "empty" {
					name += "-explicit-empty"
				}
				targets := 0
				if appMode == "null" {
					targets = 1
				}
				add(name, auths, appMode, 0, false, true, targets)
			}
		}
	}
	add("mixed-key-use-writer", []string{"derive", "mac", "sign", "item_modify"}, "null", 0, false, false, -1)
	add("mixed-key-use-encrypt", []string{"derive", "encrypt"}, "null", 0, false, false, -1)
	add("mixed-key-use-integrity", []string{"derive", "integrity"}, "null", 0, false, false, -1)
	add("overlap-with-unmodeled-writer", []string{"decrypt", "export_clear", "export_wrapped", "derive", "mac", "sign", "item_modify"}, "null", 0, false, false, -1)
	add("overlap-with-any", []string{"decrypt", "derive", "any"}, "null", 0, false, false, -1)
	add("unknown-gen-key", []string{"gen_key"}, "null", 0, false, false, -1)
	add("overlap-with-unknown-gen-key", []string{"decrypt", "export_clear", "export_wrapped", "derive", "mac", "sign", "gen_key"}, "null", 0, false, false, -1)
	add("integrity-exact", []string{"integrity"}, "null", 0, false, true, 0)
	add("integrity-explicit-empty", []string{"integrity"}, "empty", 0, false, false, -1)
	add("integrity-duplicate", []string{"integrity"}, "null", 2, false, false, -1)
	add("opaque-key-use", []string{"derive", "mac", "sign"}, "opaque", 0, true, false, -1)
	return cases
}

func nonEmptyAuthorizationSubsets(authorizations []string) [][]string {
	result := make([][]string, 0, (1<<len(authorizations))-1)
	for mask := 1; mask < 1<<len(authorizations); mask++ {
		var subset []string
		for i, authorization := range authorizations {
			if mask&(1<<i) != 0 {
				subset = append(subset, authorization)
			}
		}
		result = append(result, subset)
	}
	return result
}

// Claim: Go planning and native preflight agree on the same raw-authorization table, including the observed release/key-use overlap, and all probe inputs remain unchanged.
func TestNativeACLAuthorizationContract(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	fixture := filepath.Join(t.TempDir(), "native-acl-contract")
	compile := exec.CommandContext(ctx, "/usr/bin/clang",
		"-Wno-deprecated-declarations", "-framework", "Foundation", "-framework", "Security",
		"-o", fixture, "testdata/native_prepare_fixture.m")
	if output, err := compile.CombinedOutput(); err != nil {
		t.Fatalf("compile in-memory native ACL fixture: %v\n%s", err, output)
	}

	for _, tc := range nativeACLAuthorizationContractCases() {
		t.Run(tc.name, func(t *testing.T) {
			item := itemForNativeACLContract(tc)
			_, planErr := PlanBind(item, validOwner(), BindOptions{})
			planAccepts := planErr == nil
			if planAccepts != tc.wantAccept {
				t.Fatalf("Go planner acceptance=%v, want %v (err=%v)", planAccepts, tc.wantAccept, planErr)
			}

			copies := tc.aclCopies
			if copies == 0 {
				copies = 1
			}
			command := exec.CommandContext(ctx, fixture, "contract", strings.Join(tc.auths, ","), tc.appMode, strconv.Itoa(copies))
			output, err := command.CombinedOutput()
			if err != nil {
				t.Fatalf("native in-memory probe setup: %v\n%s", err, output)
			}
			var native struct {
				Status    int  `json:"status"`
				Targets   int  `json:"targets"`
				Unchanged bool `json:"unchanged"`
			}
			if err := json.Unmarshal(output, &native); err != nil {
				t.Fatalf("decode native probe: %v: %s", err, output)
			}
			nativeAccepts := native.Status == 0
			if nativeAccepts != planAccepts {
				t.Fatalf("Go/native contract disagreement: Go accepts=%v native status=%d targets=%d", planAccepts, native.Status, native.Targets)
			}
			if nativeAccepts != tc.wantAccept || native.Targets != tc.wantTarget {
				t.Fatalf("native acceptance/targets=(%v,%d), want (%v,%d), status=%d", nativeAccepts, native.Targets, tc.wantAccept, tc.wantTarget, native.Status)
			}
			if !native.Unchanged {
				t.Fatal("native preflight changed the in-memory ACLs")
			}
			if tc.name == "integrity-duplicate" && (native.Status == 0 || !native.Unchanged) {
				t.Fatalf("duplicate Integrity must refuse without editing ACLs: %+v", native)
			}
		})
	}
}

func itemForNativeACLContract(tc nativeACLContractCase) Item {
	anyApplication := tc.appMode == "null" || tc.appMode == "opaque"
	applications := []TrustedApplication{}
	contentsUnverified := tc.opaque
	item := Item{
		Service:          "works.relux.fixture",
		Account:          "contract-account",
		Label:            "native ACL contract fixture",
		ReleaseACLs:      []ReleaseACL{},
		WriterACLs:       []ReleaseACL{},
		Partitions:       []string{validOwner().Partition},
		PartitionUnknown: false,
	}
	var releaseAuths, writerAuths, unmodeled []string
	for _, authorization := range tc.auths {
		switch authorization {
		case "decrypt", "export_clear", "export_wrapped":
			releaseAuths = append(releaseAuths, authorization)
		case "derive", "mac", "sign", "item_modify", "encrypt", "integrity":
			writerAuths = append(writerAuths, authorization)
		case "gen_key":
			unmodeled = append(unmodeled, "ACLAuthorizationGenKey")
		default:
			unmodeled = append(unmodeled, "ACLAuthorizationUnknown")
		}
	}
	copies := tc.aclCopies
	if copies == 0 {
		copies = 1
	}
	for i := 0; i < copies; i++ {
		if len(releaseAuths) != 0 {
			item.ReleaseACLs = append(item.ReleaseACLs, ReleaseACL{
				Authorizations:          append([]string(nil), releaseAuths...),
				AnyApplication:          anyApplication,
				Applications:            append([]TrustedApplication(nil), applications...),
				ContentsUnverified:      contentsUnverified,
				UnmodeledAuthorizations: append([]string(nil), unmodeled...),
			})
		}
		if len(writerAuths) != 0 || len(unmodeled) != 0 {
			item.WriterACLs = append(item.WriterACLs, ReleaseACL{
				Authorizations:          append([]string(nil), writerAuths...),
				AnyApplication:          anyApplication,
				Applications:            append([]TrustedApplication(nil), applications...),
				ContentsUnverified:      contentsUnverified,
				UnmodeledAuthorizations: append([]string(nil), unmodeled...),
			})
		}
	}
	return item
}

// Claim: the observed combined release/key-use ACL can be prepared natively from the exact Go rollback plan, with the rollback application present in every narrowed secret-use grant.
func TestNativeInventoryOverlapPreparationMatchesRollbackPlan(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 90*time.Second)
	defer cancel()
	fixture := filepath.Join(t.TempDir(), "native-overlap-roundtrip")
	compile := exec.CommandContext(ctx, "/usr/bin/clang",
		"-Wno-deprecated-declarations", "-DTOOLSECRET_TEST_TRACE", "-framework", "Foundation", "-framework", "Security",
		"-o", fixture, "testdata/native_prepare_fixture.m")
	if output, err := compile.CombinedOutput(); err != nil {
		t.Fatalf("compile in-memory native ACL fixture: %v\n%s", err, output)
	}

	owner := validOwner()
	rollback := TrustedApplication{Path: rollbackSubject, Requirement: rollbackSecurityRequirement}
	legacy := TrustedApplication{Path: "/test/previous-owner", Requirement: `identifier "works.relux.previous" and anchor apple generic`}
	beforeApplications := []TrustedApplication{legacy, rollback}
	sort.Slice(beforeApplications, func(i, j int) bool {
		if beforeApplications[i].Path != beforeApplications[j].Path {
			return beforeApplications[i].Path < beforeApplications[j].Path
		}
		return beforeApplications[i].Requirement < beforeApplications[j].Requirement
	})
	item := Item{
		Service: "works.relux.fixture", Account: "rollback-account", Label: "native preparation fixture",
		ReleaseACLs: []ReleaseACL{{
			Authorizations: []string{"decrypt", "export_clear", "export_wrapped"},
			Applications:   append([]TrustedApplication(nil), beforeApplications...),
		}},
		WriterACLs: []ReleaseACL{
			{Authorizations: []string{"change_acl"}, Applications: []TrustedApplication{}},
			{Authorizations: []string{"derive", "mac", "sign"}, Applications: append([]TrustedApplication(nil), beforeApplications...)},
			{Authorizations: []string{"encrypt"}, AnyApplication: true, Applications: []TrustedApplication{}},
			{Authorizations: []string{"integrity"}, AnyApplication: true, Applications: []TrustedApplication{}},
		},
		Partitions: []string{}, PartitionUnknown: false,
	}
	plan, err := PlanBind(item, owner, BindOptions{
		Keep: []string{rollbackSubject},
		KeepOwners: map[string]Owner{rollbackSubject: {
			Path: rollbackSubject, Requirement: rollbackSecurityRequirement, Partition: owner.Partition,
		}},
		OwnerDecision: rollbackDecision,
	})
	if err != nil {
		t.Fatalf("Go planner refused observed authorization overlap: %v", err)
	}
	plan.Keychain = "/test/in-memory.keychain-db"

	input, err := json.Marshal(plan)
	if err != nil {
		t.Fatal(err)
	}
	command := exec.CommandContext(ctx, fixture, "inventory-overlap-roundtrip")
	command.Stdin = bytes.NewReader(input)
	var output, diagnostics bytes.Buffer
	command.Stdout = &output
	command.Stderr = &diagnostics
	err = command.Run()
	if err != nil {
		t.Fatalf("native in-memory preparation setup: %v\n%s", err, diagnostics.String())
	}
	var result struct {
		Status   int  `json:"status"`
		Prepared Item `json:"prepared"`
	}
	if err := json.Unmarshal(output.Bytes(), &result); err != nil {
		t.Fatalf("decode native round-trip: %v: %s", err, output.String())
	}
	if result.Status != 0 {
		t.Fatalf("native preparation refused Go plan: status=%d output=%s\ndiagnostics=%s", result.Status, output.String(), diagnostics.String())
	}
	if !reflect.DeepEqual(result.Prepared, plan.After) {
		t.Fatalf("native prepared ACL metadata differs from Go plan:\n got: %+v\nwant: %+v", result.Prepared, plan.After)
	}
	for _, acl := range result.Prepared.WriterACLs {
		if slices.Equal(acl.Authorizations, []string{"derive", "mac", "sign"}) || slices.Equal(acl.Authorizations, []string{"encrypt"}) {
			if !slices.Contains(acl.Applications, rollback) || acl.AnyApplication {
				t.Fatalf("rollback reader missing from narrowed ACL: %+v", acl)
			}
		}
	}
}
