package cleanup

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"
)

const (
	PlanSchemaVersion     = 1
	CategoryPolicyVersion = "cleanup-policy-v1"
	PlanHashAlgorithm     = "sha256"

	DefaultPlanStaleAfter = 24 * time.Hour
)

type PlanSource string

const (
	PlanSourceScan   PlanSource = "scan"
	PlanSourceTarget PlanSource = "target"
	PlanSourceXcode  PlanSource = "xcode"
)

type CleanupAction string

const (
	CleanupActionTrash  CleanupAction = "trash"
	CleanupActionDelete CleanupAction = "delete"
)

type CandidateKind string

const (
	CandidateKindDirectory CandidateKind = "directory"
	CandidateKindFile      CandidateKind = "file"
	CandidateKindSymlink   CandidateKind = "symlink"
	CandidateKindOther     CandidateKind = "other"
)

type DirectApplyPolicy string

const (
	DirectApplyUnsupportedV1 DirectApplyPolicy = "unsupported_v1"
)

type PlanRoot struct {
	Path     string `json:"path"`
	RealPath string `json:"realPath"`
	Device   uint64 `json:"device,omitempty"`
	Inode    uint64 `json:"inode,omitempty"`
	UID      uint32 `json:"uid"`
	GID      uint32 `json:"gid"`
}

type CandidateIdentity struct {
	Path         string        `json:"path"`
	RealPath     string        `json:"realPath"`
	RootPath     string        `json:"rootPath"`
	RootRealPath string        `json:"rootRealPath"`
	Kind         CandidateKind `json:"kind"`
	Mode         uint32        `json:"mode"`
	LogicalBytes int64         `json:"logicalBytes"`
	DiskBytes    int64         `json:"diskBytes"`
	ModTime      time.Time     `json:"modTime"`
	Device       uint64        `json:"device,omitempty"`
	Inode        uint64        `json:"inode,omitempty"`
	LinkCount    uint64        `json:"linkCount,omitempty"`
	UID          uint32        `json:"uid"`
	GID          uint32        `json:"gid"`
	RootDevice   uint64        `json:"rootDevice,omitempty"`
	RootInode    uint64        `json:"rootInode,omitempty"`
	RootUID      uint32        `json:"rootUid"`
	RootGID      uint32        `json:"rootGid"`
}

type Candidate struct {
	ID              string            `json:"id"`
	CategoryID      CategoryID        `json:"categoryId"`
	Reason          string            `json:"reason"`
	Risk            RiskLevel         `json:"risk"`
	DefaultSelected bool              `json:"defaultSelected"`
	Selected        bool              `json:"selected"`
	LogicalBytes    int64             `json:"logicalBytes"`
	DiskBytes       int64             `json:"diskBytes"`
	Identity        CandidateIdentity `json:"identity"`
}

type PlanCategory struct {
	ID              CategoryID `json:"id"`
	Risk            RiskLevel  `json:"risk"`
	DefaultSelected bool       `json:"defaultSelected"`
}

type PlanTotals struct {
	CandidateCount       int   `json:"candidateCount"`
	SelectedCount        int   `json:"selectedCount"`
	LogicalBytes         int64 `json:"logicalBytes"`
	DiskBytes            int64 `json:"diskBytes"`
	SelectedLogicalBytes int64 `json:"selectedLogicalBytes"`
	SelectedDiskBytes    int64 `json:"selectedDiskBytes"`
}

type ConfirmationPolicy struct {
	Required       bool     `json:"required"`
	PromptIncludes []string `json:"promptIncludes"`
}

type CandidateRevalidationPolicy struct {
	ReLstatBeforeDelete        bool     `json:"reLstatBeforeDelete"`
	RefuseSymlinkSwap          bool     `json:"refuseSymlinkSwap"`
	RefuseOutOfRoot            bool     `json:"refuseOutOfRoot"`
	RequireOwnershipRecheck    bool     `json:"requireOwnershipRecheck"`
	RequireIdentityMatchFields []string `json:"requireIdentityMatchFields"`
}

type PlanApplyContract struct {
	CleanApplyRequiresPlan bool                        `json:"cleanApplyRequiresPlan"`
	DirectCategoryApply    DirectApplyPolicy           `json:"directCategoryApply"`
	DefaultAction          CleanupAction               `json:"defaultAction"`
	PermanentDeleteFlags   []string                    `json:"permanentDeleteFlags"`
	Confirmation           ConfirmationPolicy          `json:"confirmation"`
	Revalidation           CandidateRevalidationPolicy `json:"revalidation"`
}

type Plan struct {
	SchemaVersion         int               `json:"schemaVersion"`
	CategoryPolicyVersion string            `json:"categoryPolicyVersion"`
	GeneratedAt           time.Time         `json:"generatedAt"`
	StaleAfterSeconds     int64             `json:"staleAfterSeconds"`
	Source                PlanSource        `json:"source"`
	Root                  PlanRoot          `json:"root"`
	Categories            []PlanCategory    `json:"categories,omitempty"`
	Candidates            []Candidate       `json:"candidates"`
	Totals                PlanTotals        `json:"totals"`
	Apply                 PlanApplyContract `json:"apply"`
	HashInputs            []string          `json:"hashInputs"`
	PlanHash              string            `json:"planHash"`
}

type NewCandidateInput struct {
	Path            string
	RootPath        string
	CategoryID      CategoryID
	Reason          string
	Risk            RiskLevel
	DefaultSelected bool
	Selected        bool
}

type NewPlanInput struct {
	GeneratedAt time.Time
	Source      PlanSource
	Root        PlanRoot
	Categories  []PlanCategory
	Candidates  []Candidate
}

type CleanApplyInvocation struct {
	Apply          bool
	PlanPath       string
	DirectCategory CategoryID
}

type RefusalCode string

const (
	RefusalApplyFlagMissing            RefusalCode = "apply_flag_missing"
	RefusalPlanPathMissing             RefusalCode = "plan_path_missing"
	RefusalDirectCategoryApply         RefusalCode = "direct_category_apply_unsupported"
	RefusalSchemaVersion               RefusalCode = "schema_version_mismatch"
	RefusalCategoryPolicyVersion       RefusalCode = "category_policy_version_mismatch"
	RefusalGeneratedAtMissing          RefusalCode = "generated_at_missing"
	RefusalPlanHashMissing             RefusalCode = "plan_hash_missing"
	RefusalPlanHashMismatch            RefusalCode = "plan_hash_mismatch"
	RefusalPlanStale                   RefusalCode = "plan_stale"
	RefusalRootLstat                   RefusalCode = "root_lstat_failed"
	RefusalRootSymlink                 RefusalCode = "root_symlink"
	RefusalRootRealpath                RefusalCode = "root_realpath_failed"
	RefusalRootRealpathChanged         RefusalCode = "root_realpath_changed"
	RefusalRootOwnership               RefusalCode = "root_ownership_mismatch"
	RefusalRootIdentityChanged         RefusalCode = "root_identity_changed"
	RefusalCandidateLstat              RefusalCode = "candidate_lstat_failed"
	RefusalCandidateSymlink            RefusalCode = "candidate_symlink"
	RefusalCandidateRealpath           RefusalCode = "candidate_realpath_failed"
	RefusalCandidateRealpathChanged    RefusalCode = "candidate_realpath_changed"
	RefusalCandidateOutOfRoot          RefusalCode = "candidate_out_of_root"
	RefusalCandidateOwnership          RefusalCode = "candidate_ownership_mismatch"
	RefusalCandidateIdentityChanged    RefusalCode = "candidate_identity_changed"
	RefusalSelectedOutOfScopeCandidate RefusalCode = "selected_out_of_scope_candidate"
)

type Refusal struct {
	Code        RefusalCode `json:"code"`
	CandidateID string      `json:"candidateId,omitempty"`
	Path        string      `json:"path,omitempty"`
	Message     string      `json:"message"`
}

type ApplyPreflightResult struct {
	Refusals       []Refusal `json:"refusals,omitempty"`
	CandidateCount int       `json:"candidateCount"`
	LogicalBytes   int64     `json:"logicalBytes"`
	DiskBytes      int64     `json:"diskBytes"`
	CheckedAt      time.Time `json:"checkedAt"`
}

func (result ApplyPreflightResult) Allowed() bool {
	return len(result.Refusals) == 0
}

type RevalidationOptions struct {
	CurrentUID    uint32
	CurrentUIDSet bool
	SelectedOnly  bool
	CheckedAt     time.Time
}

func DefaultPlanApplyContract() PlanApplyContract {
	return PlanApplyContract{
		CleanApplyRequiresPlan: true,
		DirectCategoryApply:    DirectApplyUnsupportedV1,
		DefaultAction:          CleanupActionTrash,
		PermanentDeleteFlags:   []string{"--permanent", "--yes-i-know"},
		Confirmation: ConfirmationPolicy{
			Required: true,
			PromptIncludes: []string{
				"planHash",
				"generatedAt",
				"staleAfterSeconds",
				"selectedCount",
				"selectedLogicalBytes",
				"selectedDiskBytes",
				"defaultAction",
			},
		},
		Revalidation: CandidateRevalidationPolicy{
			ReLstatBeforeDelete:     true,
			RefuseSymlinkSwap:       true,
			RefuseOutOfRoot:         true,
			RequireOwnershipRecheck: true,
			RequireIdentityMatchFields: []string{
				"rootRealPath",
				"path",
				"realPath",
				"kind",
				"mode",
				"logicalBytes",
				"diskBytes",
				"modTime",
				"device",
				"inode",
				"uid",
				"gid",
			},
		},
	}
}

func DefaultPlanHashInputs() []string {
	return []string{
		"schemaVersion",
		"categoryPolicyVersion",
		"generatedAt",
		"staleAfterSeconds",
		"source",
		"root",
		"categories",
		"candidates",
		"totals",
		"apply",
		"hashInputs",
	}
}

func NewCandidate(input NewCandidateInput) (Candidate, error) {
	identity, err := SnapshotCandidateIdentity(input.Path, input.RootPath)
	if err != nil {
		return Candidate{}, err
	}
	candidate := Candidate{
		CategoryID:      input.CategoryID,
		Reason:          input.Reason,
		Risk:            input.Risk,
		DefaultSelected: input.DefaultSelected,
		Selected:        input.Selected,
		LogicalBytes:    identity.LogicalBytes,
		DiskBytes:       identity.DiskBytes,
		Identity:        identity,
	}
	candidate.ID = CandidateStableID(candidate)
	return candidate, nil
}

func NewPlan(input NewPlanInput) (Plan, error) {
	generatedAt := input.GeneratedAt
	if generatedAt.IsZero() {
		generatedAt = time.Now()
	}
	plan := Plan{
		SchemaVersion:         PlanSchemaVersion,
		CategoryPolicyVersion: CategoryPolicyVersion,
		GeneratedAt:           generatedAt,
		StaleAfterSeconds:     int64(DefaultPlanStaleAfter / time.Second),
		Source:                input.Source,
		Root:                  input.Root,
		Categories:            append([]PlanCategory(nil), input.Categories...),
		Candidates:            append([]Candidate(nil), input.Candidates...),
		Apply:                 DefaultPlanApplyContract(),
		HashInputs:            DefaultPlanHashInputs(),
	}
	plan.Totals = SummarizeCandidates(plan.Candidates)
	return SealPlan(plan)
}

func SealPlan(plan Plan) (Plan, error) {
	if plan.SchemaVersion == 0 {
		plan.SchemaVersion = PlanSchemaVersion
	}
	if plan.CategoryPolicyVersion == "" {
		plan.CategoryPolicyVersion = CategoryPolicyVersion
	}
	if plan.StaleAfterSeconds == 0 {
		plan.StaleAfterSeconds = int64(DefaultPlanStaleAfter / time.Second)
	}
	if plan.Apply.CleanApplyRequiresPlan == false && plan.Apply.DirectCategoryApply == "" {
		plan.Apply = DefaultPlanApplyContract()
	}
	if len(plan.HashInputs) == 0 {
		plan.HashInputs = DefaultPlanHashInputs()
	}
	plan.Totals = SummarizeCandidates(plan.Candidates)
	hash, err := ComputePlanHash(plan)
	if err != nil {
		return Plan{}, err
	}
	plan.PlanHash = hash
	return plan, nil
}

func CandidateStableID(candidate Candidate) string {
	payload := struct {
		CategoryID   CategoryID `json:"categoryId"`
		Path         string     `json:"path"`
		RealPath     string     `json:"realPath"`
		RootRealPath string     `json:"rootRealPath"`
		Device       uint64     `json:"device,omitempty"`
		Inode        uint64     `json:"inode,omitempty"`
	}{
		CategoryID:   candidate.CategoryID,
		Path:         filepath.Clean(candidate.Identity.Path),
		RealPath:     filepath.Clean(candidate.Identity.RealPath),
		RootRealPath: filepath.Clean(candidate.Identity.RootRealPath),
		Device:       candidate.Identity.Device,
		Inode:        candidate.Identity.Inode,
	}
	encoded, _ := json.Marshal(payload)
	sum := sha256.Sum256(encoded)
	return "cand_" + hex.EncodeToString(sum[:8])
}

func SummarizeCandidates(candidates []Candidate) PlanTotals {
	totals := PlanTotals{CandidateCount: len(candidates)}
	for _, candidate := range candidates {
		totals.LogicalBytes += candidate.LogicalBytes
		totals.DiskBytes += candidate.DiskBytes
		if candidate.Selected {
			totals.SelectedCount++
			totals.SelectedLogicalBytes += candidate.LogicalBytes
			totals.SelectedDiskBytes += candidate.DiskBytes
		}
	}
	return totals
}

func ComputePlanHash(plan Plan) (string, error) {
	plan.PlanHash = ""
	payload, err := json.Marshal(plan)
	if err != nil {
		return "", err
	}
	sum := sha256.Sum256(payload)
	return PlanHashAlgorithm + ":" + hex.EncodeToString(sum[:]), nil
}

func ValidatePlanHash(plan Plan) error {
	if plan.PlanHash == "" {
		return errors.New("plan hash is empty")
	}
	expected, err := ComputePlanHash(plan)
	if err != nil {
		return err
	}
	if plan.PlanHash != expected {
		return fmt.Errorf("plan hash mismatch: got %s want %s", plan.PlanHash, expected)
	}
	return nil
}

func ValidateCleanApplyInvocation(invocation CleanApplyInvocation) []Refusal {
	var refusals []Refusal
	if !invocation.Apply {
		refusals = append(refusals, Refusal{Code: RefusalApplyFlagMissing, Message: "clean refuses to delete unless --apply is present"})
	}
	if strings.TrimSpace(invocation.PlanPath) == "" {
		refusals = append(refusals, Refusal{Code: RefusalPlanPathMissing, Message: "clean --apply requires --plan PATH in v1"})
	}
	if invocation.DirectCategory != "" {
		refusals = append(refusals, Refusal{
			Code:    RefusalDirectCategoryApply,
			Message: "direct category apply is unsupported in v1; run scan/target/xcode, save a plan, then clean --apply --plan PATH",
		})
	}
	return refusals
}

func ValidatePlanForApply(plan Plan, now time.Time) ApplyPreflightResult {
	if now.IsZero() {
		now = time.Now()
	}
	result := ApplyPreflightResult{CheckedAt: now}
	if plan.SchemaVersion != PlanSchemaVersion {
		result.addRefusal(Refusal{Code: RefusalSchemaVersion, Message: fmt.Sprintf("plan schemaVersion %d is not supported", plan.SchemaVersion)})
	}
	if plan.CategoryPolicyVersion != CategoryPolicyVersion {
		result.addRefusal(Refusal{Code: RefusalCategoryPolicyVersion, Message: fmt.Sprintf("category policy version %q is not supported", plan.CategoryPolicyVersion)})
	}
	if plan.GeneratedAt.IsZero() {
		result.addRefusal(Refusal{Code: RefusalGeneratedAtMissing, Message: "plan generatedAt is required"})
	}
	if plan.PlanHash == "" {
		result.addRefusal(Refusal{Code: RefusalPlanHashMissing, Message: "planHash is required"})
	} else if err := ValidatePlanHash(plan); err != nil {
		result.addRefusal(Refusal{Code: RefusalPlanHashMismatch, Message: err.Error()})
	}
	staleAfter := time.Duration(plan.StaleAfterSeconds) * time.Second
	if staleAfter <= 0 {
		staleAfter = DefaultPlanStaleAfter
	}
	if !plan.GeneratedAt.IsZero() && now.After(plan.GeneratedAt.Add(staleAfter)) {
		result.addRefusal(Refusal{
			Code:    RefusalPlanStale,
			Message: fmt.Sprintf("plan is older than stale window %s", staleAfter),
		})
	}
	for _, candidate := range plan.Candidates {
		if !candidate.Selected {
			continue
		}
		result.CandidateCount++
		result.LogicalBytes += candidate.LogicalBytes
		result.DiskBytes += candidate.DiskBytes
		if candidate.Risk == RiskOutOfScope {
			result.addRefusal(Refusal{
				Code:        RefusalSelectedOutOfScopeCandidate,
				CandidateID: candidate.ID,
				Path:        candidate.Identity.Path,
				Message:     "out-of-scope candidates cannot be selected for apply",
			})
		}
	}
	return result
}

func RevalidatePlanCandidates(plan Plan, options RevalidationOptions) ApplyPreflightResult {
	options = normalizeRevalidationOptions(options)
	result := ValidatePlanForApply(plan, options.CheckedAt)
	for _, candidate := range plan.Candidates {
		if options.SelectedOnly && !candidate.Selected {
			continue
		}
		for _, refusal := range RevalidateCandidate(candidate, options) {
			result.addRefusal(refusal)
		}
	}
	return result
}

func RevalidateCandidate(candidate Candidate, options RevalidationOptions) []Refusal {
	options = normalizeRevalidationOptions(options)
	var refusals []Refusal
	add := func(code RefusalCode, path string, message string) {
		refusals = append(refusals, Refusal{Code: code, CandidateID: candidate.ID, Path: path, Message: message})
	}

	rootInfo, err := os.Lstat(candidate.Identity.RootPath)
	if err != nil {
		add(RefusalRootLstat, candidate.Identity.RootPath, err.Error())
		return refusals
	}
	if rootInfo.Mode()&os.ModeSymlink != 0 {
		add(RefusalRootSymlink, candidate.Identity.RootPath, "root is now a symlink")
		return refusals
	}
	rootStat, err := statFromFileInfo(rootInfo)
	if err != nil {
		add(RefusalRootLstat, candidate.Identity.RootPath, err.Error())
		return refusals
	}
	if rootStat.UID != options.CurrentUID || rootStat.UID != candidate.Identity.RootUID {
		add(RefusalRootOwnership, candidate.Identity.RootPath, "root ownership no longer matches the current user and saved plan")
	}
	if rootStat.Device != candidate.Identity.RootDevice || rootStat.Inode != candidate.Identity.RootInode {
		add(RefusalRootIdentityChanged, candidate.Identity.RootPath, "root device/inode changed since the plan was generated")
	}
	rootRealPath, err := filepath.EvalSymlinks(candidate.Identity.RootPath)
	if err != nil {
		add(RefusalRootRealpath, candidate.Identity.RootPath, err.Error())
		return refusals
	}
	rootRealPath = filepath.Clean(rootRealPath)
	if rootRealPath != filepath.Clean(candidate.Identity.RootRealPath) {
		add(RefusalRootRealpathChanged, candidate.Identity.RootPath, "root realpath changed since the plan was generated")
	}

	info, err := os.Lstat(candidate.Identity.Path)
	if err != nil {
		add(RefusalCandidateLstat, candidate.Identity.Path, err.Error())
		return refusals
	}
	if info.Mode()&os.ModeSymlink != 0 {
		add(RefusalCandidateSymlink, candidate.Identity.Path, "candidate is now a symlink")
		return refusals
	}
	current, err := statFromFileInfo(info)
	if err != nil {
		add(RefusalCandidateLstat, candidate.Identity.Path, err.Error())
		return refusals
	}
	if current.UID != options.CurrentUID || current.UID != candidate.Identity.UID {
		add(RefusalCandidateOwnership, candidate.Identity.Path, "candidate ownership no longer matches the current user and saved plan")
	}
	realPath, err := filepath.EvalSymlinks(candidate.Identity.Path)
	if err != nil {
		add(RefusalCandidateRealpath, candidate.Identity.Path, err.Error())
		return refusals
	}
	realPath = filepath.Clean(realPath)
	if realPath != filepath.Clean(candidate.Identity.RealPath) {
		add(RefusalCandidateRealpathChanged, candidate.Identity.Path, "candidate realpath changed since the plan was generated")
	}
	if !pathContainedInRoot(realPath, rootRealPath) {
		add(RefusalCandidateOutOfRoot, candidate.Identity.Path, "candidate realpath is outside the root realpath")
	}
	if !candidateIdentityMatches(candidate.Identity, current, info, realPath) {
		add(RefusalCandidateIdentityChanged, candidate.Identity.Path, "candidate identity or size changed since the plan was generated")
	}
	return refusals
}

func SnapshotPlanRoot(path string) (PlanRoot, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return PlanRoot{}, err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return PlanRoot{}, fmt.Errorf("root %q is a symlink", path)
	}
	stat, err := statFromFileInfo(info)
	if err != nil {
		return PlanRoot{}, err
	}
	realPath, err := filepath.EvalSymlinks(path)
	if err != nil {
		return PlanRoot{}, err
	}
	return PlanRoot{
		Path:     filepath.Clean(path),
		RealPath: filepath.Clean(realPath),
		Device:   stat.Device,
		Inode:    stat.Inode,
		UID:      stat.UID,
		GID:      stat.GID,
	}, nil
}

func SnapshotCandidateIdentity(path string, rootPath string) (CandidateIdentity, error) {
	root, err := SnapshotPlanRoot(rootPath)
	if err != nil {
		return CandidateIdentity{}, err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return CandidateIdentity{}, err
	}
	stat, err := statFromFileInfo(info)
	if err != nil {
		return CandidateIdentity{}, err
	}
	realPath := filepath.Clean(path)
	if info.Mode()&os.ModeSymlink == 0 {
		resolved, err := filepath.EvalSymlinks(path)
		if err != nil {
			return CandidateIdentity{}, err
		}
		realPath = filepath.Clean(resolved)
		if !pathContainedInRoot(realPath, root.RealPath) {
			return CandidateIdentity{}, fmt.Errorf("candidate %q realpath %q is outside root %q", path, realPath, root.RealPath)
		}
	}
	return CandidateIdentity{
		Path:         filepath.Clean(path),
		RealPath:     realPath,
		RootPath:     root.Path,
		RootRealPath: root.RealPath,
		Kind:         candidateKindFromMode(info.Mode()),
		Mode:         uint32(info.Mode()),
		LogicalBytes: info.Size(),
		DiskBytes:    stat.DiskBytes,
		ModTime:      info.ModTime(),
		Device:       stat.Device,
		Inode:        stat.Inode,
		LinkCount:    stat.LinkCount,
		UID:          stat.UID,
		GID:          stat.GID,
		RootDevice:   root.Device,
		RootInode:    root.Inode,
		RootUID:      root.UID,
		RootGID:      root.GID,
	}, nil
}

func WritePlanArtifact(pathName string, plan Plan) error {
	if pathName == "" {
		return fmt.Errorf("plan artifact path is empty")
	}
	sealed, err := SealPlan(plan)
	if err != nil {
		return err
	}
	plan = sealed
	dir := filepath.Dir(pathName)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("create plan artifact dir: %w", err)
	}
	file, err := os.OpenFile(pathName, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return fmt.Errorf("create plan artifact: %w", err)
	}
	encoder := json.NewEncoder(file)
	encoder.SetIndent("", "  ")
	if err := encoder.Encode(plan); err != nil {
		_ = file.Close()
		return fmt.Errorf("write plan artifact: %w", err)
	}
	if err := file.Close(); err != nil {
		return fmt.Errorf("close plan artifact: %w", err)
	}
	if err := os.Chmod(pathName, 0o600); err != nil {
		return fmt.Errorf("chmod plan artifact: %w", err)
	}
	return nil
}

func ReadPlanArtifact(pathName string) (Plan, error) {
	file, err := os.Open(pathName)
	if err != nil {
		return Plan{}, err
	}
	defer file.Close()
	var plan Plan
	if err := json.NewDecoder(file).Decode(&plan); err != nil {
		return Plan{}, err
	}
	return plan, nil
}

func (result *ApplyPreflightResult) addRefusal(refusal Refusal) {
	result.Refusals = append(result.Refusals, refusal)
}

func normalizeRevalidationOptions(options RevalidationOptions) RevalidationOptions {
	if !options.CurrentUIDSet {
		options.CurrentUID = uint32(os.Getuid())
		options.CurrentUIDSet = true
	}
	if options.CheckedAt.IsZero() {
		options.CheckedAt = time.Now()
	}
	return options
}

type statIdentity struct {
	Device    uint64
	Inode     uint64
	LinkCount uint64
	UID       uint32
	GID       uint32
	DiskBytes int64
}

func statFromFileInfo(info os.FileInfo) (statIdentity, error) {
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok {
		return statIdentity{}, fmt.Errorf("unsupported stat type %T", info.Sys())
	}
	return statIdentity{
		Device:    uint64(stat.Dev),
		Inode:     uint64(stat.Ino),
		LinkCount: uint64(stat.Nlink),
		UID:       stat.Uid,
		GID:       stat.Gid,
		DiskBytes: stat.Blocks * 512,
	}, nil
}

func candidateKindFromMode(mode os.FileMode) CandidateKind {
	switch {
	case mode&os.ModeSymlink != 0:
		return CandidateKindSymlink
	case mode.IsDir():
		return CandidateKindDirectory
	case mode.IsRegular():
		return CandidateKindFile
	default:
		return CandidateKindOther
	}
}

func candidateIdentityMatches(saved CandidateIdentity, current statIdentity, info os.FileInfo, realPath string) bool {
	return filepath.Clean(saved.RealPath) == filepath.Clean(realPath) &&
		saved.Kind == candidateKindFromMode(info.Mode()) &&
		saved.Mode == uint32(info.Mode()) &&
		saved.LogicalBytes == info.Size() &&
		saved.ModTime.Equal(info.ModTime()) &&
		saved.Device == current.Device &&
		saved.Inode == current.Inode &&
		saved.LinkCount == current.LinkCount &&
		saved.UID == current.UID &&
		saved.GID == current.GID &&
		saved.DiskBytes == current.DiskBytes
}

func pathContainedInRoot(path string, root string) bool {
	cleanPath := filepath.Clean(path)
	cleanRoot := filepath.Clean(root)
	return cleanPath == cleanRoot || strings.HasPrefix(cleanPath, cleanRoot+string(filepath.Separator))
}
