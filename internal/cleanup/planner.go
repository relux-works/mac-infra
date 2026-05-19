package cleanup

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const (
	DefaultLargeFileBytes = 500 * 1024 * 1024
	DefaultOldFileAge     = 180 * 24 * time.Hour
)

type PlannerOptions struct {
	Source         PlanSource
	Root           string
	HomeDir        string
	CategoryIDs    []CategoryID
	GeneratedAt    time.Time
	LargeFileBytes int64
	OldFileAge     time.Duration
	CurrentUID     uint32
	CurrentUIDSet  bool
}

type PlannerResult struct {
	Plan     Plan
	Rows     []CategorySummary
	Warnings []PlannerWarning
}

type PlannerWarningCode string

const (
	PlannerWarningPermissionDenied PlannerWarningCode = "permission_denied"
)

type PlannerWarning struct {
	Code      PlannerWarningCode `json:"code"`
	Path      string             `json:"path"`
	Operation string             `json:"operation"`
	Message   string             `json:"message"`
}

type CategorySummary struct {
	ID              CategoryID
	Risk            RiskLevel
	DefaultSelected bool
	CandidateCount  int
	SelectedCount   int
	LogicalBytes    int64
	DiskBytes       int64
	Reason          string
}

type RootRefusalError struct {
	Path   string
	Reason string
}

func (err RootRefusalError) Error() string {
	return fmt.Sprintf("refusing cleanup root %q: %s", err.Path, err.Reason)
}

func BuildPlan(ctx context.Context, options PlannerOptions) (PlannerResult, error) {
	options, err := normalizePlannerOptions(options)
	if err != nil {
		return PlannerResult{}, err
	}
	if err := ctx.Err(); err != nil {
		return PlannerResult{}, err
	}

	policy := DefaultPolicy()
	targetRoot := ""
	planRootPath := options.HomeDir
	if options.Source == PlanSourceTarget {
		if strings.TrimSpace(options.Root) == "" {
			return PlannerResult{}, errors.New("target root is required")
		}
		targetRoot, err = validateCleanupRoot(expandHome(options.Root, options.HomeDir), options.HomeDir, policy.Safety, options.CurrentUID)
		if err != nil {
			return PlannerResult{}, err
		}
		planRootPath = targetRoot
	}

	planRoot, err := SnapshotPlanRoot(planRootPath)
	if err != nil {
		return PlannerResult{}, fmt.Errorf("snapshot plan root: %w", err)
	}

	categories, err := categoriesForSource(options.Source, options.CategoryIDs)
	if err != nil {
		return PlannerResult{}, err
	}

	var allCandidates []Candidate
	var warnings []PlannerWarning
	rows := make([]CategorySummary, 0, len(categories))
	planCategories := make([]PlanCategory, 0, len(categories))
	for _, category := range categories {
		if err := ctx.Err(); err != nil {
			return PlannerResult{}, err
		}
		candidates, err := buildCategoryCandidates(ctx, categoryPlanInput{
			category: category,
			options:  options,
			policy:   policy,
			target:   targetRoot,
			warnings: &warnings,
		})
		if err != nil {
			return PlannerResult{}, err
		}
		sortCandidates(candidates)
		allCandidates = append(allCandidates, candidates...)
		rows = append(rows, summarizeCategory(category, candidates))
		planCategories = append(planCategories, PlanCategory{
			ID:              category.ID,
			Risk:            category.Risk,
			DefaultSelected: category.DefaultSelected,
		})
	}
	sortCandidates(allCandidates)

	plan, err := NewPlan(NewPlanInput{
		GeneratedAt: options.GeneratedAt,
		Source:      options.Source,
		Root:        planRoot,
		Categories:  planCategories,
		Candidates:  allCandidates,
		Warnings:    warnings,
	})
	if err != nil {
		return PlannerResult{}, err
	}
	return PlannerResult{Plan: plan, Rows: rows, Warnings: warnings}, nil
}

func SupportedCategoryIDs(source PlanSource) []CategoryID {
	switch source {
	case PlanSourceScan:
		return []CategoryID{
			CategoryXcodeDerivedData,
			CategoryRotatedLogs,
			CategoryDownloads,
			CategoryAppCaches,
			CategoryIOSBackups,
			CategoryXcodeArchives,
			CategoryXcodeDeviceSupport,
			CategoryXcodeSimulators,
		}
	case PlanSourceTarget:
		return []CategoryID{
			CategoryTargetGenerated,
			CategoryLargeFiles,
			CategoryOldFiles,
		}
	case PlanSourceXcode:
		return []CategoryID{
			CategoryXcodeDerivedData,
			CategoryXcodeArchives,
			CategoryXcodeDeviceSupport,
			CategoryXcodeSimulators,
		}
	default:
		return nil
	}
}

type categoryPlanInput struct {
	category Category
	options  PlannerOptions
	policy   Policy
	target   string
	warnings *[]PlannerWarning
}

type candidateSpec struct {
	path     string
	root     string
	reason   string
	risk     RiskLevel
	selected bool
}

func normalizePlannerOptions(options PlannerOptions) (PlannerOptions, error) {
	if options.Source == "" {
		options.Source = PlanSourceScan
	}
	if options.GeneratedAt.IsZero() {
		options.GeneratedAt = time.Now().UTC()
	} else {
		options.GeneratedAt = options.GeneratedAt.UTC()
	}
	if options.LargeFileBytes <= 0 {
		options.LargeFileBytes = DefaultLargeFileBytes
	}
	if options.OldFileAge <= 0 {
		options.OldFileAge = DefaultOldFileAge
	}
	if !options.CurrentUIDSet {
		options.CurrentUID = uint32(os.Getuid())
		options.CurrentUIDSet = true
	}
	if strings.TrimSpace(options.HomeDir) == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			return PlannerOptions{}, fmt.Errorf("resolve home dir: %w", err)
		}
		options.HomeDir = home
	}
	home, err := absoluteCleanPath(options.HomeDir)
	if err != nil {
		return PlannerOptions{}, fmt.Errorf("resolve home dir: %w", err)
	}
	options.HomeDir = home
	return options, nil
}

func categoriesForSource(source PlanSource, ids []CategoryID) ([]Category, error) {
	supported := SupportedCategoryIDs(source)
	if len(supported) == 0 {
		return nil, fmt.Errorf("unsupported plan source %q", source)
	}
	supportedSet := make(map[CategoryID]bool, len(supported))
	for _, id := range supported {
		supportedSet[id] = true
	}

	requested := supportedSet
	if len(ids) > 0 {
		requested = make(map[CategoryID]bool, len(ids))
		for _, id := range ids {
			if !supportedSet[id] {
				return nil, fmt.Errorf("category %q is not supported by %s", id, source)
			}
			requested[id] = true
		}
	}

	byID := make(map[CategoryID]Category)
	for _, category := range DefaultCategories() {
		byID[category.ID] = category
	}
	categories := make([]Category, 0, len(requested))
	for _, id := range supported {
		if requested[id] {
			category, ok := byID[id]
			if !ok {
				return nil, fmt.Errorf("category %q is not defined by policy", id)
			}
			categories = append(categories, category)
		}
	}
	return categories, nil
}

func buildCategoryCandidates(ctx context.Context, input categoryPlanInput) ([]Candidate, error) {
	specs, err := collectCandidateSpecs(ctx, input)
	if err != nil {
		return nil, err
	}
	candidates := make([]Candidate, 0, len(specs))
	for _, spec := range specs {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		candidate, err := newPlannedCandidate(input.category, spec, input.policy.Safety, input.options.CurrentUID)
		if err != nil {
			if isPermissionError(err) {
				addPermissionWarning(input.warnings, "measure candidate", spec.path, err)
				continue
			}
			return nil, err
		}
		candidates = append(candidates, candidate)
	}
	return candidates, nil
}

func collectCandidateSpecs(ctx context.Context, input categoryPlanInput) ([]candidateSpec, error) {
	switch input.category.ID {
	case CategoryTargetGenerated:
		return collectTargetGeneratedCandidates(input.category, input.target, input.warnings)
	case CategoryLargeFiles:
		return collectLargeFileCandidates(ctx, input.category, input.target, input.options.LargeFileBytes, input.warnings)
	case CategoryOldFiles:
		cutoff := input.options.GeneratedAt.Add(-input.options.OldFileAge)
		return collectOldFileCandidates(ctx, input.category, input.target, cutoff, input.warnings)
	case CategoryXcodeDerivedData:
		return collectImmediateChildren(input.category, input.options.HomeDir, input.policy.Safety, input.options.CurrentUID, input.warnings)
	case CategoryRotatedLogs:
		return collectRotatedLogCandidates(ctx, input.category, input.options.HomeDir, input.policy.Safety, input.options.CurrentUID, input.options.GeneratedAt, input.warnings)
	case CategoryDownloads, CategoryAppCaches, CategoryIOSBackups, CategoryXcodeDeviceSupport, CategoryXcodeSimulators:
		return collectImmediateChildren(input.category, input.options.HomeDir, input.policy.Safety, input.options.CurrentUID, input.warnings)
	case CategoryXcodeArchives:
		return collectXcodeArchiveCandidates(ctx, input.category, input.options.HomeDir, input.policy.Safety, input.options.CurrentUID, input.warnings)
	default:
		return nil, fmt.Errorf("category %q has no planner", input.category.ID)
	}
}

func collectTargetGeneratedCandidates(category Category, targetRoot string, warnings *[]PlannerWarning) ([]candidateSpec, error) {
	if targetRoot == "" {
		return nil, errors.New("target root is required for target-generated-data")
	}
	seen := map[string]bool{}
	var specs []candidateSpec
	for _, patternText := range category.Patterns {
		candidatePath := filepath.Join(targetRoot, filepath.FromSlash(patternText))
		info, err := os.Lstat(candidatePath)
		if errors.Is(err, os.ErrNotExist) {
			continue
		}
		if err != nil {
			if isPermissionError(err) {
				addPermissionWarning(warnings, "lstat candidate", candidatePath, err)
				continue
			}
			return nil, fmt.Errorf("lstat target-generated candidate %q: %w", candidatePath, err)
		}
		if !info.IsDir() && info.Mode()&os.ModeSymlink == 0 {
			continue
		}
		addSpec(&specs, seen, candidateSpec{
			path:     candidatePath,
			root:     targetRoot,
			reason:   category.Reason,
			risk:     category.Risk,
			selected: category.DefaultSelected,
		})
	}
	return specs, nil
}

func collectLargeFileCandidates(ctx context.Context, category Category, targetRoot string, threshold int64, warnings *[]PlannerWarning) ([]candidateSpec, error) {
	return collectTargetFiles(ctx, category, targetRoot, func(pathName string, info fs.FileInfo) bool {
		return info.Mode().IsRegular() && info.Size() >= threshold
	}, warnings)
}

func collectOldFileCandidates(ctx context.Context, category Category, targetRoot string, cutoff time.Time, warnings *[]PlannerWarning) ([]candidateSpec, error) {
	return collectTargetFiles(ctx, category, targetRoot, func(pathName string, info fs.FileInfo) bool {
		return info.Mode().IsRegular() && !info.ModTime().After(cutoff)
	}, warnings)
}

func collectTargetFiles(ctx context.Context, category Category, targetRoot string, keep func(string, fs.FileInfo) bool, warnings *[]PlannerWarning) ([]candidateSpec, error) {
	if targetRoot == "" {
		return nil, fmt.Errorf("target root is required for %s", category.ID)
	}
	seen := map[string]bool{}
	var specs []candidateSpec
	err := filepath.WalkDir(targetRoot, func(pathName string, entry fs.DirEntry, walkErr error) error {
		if err := ctx.Err(); err != nil {
			return err
		}
		if walkErr != nil {
			if isPermissionError(walkErr) {
				addPermissionWarning(warnings, "walk target", pathName, walkErr)
				if entry != nil && entry.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
			return walkErr
		}
		if pathName == targetRoot {
			return nil
		}
		info, err := entry.Info()
		if err != nil {
			if isPermissionError(err) {
				addPermissionWarning(warnings, "stat target", pathName, err)
				if entry.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
			return err
		}
		if info.Mode()&os.ModeSymlink != 0 {
			if entry.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if keep(pathName, info) {
			addSpec(&specs, seen, candidateSpec{
				path:     pathName,
				root:     targetRoot,
				reason:   category.Reason,
				risk:     category.Risk,
				selected: category.DefaultSelected,
			})
		}
		return nil
	})
	if err != nil {
		if isPermissionError(err) {
			addPermissionWarning(warnings, "walk target", targetRoot, err)
			return specs, nil
		}
		return nil, fmt.Errorf("walk %s candidates under %q: %w", category.ID, targetRoot, err)
	}
	return specs, nil
}

func collectImmediateChildren(category Category, homeDir string, safety RootSafetyPolicy, uid uint32, warnings *[]PlannerWarning) ([]candidateSpec, error) {
	seen := map[string]bool{}
	var specs []candidateSpec
	for _, root := range category.Roots {
		rootPath, ok, err := prepareCategoryRoot(root.Path, homeDir, safety, uid)
		if err != nil {
			if isPermissionError(err) {
				addPermissionWarning(warnings, "prepare category root", expandHome(root.Path, homeDir), err)
				continue
			}
			return nil, err
		}
		if !ok {
			continue
		}
		entries, err := os.ReadDir(rootPath)
		if err != nil {
			if isPermissionError(err) {
				addPermissionWarning(warnings, "read category root", rootPath, err)
				continue
			}
			return nil, fmt.Errorf("read %s root %q: %w", category.ID, rootPath, err)
		}
		sort.Slice(entries, func(i, j int) bool {
			return entries[i].Name() < entries[j].Name()
		})
		for _, entry := range entries {
			addSpec(&specs, seen, candidateSpec{
				path:     filepath.Join(rootPath, entry.Name()),
				root:     rootPath,
				reason:   category.Reason,
				risk:     category.Risk,
				selected: category.DefaultSelected,
			})
		}
	}
	return specs, nil
}

func collectRotatedLogCandidates(ctx context.Context, category Category, homeDir string, safety RootSafetyPolicy, uid uint32, now time.Time, warnings *[]PlannerWarning) ([]candidateSpec, error) {
	seen := map[string]bool{}
	var specs []candidateSpec
	cutoff := now.Add(-time.Duration(category.MinimumAgeDays) * 24 * time.Hour)
	for _, root := range category.Roots {
		rootPath, ok, err := prepareCategoryRoot(root.Path, homeDir, safety, uid)
		if err != nil {
			if isPermissionError(err) {
				addPermissionWarning(warnings, "prepare category root", expandHome(root.Path, homeDir), err)
				continue
			}
			return nil, err
		}
		if !ok {
			continue
		}
		err = filepath.WalkDir(rootPath, func(pathName string, entry fs.DirEntry, walkErr error) error {
			if err := ctx.Err(); err != nil {
				return err
			}
			if walkErr != nil {
				if isPermissionError(walkErr) {
					addPermissionWarning(warnings, "walk rotated logs", pathName, walkErr)
					if entry != nil && entry.IsDir() {
						return filepath.SkipDir
					}
					return nil
				}
				return walkErr
			}
			if pathName == rootPath {
				return nil
			}
			info, err := entry.Info()
			if err != nil {
				if isPermissionError(err) {
					addPermissionWarning(warnings, "stat rotated log", pathName, err)
					if entry.IsDir() {
						return filepath.SkipDir
					}
					return nil
				}
				return err
			}
			if info.Mode()&os.ModeSymlink != 0 {
				if entry.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
			if !info.Mode().IsRegular() || info.ModTime().After(cutoff) {
				return nil
			}
			if !matchesAnyPattern(rootPath, pathName, entry.Name(), category.Patterns) {
				return nil
			}
			addSpec(&specs, seen, candidateSpec{
				path:     pathName,
				root:     rootPath,
				reason:   category.Reason,
				risk:     category.Risk,
				selected: category.DefaultSelected,
			})
			return nil
		})
		if err != nil {
			if isPermissionError(err) {
				addPermissionWarning(warnings, "walk rotated logs", rootPath, err)
				continue
			}
			return nil, fmt.Errorf("walk rotated logs under %q: %w", rootPath, err)
		}
	}
	return specs, nil
}

func collectXcodeArchiveCandidates(ctx context.Context, category Category, homeDir string, safety RootSafetyPolicy, uid uint32, warnings *[]PlannerWarning) ([]candidateSpec, error) {
	seen := map[string]bool{}
	var specs []candidateSpec
	for _, root := range category.Roots {
		rootPath, ok, err := prepareCategoryRoot(root.Path, homeDir, safety, uid)
		if err != nil {
			if isPermissionError(err) {
				addPermissionWarning(warnings, "prepare category root", expandHome(root.Path, homeDir), err)
				continue
			}
			return nil, err
		}
		if !ok {
			continue
		}
		err = filepath.WalkDir(rootPath, func(pathName string, entry fs.DirEntry, walkErr error) error {
			if err := ctx.Err(); err != nil {
				return err
			}
			if walkErr != nil {
				if isPermissionError(walkErr) {
					addPermissionWarning(warnings, "walk Xcode archives", pathName, walkErr)
					if entry != nil && entry.IsDir() {
						return filepath.SkipDir
					}
					return nil
				}
				return walkErr
			}
			if pathName == rootPath {
				return nil
			}
			if entry.Type()&os.ModeSymlink != 0 {
				if entry.IsDir() {
					return filepath.SkipDir
				}
				return nil
			}
			if entry.IsDir() && strings.HasSuffix(entry.Name(), ".xcarchive") {
				addSpec(&specs, seen, candidateSpec{
					path:     pathName,
					root:     rootPath,
					reason:   category.Reason,
					risk:     category.Risk,
					selected: category.DefaultSelected,
				})
				return filepath.SkipDir
			}
			return nil
		})
		if err != nil {
			if isPermissionError(err) {
				addPermissionWarning(warnings, "walk Xcode archives", rootPath, err)
				continue
			}
			return nil, fmt.Errorf("walk Xcode archives under %q: %w", rootPath, err)
		}
	}
	return specs, nil
}

func newPlannedCandidate(category Category, spec candidateSpec, safety RootSafetyPolicy, uid uint32) (Candidate, error) {
	logicalBytes, diskBytes, err := measurePath(spec.path)
	if err != nil {
		return Candidate{}, err
	}
	identity, err := SnapshotCandidateIdentity(spec.path, spec.root)
	if err != nil {
		return Candidate{}, err
	}
	risk := spec.risk
	selected := spec.selected && risk == RiskSafeGenerated
	defaultSelected := category.DefaultSelected && risk == RiskSafeGenerated
	reason := spec.reason

	if safety.RefuseSymlinkCandidates && identity.Kind == CandidateKindSymlink {
		risk = RiskReviewOnly
		selected = false
		defaultSelected = false
		reason = "Safety policy refuses symlink candidates for cleanup; review manually. " + reason
	}
	if safety.RequireUserOwnedCandidates && identity.UID != uid {
		risk = RiskReviewOnly
		selected = false
		defaultSelected = false
		reason = "Candidate is not owned by the current user; review manually. " + reason
	}
	if identity.Kind == CandidateKindOther {
		risk = RiskReviewOnly
		selected = false
		defaultSelected = false
		reason = "Candidate is neither a regular file nor directory; review manually. " + reason
	}

	candidate := Candidate{
		CategoryID:      category.ID,
		Reason:          reason,
		Risk:            risk,
		DefaultSelected: defaultSelected,
		Selected:        selected,
		LogicalBytes:    logicalBytes,
		DiskBytes:       diskBytes,
		Identity:        identity,
	}
	candidate.ID = CandidateStableID(candidate)
	return candidate, nil
}

func prepareCategoryRoot(rootPath string, homeDir string, safety RootSafetyPolicy, uid uint32) (string, bool, error) {
	expanded, err := absoluteCleanPath(expandHome(rootPath, homeDir))
	if err != nil {
		return "", false, fmt.Errorf("resolve category root %q: %w", rootPath, err)
	}
	if _, err := os.Lstat(expanded); errors.Is(err, os.ErrNotExist) {
		return expanded, false, nil
	} else if err != nil {
		return "", false, fmt.Errorf("lstat category root %q: %w", expanded, err)
	}
	validated, err := validateCleanupRoot(expanded, homeDir, safety, uid)
	if err != nil {
		return "", false, err
	}
	return validated, true, nil
}

func validateCleanupRoot(rootPath string, homeDir string, safety RootSafetyPolicy, uid uint32) (string, error) {
	absPath, err := absoluteCleanPath(rootPath)
	if err != nil {
		return "", fmt.Errorf("resolve cleanup root: %w", err)
	}
	decision := safety.EvaluateRoot(absPath, homeDir)
	if !decision.Allowed {
		return "", RootRefusalError{Path: decision.Path, Reason: decision.Reason}
	}
	info, err := os.Lstat(absPath)
	if err != nil {
		return "", fmt.Errorf("lstat cleanup root %q: %w", absPath, err)
	}
	if safety.RefuseSymlinkRoots && info.Mode()&os.ModeSymlink != 0 {
		return "", RootRefusalError{Path: absPath, Reason: "cleanup root is a symlink"}
	}
	stat, err := statFromFileInfo(info)
	if err != nil {
		return "", fmt.Errorf("stat cleanup root %q: %w", absPath, err)
	}
	if safety.RequireUserOwnedRoots && stat.UID != uid {
		return "", RootRefusalError{Path: absPath, Reason: "cleanup root is not owned by the current user"}
	}
	if safety.RequireRealpathContainment {
		realPath, err := filepath.EvalSymlinks(absPath)
		if err != nil {
			return "", fmt.Errorf("resolve cleanup root realpath %q: %w", absPath, err)
		}
		if !pathContainedInRoot(filepath.Clean(realPath), absPath) {
			return "", RootRefusalError{Path: absPath, Reason: "cleanup root realpath escapes the requested root"}
		}
	}
	return absPath, nil
}

func measurePath(pathName string) (int64, int64, error) {
	var logicalBytes int64
	var diskBytes int64
	err := filepath.WalkDir(pathName, func(current string, entry fs.DirEntry, walkErr error) error {
		if walkErr != nil {
			return walkErr
		}
		info, err := entry.Info()
		if err != nil {
			return err
		}
		stat, err := statFromFileInfo(info)
		if err != nil {
			return err
		}
		logicalBytes += info.Size()
		diskBytes += stat.DiskBytes
		if info.Mode()&os.ModeSymlink != 0 && entry.IsDir() {
			return filepath.SkipDir
		}
		return nil
	})
	if err != nil {
		return 0, 0, fmt.Errorf("measure %q: %w", pathName, err)
	}
	return logicalBytes, diskBytes, nil
}

func summarizeCategory(category Category, candidates []Candidate) CategorySummary {
	summary := CategorySummary{
		ID:              category.ID,
		Risk:            category.Risk,
		DefaultSelected: category.DefaultSelected,
		Reason:          category.Reason,
		CandidateCount:  len(candidates),
	}
	for _, candidate := range candidates {
		summary.LogicalBytes += candidate.LogicalBytes
		summary.DiskBytes += candidate.DiskBytes
		if candidate.Selected {
			summary.SelectedCount++
		}
	}
	return summary
}

func addSpec(specs *[]candidateSpec, seen map[string]bool, spec candidateSpec) {
	spec.path = filepath.Clean(spec.path)
	spec.root = filepath.Clean(spec.root)
	if seen[spec.path+"|"+string(spec.risk)+"|"+spec.reason] {
		return
	}
	seen[spec.path+"|"+string(spec.risk)+"|"+spec.reason] = true
	*specs = append(*specs, spec)
}

func addPermissionWarning(warnings *[]PlannerWarning, operation string, pathName string, err error) {
	if warnings == nil {
		return
	}
	warning := PlannerWarning{
		Code:      PlannerWarningPermissionDenied,
		Path:      filepath.Clean(pathName),
		Operation: operation,
		Message:   err.Error(),
	}
	for _, existing := range *warnings {
		if existing.Code == warning.Code && existing.Path == warning.Path && existing.Operation == warning.Operation {
			return
		}
	}
	*warnings = append(*warnings, warning)
}

func isPermissionError(err error) bool {
	return errors.Is(err, fs.ErrPermission) || errors.Is(err, os.ErrPermission)
}

func sortCandidates(candidates []Candidate) {
	sort.SliceStable(candidates, func(i, j int) bool {
		if candidates[i].CategoryID == candidates[j].CategoryID {
			return candidates[i].Identity.Path < candidates[j].Identity.Path
		}
		return candidates[i].CategoryID < candidates[j].CategoryID
	})
}

func expandHome(pathName string, homeDir string) string {
	if pathName == "~" {
		return homeDir
	}
	if strings.HasPrefix(pathName, "~/") {
		return filepath.Join(homeDir, strings.TrimPrefix(pathName, "~/"))
	}
	return pathName
}

func absoluteCleanPath(pathName string) (string, error) {
	if strings.TrimSpace(pathName) == "" {
		return "", errors.New("path is empty")
	}
	abs, err := filepath.Abs(pathName)
	if err != nil {
		return "", err
	}
	return filepath.Clean(abs), nil
}

func matchesAnyPattern(root, pathName, name string, patterns []string) bool {
	rel, err := filepath.Rel(root, pathName)
	if err != nil {
		rel = pathName
	}
	rel = filepath.ToSlash(rel)
	for _, patternText := range patterns {
		slashPattern := filepath.ToSlash(strings.TrimSpace(patternText))
		if slashPattern == "" {
			continue
		}
		if ok, _ := path.Match(slashPattern, rel); ok {
			return true
		}
		if ok, _ := path.Match(slashPattern, filepath.ToSlash(name)); ok {
			return true
		}
		if slashPattern == rel || slashPattern == filepath.ToSlash(name) {
			return true
		}
	}
	return false
}
