package diskprofile

func defaultExplainNotes(errors []ScanError) []ExplainNote {
	notes := []ExplainNote{
		{
			Code:    "logical_vs_disk_bytes",
			Message: "Logical bytes are lstat apparent sizes; disk bytes are best-effort stat block sizes.",
		},
		{
			Code:    "apfs_clone_caveat",
			Message: "APFS clones and sparse files can share physical extents, so disk bytes may still overstate uniquely reclaimable space.",
		},
		{
			Code:    "apfs_hidden_space",
			Message: "APFS used space can include restricted paths, other users' homes, filesystem metadata, and other data outside this scan.",
		},
		{
			Code:    "apfs_purgeable_space",
			Message: "Purgeable space is managed by macOS and can include caches, swap, sleep images, and temporary files; v1 only reports this caveat.",
		},
		{
			Code:    "time_machine_snapshots",
			Message: "Local Time Machine snapshots can be counted as used or purgeable by macOS and may not appear in normal directory traversal.",
		},
	}

	if hasErrorKind(errors, ScanErrorPermissionDenied) {
		notes = append(notes, ExplainNote{
			Code:    "permission_denied",
			Message: "Some paths were unreadable and are recorded as unaccounted candidates.",
		})
	}
	if hasErrorKind(errors, ScanErrorExcluded) {
		notes = append(notes, ExplainNote{
			Code:    "excluded_paths",
			Message: "Excluded paths were skipped and do not contribute to scan totals.",
		})
	}
	if hasErrorKind(errors, ScanErrorOneFileSystem) {
		notes = append(notes, ExplainNote{
			Code:    "one_file_system",
			Message: "Paths on devices outside the root filesystem were skipped.",
		})
	}
	if hasErrorKind(errors, ScanErrorCanceled) {
		notes = append(notes, ExplainNote{
			Code:    "scan_canceled",
			Message: "The scan stopped early after context cancellation; totals may be partial.",
		})
	}
	if hasErrorKind(errors, ScanErrorRetentionLimit) {
		notes = append(notes, ExplainNote{
			Code:    "retention_limit",
			Message: "Some scanned entries were omitted from the retained JSON tree, but counted bytes and top lists still include scanned data.",
		})
	}
	return notes
}

func hasErrorKind(errors []ScanError, kind ScanErrorKind) bool {
	for _, err := range errors {
		if err.Kind == kind {
			return true
		}
	}
	return false
}
