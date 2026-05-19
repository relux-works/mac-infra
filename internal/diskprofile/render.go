package diskprofile

import (
	"fmt"
	"io"
	"path/filepath"
	"text/tabwriter"
)

func RenderScanText(w io.Writer, result ScanResult) {
	RenderSummaryText(w, result)
	RenderTopText(w, result, true, true)
}

func RenderTopText(w io.Writer, result ScanResult, includeDirs, includeFiles bool) {
	if includeDirs {
		RenderEntryTable(w, "top directories", result.TopDirs)
	}
	if includeFiles {
		RenderEntryTable(w, "top files", result.TopFiles)
	}
}

func RenderExplainText(w io.Writer, result ScanResult) {
	RenderScanText(w, result)

	fmt.Fprintln(w, "\n== explain ==")
	for _, note := range result.Explain {
		fmt.Fprintf(w, "- %s: %s\n", note.Code, note.Message)
	}
	if len(result.Errors) == 0 {
		return
	}

	fmt.Fprintln(w, "\n== unreadable/skipped paths ==")
	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "KIND\tOP\tPATH\tDETAIL")
	for _, scanErr := range result.Errors {
		fmt.Fprintf(tw, "%s\t%s\t%s\t%s\n", scanErr.Kind, scanErr.Op, filepath.Clean(scanErr.Path), scanErrorDetail(scanErr))
	}
	_ = tw.Flush()
}

func RenderSummaryText(w io.Writer, result ScanResult) {
	fmt.Fprintf(w, "root: %s\n", result.Root)
	fmt.Fprintf(w, "logical: %s\n", FormatBytes(result.LogicalBytes))
	fmt.Fprintf(w, "disk: %s\n", FormatBytes(result.DiskBytes))
	fmt.Fprintf(w, "visited/retained/omitted: %d/%d/%d\n", result.VisitedEntries, result.RetainedEntries, result.OmittedEntries)
	fmt.Fprintf(w, "errors/skips: %d\n", len(result.Errors))
}

func RenderEntryTable(w io.Writer, title string, entries []Entry) {
	fmt.Fprintf(w, "\n== %s ==\n", title)
	if len(entries) == 0 {
		fmt.Fprintln(w, "(none)")
		return
	}

	tw := tabwriter.NewWriter(w, 0, 0, 2, ' ', 0)
	fmt.Fprintln(tw, "LOGICAL\tDISK\tPATH")
	for _, entry := range entries {
		fmt.Fprintf(tw, "%s\t%s\t%s\n", FormatBytes(entry.SubtreeLogicalBytes), FormatBytes(entry.SubtreeDiskBytes), entry.Path)
	}
	_ = tw.Flush()
}

func FormatBytes(bytes int64) string {
	const unit = 1024
	if bytes < unit {
		return fmt.Sprintf("%dB", bytes)
	}
	value := float64(bytes)
	for _, suffix := range []string{"KB", "MB", "GB", "TB"} {
		value /= unit
		if value < unit {
			return fmt.Sprintf("%.1f%s", value, suffix)
		}
	}
	return fmt.Sprintf("%.1fPB", value/unit)
}

func scanErrorDetail(scanErr ScanError) string {
	detail := scanErr.Err
	if scanErr.Pattern != "" {
		detail += " pattern=" + scanErr.Pattern
	}
	if scanErr.Depth > 0 {
		detail += fmt.Sprintf(" depth=%d", scanErr.Depth)
	}
	return detail
}
