package browserfacade

import (
	"bytes"
	"encoding/csv"
	"encoding/json"
	"fmt"
	"io"
	"sort"
)

func RenderQuery(writer io.Writer, results []any, format string) error {
	var buffer bytes.Buffer
	if err := renderQuery(&buffer, results, format); err != nil {
		return err
	}
	return WriteOutbound(writer, buffer.String())
}

func renderQuery(writer io.Writer, results []any, format string) error {
	if format == "json" {
		var value any = results
		if len(results) == 1 {
			value = results[0]
		}
		encoder := json.NewEncoder(writer)
		encoder.SetEscapeHTML(false)
		return encoder.Encode(value)
	}
	if format != "compact" {
		return coded("FORMAT_INVALID", "format must be json or compact")
	}
	for index, result := range results {
		if index > 0 {
			fmt.Fprintln(writer)
		}
		list, ok := result.(ListResult)
		if !ok {
			data, err := json.Marshal(result)
			if err != nil {
				return err
			}
			fmt.Fprintln(writer, string(data))
			continue
		}
		fields := []string{}
		if len(list.Items) > 0 {
			for field := range list.Items[0] {
				fields = append(fields, field)
			}
			sort.Strings(fields)
		}
		csvWriter := csv.NewWriter(writer)
		if len(fields) > 0 {
			if err := csvWriter.Write(fields); err != nil {
				return err
			}
			for _, item := range list.Items {
				row := make([]string, len(fields))
				for i, field := range fields {
					row[i] = item[field]
				}
				if err := csvWriter.Write(row); err != nil {
					return err
				}
			}
		}
		csvWriter.Flush()
		if err := csvWriter.Error(); err != nil {
			return err
		}
		fmt.Fprintf(writer, "# returned=%d pages=%d scanned=%d hasMore=%s cache=%s\n", list.Returned, list.PagesRead, list.Scanned, list.HasMore, list.CacheFile)
	}
	return nil
}

func RenderMutations(writer io.Writer, results []MutationResult, format string) error {
	var buffer bytes.Buffer
	if err := renderMutations(&buffer, results, format); err != nil {
		return err
	}
	return WriteOutbound(writer, buffer.String())
}

func renderMutations(writer io.Writer, results []MutationResult, format string) error {
	if format == "json" {
		var value any = results
		if len(results) == 1 {
			value = results[0]
		}
		return json.NewEncoder(writer).Encode(value)
	}
	if format != "compact" {
		return coded("FORMAT_INVALID", "format must be json or compact")
	}
	for _, result := range results {
		fmt.Fprintf(writer, "mutation:%s ok:%t preview:%t applied:%t destructive:%t requiresConfirm:%t verification:%s\n", result.Mutation, result.OK, result.Preview, result.Applied, result.Destructive, result.RequiresConfirm, result.Verification)
	}
	return nil
}

func RenderGrep(writer io.Writer, matches []GrepMatch, format string) error {
	var buffer bytes.Buffer
	if err := renderGrep(&buffer, matches, format); err != nil {
		return err
	}
	return WriteOutbound(writer, buffer.String())
}

func renderGrep(writer io.Writer, matches []GrepMatch, format string) error {
	if format == "json" {
		return json.NewEncoder(writer).Encode(matches)
	}
	if format != "compact" {
		return coded("FORMAT_INVALID", "format must be json or compact")
	}
	current := ""
	for _, match := range matches {
		if match.File != current {
			if current != "" {
				fmt.Fprintln(writer)
			}
			current = match.File
			fmt.Fprintln(writer, current)
		}
		for index, line := range match.Before {
			fmt.Fprintf(writer, "  %d  %s\n", match.Line-len(match.Before)+index, line)
		}
		fmt.Fprintf(writer, "  %d: %s\n", match.Line, match.Text)
		for index, line := range match.After {
			fmt.Fprintf(writer, "  %d  %s\n", match.Line+index+1, line)
		}
	}
	return nil
}
