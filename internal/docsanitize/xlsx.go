package docsanitize

import (
	"archive/zip"
	"encoding/xml"
	"fmt"
	"io"
	"path"
	"sort"
	"strconv"
	"strings"
)

type workbookXML struct {
	Sheets []workbookSheet `xml:"sheets>sheet"`
}

type workbookSheet struct {
	Name string `xml:"name,attr"`
	ID   string `xml:"id,attr"`
}

type relationshipsXML struct {
	Items []workbookRelationship `xml:"Relationship"`
}

type workbookRelationship struct {
	ID     string `xml:"Id,attr"`
	Target string `xml:"Target,attr"`
}

type sharedStringsXML struct {
	Items []richText `xml:"si"`
}

type richText struct {
	Text string    `xml:"t"`
	Runs []richRun `xml:"r"`
}

type richRun struct {
	Text string `xml:"t"`
}

func (r richText) value() string {
	var output strings.Builder
	output.WriteString(r.Text)
	for _, run := range r.Runs {
		output.WriteString(run.Text)
	}
	return output.String()
}

type worksheetRow struct {
	Cells []worksheetCell `xml:"c"`
}

type worksheetCell struct {
	Reference string   `xml:"r,attr"`
	Type      string   `xml:"t,attr"`
	Value     string   `xml:"v"`
	Formula   string   `xml:"f"`
	Inline    richText `xml:"is"`
}

type xlsxSheet struct {
	Name string
	Path string
}

func extractXLSX(pathName string, limit int64) (string, []string, error) {
	archive, err := zip.OpenReader(pathName)
	if err != nil {
		return "", nil, fmt.Errorf("open XLSX package: %w", err)
	}
	defer archive.Close()

	files := make(map[string]*zip.File, len(archive.File))
	for _, file := range archive.File {
		files[path.Clean(strings.TrimPrefix(file.Name, "/"))] = file
	}

	sharedStrings, err := readSharedStrings(files["xl/sharedStrings.xml"], limit)
	if err != nil {
		return "", nil, err
	}
	sheets, warnings, err := readWorkbookSheets(files, limit)
	if err != nil {
		return "", nil, err
	}
	if len(sheets) == 0 {
		return "", nil, fmt.Errorf("XLSX package contains no readable worksheets")
	}

	builder := &boundedStringBuilder{limit: limit}
	for index, sheet := range sheets {
		file := files[sheet.Path]
		if file == nil {
			warnings = append(warnings, fmt.Sprintf("worksheet %d is missing from the XLSX package", index+1))
			continue
		}
		if index > 0 {
			if err := builder.writeString("\n"); err != nil {
				return "", nil, err
			}
		}
		name := strings.NewReplacer("\r", " ", "\n", " ", "\t", " ").Replace(sheet.Name)
		if err := builder.writeString("# Sheet: " + name + "\n"); err != nil {
			return "", nil, err
		}
		if err := appendWorksheet(builder, file, sharedStrings); err != nil {
			return "", nil, fmt.Errorf("extract worksheet %d: %w", index+1, err)
		}
	}
	return builder.String(), warnings, nil
}

func readSharedStrings(file *zip.File, limit int64) ([]string, error) {
	if file == nil {
		return nil, nil
	}
	data, err := readZipEntry(file, limit)
	if err != nil {
		return nil, fmt.Errorf("read XLSX shared strings: %w", err)
	}
	var document sharedStringsXML
	if err := xml.Unmarshal(data, &document); err != nil {
		return nil, fmt.Errorf("parse XLSX shared strings: %w", err)
	}
	values := make([]string, 0, len(document.Items))
	for _, item := range document.Items {
		values = append(values, item.value())
	}
	return values, nil
}

func readWorkbookSheets(files map[string]*zip.File, limit int64) ([]xlsxSheet, []string, error) {
	workbookFile := files["xl/workbook.xml"]
	relationshipsFile := files["xl/_rels/workbook.xml.rels"]
	if workbookFile == nil || relationshipsFile == nil {
		return fallbackWorksheetList(files), []string{"workbook metadata was incomplete; fallback worksheet names were used"}, nil
	}
	workbookData, err := readZipEntry(workbookFile, limit)
	if err != nil {
		return nil, nil, fmt.Errorf("read XLSX workbook: %w", err)
	}
	relationshipData, err := readZipEntry(relationshipsFile, limit)
	if err != nil {
		return nil, nil, fmt.Errorf("read XLSX relationships: %w", err)
	}
	var workbook workbookXML
	if err := xml.Unmarshal(workbookData, &workbook); err != nil {
		return nil, nil, fmt.Errorf("parse XLSX workbook: %w", err)
	}
	var relationships relationshipsXML
	if err := xml.Unmarshal(relationshipData, &relationships); err != nil {
		return nil, nil, fmt.Errorf("parse XLSX relationships: %w", err)
	}
	targets := make(map[string]string, len(relationships.Items))
	for _, relationship := range relationships.Items {
		target := strings.TrimPrefix(relationship.Target, "/")
		if !strings.HasPrefix(target, "xl/") {
			target = path.Join("xl", target)
		}
		targets[relationship.ID] = path.Clean(target)
	}
	result := make([]xlsxSheet, 0, len(workbook.Sheets))
	warnings := make([]string, 0)
	for index, sheet := range workbook.Sheets {
		target := targets[sheet.ID]
		if target == "" {
			warnings = append(warnings, fmt.Sprintf("worksheet %d has no relationship target", index+1))
			continue
		}
		name := strings.TrimSpace(sheet.Name)
		if name == "" {
			name = fmt.Sprintf("Sheet %d", index+1)
		}
		result = append(result, xlsxSheet{Name: name, Path: target})
	}
	return result, warnings, nil
}

func fallbackWorksheetList(files map[string]*zip.File) []xlsxSheet {
	paths := make([]string, 0)
	for name := range files {
		if strings.HasPrefix(name, "xl/worksheets/") && strings.HasSuffix(name, ".xml") {
			paths = append(paths, name)
		}
	}
	sort.Strings(paths)
	result := make([]xlsxSheet, 0, len(paths))
	for index, name := range paths {
		result = append(result, xlsxSheet{Name: fmt.Sprintf("Sheet %d", index+1), Path: name})
	}
	return result
}

func appendWorksheet(builder *boundedStringBuilder, file *zip.File, sharedStrings []string) error {
	reader, err := file.Open()
	if err != nil {
		return err
	}
	defer reader.Close()
	decoder := xml.NewDecoder(reader)
	for {
		token, err := decoder.Token()
		if err == io.EOF {
			return nil
		}
		if err != nil {
			return err
		}
		start, ok := token.(xml.StartElement)
		if !ok || start.Name.Local != "row" {
			continue
		}
		var row worksheetRow
		if err := decoder.DecodeElement(&row, &start); err != nil {
			return err
		}
		values := make([]string, 0, len(row.Cells))
		for _, cell := range row.Cells {
			column := spreadsheetColumn(cell.Reference)
			if column < 0 {
				column = len(values)
			}
			for len(values) <= column {
				values = append(values, "")
			}
			values[column] = spreadsheetCellValue(cell, sharedStrings)
		}
		for index, value := range values {
			if index > 0 {
				if err := builder.writeString("\t"); err != nil {
					return err
				}
			}
			value = strings.NewReplacer("\r", " ", "\n", " ", "\t", " ").Replace(value)
			if err := builder.writeString(value); err != nil {
				return err
			}
		}
		if err := builder.writeString("\n"); err != nil {
			return err
		}
	}
}

func spreadsheetCellValue(cell worksheetCell, sharedStrings []string) string {
	value := cell.Value
	switch cell.Type {
	case "s":
		index, err := strconv.Atoi(strings.TrimSpace(value))
		if err == nil && index >= 0 && index < len(sharedStrings) {
			return sharedStrings[index]
		}
	case "inlineStr":
		return cell.Inline.value()
	case "b":
		if strings.TrimSpace(value) == "1" {
			return "true"
		}
		return "false"
	}
	if value == "" && cell.Formula != "" {
		return "=" + cell.Formula
	}
	return value
}

func spreadsheetColumn(reference string) int {
	column := 0
	found := false
	for _, character := range reference {
		if character >= 'A' && character <= 'Z' {
			column = column*26 + int(character-'A'+1)
			found = true
			continue
		}
		if character >= 'a' && character <= 'z' {
			column = column*26 + int(character-'a'+1)
			found = true
			continue
		}
		break
	}
	if !found {
		return -1
	}
	return column - 1
}

func readZipEntry(file *zip.File, limit int64) ([]byte, error) {
	if int64(file.UncompressedSize64) > limit {
		return nil, fmt.Errorf("uncompressed entry exceeds %d bytes", limit)
	}
	reader, err := file.Open()
	if err != nil {
		return nil, err
	}
	defer reader.Close()
	data, err := io.ReadAll(io.LimitReader(reader, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("uncompressed entry exceeds %d bytes", limit)
	}
	return data, nil
}

type boundedStringBuilder struct {
	builder strings.Builder
	limit   int64
}

func (b *boundedStringBuilder) writeString(value string) error {
	if int64(b.builder.Len()+len(value)) > b.limit {
		return fmt.Errorf("extracted text exceeds %d bytes", b.limit)
	}
	b.builder.WriteString(value)
	return nil
}

func (b *boundedStringBuilder) String() string {
	return b.builder.String()
}
