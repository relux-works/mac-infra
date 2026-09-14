package main

import (
	"fmt"

	"github.com/relux-works/mac-infra/internal/keyvault"
)

type store struct {
	items   []keyvault.Item
	creates int
}

func (s *store) Create(opts keyvault.CreateOptions) (keyvault.Item, error) {
	s.creates++
	item := keyvault.Item{Label: opts.Label, Tag: opts.Tag}
	s.items = append(s.items, item)
	return item, nil
}
func (s *store) List() ([]keyvault.Item, error) { return append([]keyvault.Item(nil), s.items...), nil }
func (s *store) Delete(string) error            { return nil }
func (s *store) UpdateTag(string, []byte) error { return nil }

func main() {
	rec := keyvault.Record{
		Schema: 2, Kind: keyvault.KindKey, Service: keyvault.TestService,
		Purpose: "trailing-tag", Version: 1, Algorithm: keyvault.AlgorithmECP256,
		Store: keyvault.StoreKeychain, Extraction: keyvault.ExtractionNone,
		Usages: []string{"sign"},
		Format: keyvault.Format{Public: keyvault.FormatPublicSPKIDER, Signature: keyvault.FormatSignatureDERLowS},
		Meta: map[string]any{},
	}
	tag, err := keyvault.EncodeRecord(rec)
	if err != nil { panic(err) }
	tag = append(tag, []byte(` {"forged":true}`)...)
	decoded, problem := keyvault.DecodeRecord(tag)
	s := &store{items: []keyvault.Item{{Label: rec.Label(), Tag: tag}}}
	m := keyvault.NewManager(s, keyvault.NoLock{}, keyvault.Origin{Tool: "reviewer"})
	rotated, rotateErr := m.Rotate(keyvault.Address{Kind: rec.Kind, Service: rec.Service, Purpose: rec.Purpose})
	fmt.Printf("decode_problem=%q decoded_schema=%d rotate_error=%v creates=%d new_label=%q\n", problem, decoded.Schema, rotateErr, s.creates, rotated.New.Label)
}
