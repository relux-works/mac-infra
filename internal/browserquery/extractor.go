package browserquery

import (
	"encoding/json"
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
)

const (
	defaultMaxFieldChars = 2000
	maximumFieldChars    = 4000
	maximumTake          = 100
)

var fieldNamePattern = regexp.MustCompile(`^[a-z][a-zA-Z0-9_]{0,47}$`)

type Template struct {
	ItemSelector      string           `json:"itemSelector"`
	PierceShadowRoots bool             `json:"pierceShadowRoots,omitempty"`
	MaxFieldChars     int              `json:"maxFieldChars,omitempty"`
	Fields            map[string]Field `json:"fields"`
}

type Field struct {
	Selector  string `json:"selector,omitempty"`
	Source    string `json:"source"`
	Attribute string `json:"attribute,omitempty"`
}

type Predicate struct {
	Field string `json:"field"`
	Op    string `json:"op"`
	Value string `json:"value"`
}

type Query struct {
	Fields    []string   `json:"fields,omitempty"`
	Predicate *Predicate `json:"predicate,omitempty"`
	Skip      int        `json:"skip"`
	Take      int        `json:"take"`
}

func DecodeTemplate(data []byte) (Template, error) {
	var template Template
	decoder := json.NewDecoder(strings.NewReader(string(data)))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(&template); err != nil {
		return Template{}, fmt.Errorf("decode extraction template: %w", err)
	}
	if err := template.Validate(); err != nil {
		return Template{}, err
	}
	return template, nil
}

func (t Template) Validate() error {
	if strings.TrimSpace(t.ItemSelector) == "" || len(t.ItemSelector) > 512 {
		return errors.New("itemSelector must contain 1..512 characters")
	}
	if len(t.Fields) == 0 || len(t.Fields) > 32 {
		return errors.New("template must define 1..32 fields")
	}
	if t.MaxFieldChars < 0 || t.MaxFieldChars > maximumFieldChars {
		return fmt.Errorf("maxFieldChars must be between 1 and %d when set", maximumFieldChars)
	}
	for name, field := range t.Fields {
		if !fieldNamePattern.MatchString(name) {
			return fmt.Errorf("invalid field name %q", name)
		}
		if len(field.Selector) > 512 {
			return fmt.Errorf("field %q selector exceeds 512 characters", name)
		}
		switch field.Source {
		case "tag":
			if field.Attribute != "" {
				return fmt.Errorf("tag field %q must not define attribute", name)
			}
		case "text":
			if field.Attribute != "" {
				return fmt.Errorf("text field %q must not define attribute", name)
			}
		case "attribute":
			if !safeAttribute(field.Attribute) {
				return fmt.Errorf("field %q uses forbidden attribute %q", name, field.Attribute)
			}
		default:
			return fmt.Errorf("field %q source must be tag, text, or attribute", name)
		}
	}
	return nil
}

func (q Query) Validate(template Template) error {
	if q.Skip < 0 || q.Skip > 10000 {
		return errors.New("skip must be between 0 and 10000")
	}
	if q.Take < 1 || q.Take > maximumTake {
		return fmt.Errorf("take must be between 1 and %d", maximumTake)
	}
	for _, name := range q.Fields {
		if _, ok := template.Fields[name]; !ok {
			return fmt.Errorf("unknown projected field %q", name)
		}
	}
	if q.Predicate != nil {
		if _, ok := template.Fields[q.Predicate.Field]; !ok {
			return fmt.Errorf("unknown predicate field %q", q.Predicate.Field)
		}
		switch q.Predicate.Op {
		case "equals", "contains", "prefix":
		default:
			return fmt.Errorf("unsupported predicate operation %q", q.Predicate.Op)
		}
		if len(q.Predicate.Value) > 512 {
			return errors.New("predicate value exceeds 512 characters")
		}
	}
	return nil
}

func BuildJavaScript(template Template, query Query) (string, error) {
	if err := template.Validate(); err != nil {
		return "", err
	}
	if len(query.Fields) == 0 {
		query.Fields = make([]string, 0, len(template.Fields))
		for name := range template.Fields {
			query.Fields = append(query.Fields, name)
		}
		sort.Strings(query.Fields)
	}
	if err := query.Validate(template); err != nil {
		return "", err
	}
	if template.MaxFieldChars == 0 {
		template.MaxFieldChars = defaultMaxFieldChars
	}
	payload, err := json.Marshal(struct {
		Template Template `json:"template"`
		Query    Query    `json:"query"`
	}{Template: template, Query: query})
	if err != nil {
		return "", err
	}
	return `(() => {
  const spec = ` + string(payload) + `;
  const clean = value => String(value == null ? "" : value).replace(/\s+/g, " ").trim().slice(0, spec.template.maxFieldChars);
  const read = (item, field) => {
    const node = field.selector ? item.querySelector(field.selector) : item;
    if (!node) return "";
	    if (field.source === "tag") return clean(node.tagName.toLowerCase());
	    if (field.source === "attribute") return clean(node.getAttribute(field.attribute));
    return clean(node.innerText);
  };
	  const roots = [document];
	  if (spec.template.pierceShadowRoots) {
	    for (let i = 0; i < roots.length && roots.length < 64; i++) {
	      const elements = roots[i].querySelectorAll("*");
	      for (let j = 0; j < elements.length && j < 10000 && roots.length < 64; j++) {
	        if (elements[j].shadowRoot) roots.push(elements[j].shadowRoot);
	      }
	    }
	  }
	  const matches = roots.flatMap(root => Array.from(root.querySelectorAll(spec.template.itemSelector)));
	  const extracted = matches.map(item => {
    const out = {};
    for (const name of spec.query.fields) out[name] = read(item, spec.template.fields[name]);
    if (spec.query.predicate && !(spec.query.predicate.field in out)) {
      const name = spec.query.predicate.field;
      out[name] = read(item, spec.template.fields[name]);
    }
    return out;
  });
  const predicate = spec.query.predicate;
  const filtered = predicate ? extracted.filter(item => {
    const actual = String(item[predicate.field] || "");
    if (predicate.op === "equals") return actual === predicate.value;
    if (predicate.op === "prefix") return actual.startsWith(predicate.value);
    return actual.includes(predicate.value);
  }) : extracted;
  const items = filtered.slice(spec.query.skip, spec.query.skip + spec.query.take);
  return JSON.stringify({matched:filtered.length,skip:spec.query.skip,take:spec.query.take,returned:items.length,items});
})()`, nil
}

func safeAttribute(name string) bool {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "aria-label", "class", "datetime", "role", "title":
		return true
	default:
		return false
	}
}
