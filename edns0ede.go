package rdns

import (
	"bytes"
	"text/template"

	"github.com/miekg/dns"
)

type EDNS0EDETemplate struct {
	infoCode     uint16
	extraText    string
	textTemplate *template.Template
}

func NewEDNS0EDETemplate(infoCode uint16, extraText string) (*EDNS0EDETemplate, error) {
	if infoCode == 0 && extraText == "" {
		return nil, nil
	}

	textTemplate := template.New("EDNS0EDE")
	textTemplate, err := textTemplate.Parse(extraText)
	if err != nil {
		return nil, err
	}

	return &EDNS0EDETemplate{
		infoCode:     infoCode,
		extraText:    extraText,
		textTemplate: textTemplate,
	}, nil
}

// Data that is passed to any templates.
type templateInput struct {
	ID       uint16
	Question string
}

// Apply executes the template for the EDNS0-EDE record text, e.g. replacing
// placeholders in the Text with Query names, then adding the EDE record to
// the given msg.
func (t *EDNS0EDETemplate) Apply(msg, q *dns.Msg) error {
	if t == nil {
		return nil
	}
	var question string
	if len(q.Question) > 0 {
		question = q.Question[0].Name
	}
	input := templateInput{
		ID:       q.Id,
		Question: question,
	}
	text := new(bytes.Buffer)
	if err := t.textTemplate.Execute(text, input); err != nil {
		return err
	}

	ede := &dns.EDNS0_EDE{
		InfoCode:  t.infoCode,
		ExtraText: text.String(),
	}
	msg.SetEdns0(4096, false)
	opt := msg.IsEdns0()
	opt.Option = append(opt.Option, ede)
	return nil
}
