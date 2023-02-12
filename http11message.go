package http11p

import (
	"errors"

	abnfp "github.com/um7a/abnf-parser"
)

// RFC9112 - 5. Field Syntax
//
//  field-line   = field-name ":" OWS field-value OWS
//

type FieldLine struct {
	FieldName  []byte
	FieldValue []byte
}

func marshalFieldLines(data []byte) (fieldLines []FieldLine, remaining []byte, err error) {
	fieldLines = []FieldLine{}
	remaining = data
	var fieldName []byte
	var fieldValue []byte
	var colon []byte
	var crlf []byte

	for {
		found, _ := NewFieldLineFinder().Find(remaining)
		if !found {
			break
		}

		// field-name
		fieldName, remaining = abnfp.Parse(remaining, NewFieldNameFinder())
		if len(fieldName) == 0 {
			return fieldLines, data, errors.New("field-name not found")
		}

		// ":"
		colon, remaining = abnfp.Parse(remaining, abnfp.NewByteFinder(':'))
		if len(colon) == 0 {
			return fieldLines, data, errors.New("\":\" after field-name not found")
		}

		// OWS
		_, remaining = abnfp.Parse(remaining, NewOwsFinder())

		// field-value
		fieldValue, remaining = abnfp.Parse(remaining, NewFieldValueFinder())
		if len(fieldValue) == 0 {
			return fieldLines, data, errors.New("field-value not found")
		}

		// OWS
		_, remaining = abnfp.Parse(remaining, NewOwsFinder())

		fieldLines = append(
			fieldLines,
			FieldLine{FieldName: fieldName, FieldValue: fieldValue},
		)

		// CRLF
		crlf, remaining = abnfp.Parse(remaining, abnfp.NewCrLfFinder())
		if len(crlf) == 0 {
			return fieldLines, data, errors.New("CRLF after field-line not found")
		}
	}

	return
}
