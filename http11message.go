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

	for {
		fieldLineEnds := FindFieldLine(remaining)
		if len(fieldLineEnds) == 0 {
			break
		}

		// field-name
		result := abnfp.ParseLongest(remaining, FindFieldName)
		if len(result.Parsed) == 0 {
			return fieldLines, data, errors.New("field-name not found")
		}
		fieldName := result.Parsed
		remaining = result.Remaining

		// ":"
		result = abnfp.ParseShortest(remaining, abnfp.NewFindByte(':'))
		if len(result.Parsed) == 0 {
			return fieldLines, data, errors.New("\":\" after field-name not found")
		}
		remaining = result.Remaining

		// OWS
		result = abnfp.ParseLongest(remaining, FindOws)
		remaining = result.Remaining

		// field-value
		result = abnfp.ParseLongest(remaining, FindFieldValue)
		if len(result.Parsed) == 0 {
			return fieldLines, data, errors.New("field-value not found")
		}
		fieldValue := result.Parsed
		remaining = result.Remaining

		// OWS
		result = abnfp.ParseLongest(remaining, FindOws)
		remaining = result.Remaining

		fieldLines = append(
			fieldLines,
			FieldLine{FieldName: fieldName, FieldValue: fieldValue},
		)

		// CRLF
		result = abnfp.ParseShortest(remaining, abnfp.FindCrLf)
		if len(result.Parsed) == 0 {
			return fieldLines, data, errors.New("CRLF after field-line not found")
		}
		remaining = result.Remaining
	}

	return
}
