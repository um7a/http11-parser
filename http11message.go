package http11p

import (
	"errors"

	abnfp "github.com/um7a/abnf-parser"
)

// RFC9112 - 2.1. Message Format
//
//  HTTP-message   = start-line CRLF
//                   *( field-line CRLF )
//                   CRLF
//                   [ message-body ]
//

// RFC9112 - 2.1. Message Format
//
//  start-line     = request-line / status-line
//

// RFC9112 - 3. Request Line
//
//  request-line   = method SP request-target SP HTTP-version
//

// RFC9112 - 4. Status Line
//
//  status-line = HTTP-version SP status-code SP [ reason-phrase ]
//

type Http11Request struct {
	Method        []byte
	RequestTarget []byte
	HttpVersion   []byte
	FieldLines    []FieldLine
	MessageBody   []byte
}

type Http11Response struct {
	HttpVersion  []byte
	StatusCode   []byte
	ReasonPhrase []byte
	FieldLines   []FieldLine
	MessageBody  []byte
}

// RFC9112 - 5. Field Syntax
//
//  field-line   = field-name ":" OWS field-value OWS
//

type FieldLine struct {
	FieldName  []byte
	FieldValue []byte
}

func marshalRequestLine(data []byte, req *Http11Request) (remaining []byte, err error) {
	remaining = data

	result := abnfp.ParseLongest(remaining, FindMethod)
	if len(result.Parsed) == 0 {
		return data, errors.New("method not found")
	}
	req.Method = result.Parsed
	remaining = result.Remaining

	result = abnfp.ParseLongest(remaining, abnfp.FindSp)
	if len(result.Parsed) == 0 {
		return data, errors.New("SP after method not found")
	}
	remaining = result.Remaining

	result = abnfp.ParseLongest(remaining, FindRequestTarget)
	if len(result.Parsed) == 0 {
		return data, errors.New("request-target not found")
	}
	req.RequestTarget = result.Parsed
	remaining = result.Remaining

	result = abnfp.ParseLongest(remaining, abnfp.FindSp)
	if len(result.Parsed) == 0 {
		return data, errors.New("SP after request-target not found")
	}
	remaining = result.Remaining

	result = abnfp.ParseLongest(remaining, FindHttpVersion)
	if len(result.Parsed) == 0 {
		return data, errors.New("http-version not found")
	}
	req.HttpVersion = result.Parsed
	remaining = result.Remaining

	return
}

func marshalStatusLine(data []byte, resp *Http11Response) (remaining []byte, err error) {
	remaining = data

	result := abnfp.ParseLongest(remaining, FindHttpVersion)
	if len(result.Parsed) == 0 {
		return data, errors.New("http-version not found")
	}
	resp.HttpVersion = result.Parsed
	remaining = result.Remaining

	result = abnfp.ParseLongest(remaining, abnfp.FindSp)
	if len(result.Parsed) == 0 {
		return data, errors.New("SP after http-version not found")
	}
	remaining = result.Remaining

	result = abnfp.ParseLongest(remaining, FindStatusCode)
	if len(result.Parsed) == 0 {
		return data, errors.New("status-code not found")
	}
	resp.StatusCode = result.Parsed
	remaining = result.Remaining

	result = abnfp.ParseLongest(remaining, abnfp.FindSp)
	if len(result.Parsed) == 0 {
		return data, errors.New("SP after status-code not found")
	}
	remaining = result.Remaining

	result = abnfp.ParseLongest(remaining, FindReasonPhrase)
	if len(result.Parsed) == 0 {
		return data, errors.New("reason-phrase not found")
	}
	resp.ReasonPhrase = result.Parsed
	remaining = result.Remaining

	return
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

func (req *Http11Request) Marshal(data []byte) (err error) {
	var result abnfp.ParseResult
	remaining := data

	remaining, err = marshalRequestLine(remaining, req)
	if err != nil {
		return err
	}

	result = abnfp.ParseShortest(remaining, abnfp.FindCrLf)
	if len(result.Parsed) == 0 {
		return errors.New("CRLF after request-line not found")
	}
	remaining = result.Remaining

	req.FieldLines, remaining, err = marshalFieldLines(remaining)
	if err != nil {
		return err
	}

	result = abnfp.ParseShortest(remaining, abnfp.FindCrLf)
	if len(result.Parsed) == 0 {
		return errors.New("CRLF before message-body not found")
	}
	req.MessageBody = result.Remaining
	return nil
}

func (resp *Http11Response) Marshal(data []byte) (err error) {
	var result abnfp.ParseResult
	remaining := data

	remaining, err = marshalStatusLine(remaining, resp)
	if err != nil {
		return err
	}

	result = abnfp.ParseShortest(remaining, abnfp.FindCrLf)
	if len(result.Parsed) == 0 {
		return errors.New("CRLF after request-line not found")
	}
	remaining = result.Remaining

	resp.FieldLines, remaining, err = marshalFieldLines(remaining)
	if err != nil {
		return err
	}

	result = abnfp.ParseShortest(remaining, abnfp.FindCrLf)
	if len(result.Parsed) == 0 {
		return errors.New("CRLF before message-body not found")
	}
	resp.MessageBody = result.Remaining
	return nil
}

func (req Http11Request) Unmarshal() (data []byte) {
	sp := []byte(" ")
	crlf := []byte("\r\n")
	colon := []byte(":")

	data = append(data, req.Method...)
	data = append(data, sp...)
	data = append(data, req.RequestTarget...)
	data = append(data, sp...)
	data = append(data, req.HttpVersion...)
	data = append(data, crlf...)
	for _, fieldLine := range req.FieldLines {
		data = append(data, fieldLine.FieldName...)
		data = append(data, colon...)
		data = append(data, sp...)
		data = append(data, fieldLine.FieldValue...)
		data = append(data, crlf...)
	}
	data = append(data, crlf...)

	data = append(data, req.MessageBody...)
	return
}

func (resp Http11Response) Unmarshal() (data []byte) {
	sp := []byte(" ")
	crlf := []byte("\r\n")
	colon := []byte(":")

	data = append(data, resp.HttpVersion...)
	data = append(data, sp...)
	data = append(data, resp.StatusCode...)
	data = append(data, sp...)
	data = append(data, resp.ReasonPhrase...)
	data = append(data, crlf...)
	for _, fieldLine := range resp.FieldLines {
		data = append(data, fieldLine.FieldName...)
		data = append(data, colon...)
		data = append(data, sp...)
		data = append(data, fieldLine.FieldValue...)
		data = append(data, crlf...)
	}
	data = append(data, crlf...)

	data = append(data, resp.MessageBody...)
	return
}

func (req Http11Request) String() string {
	bytes := req.Unmarshal()
	return string(bytes)
}

func (resp Http11Response) String() string {
	bytes := resp.Unmarshal()
	return string(bytes)
}
