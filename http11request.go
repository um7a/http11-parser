package http11p

import (
	"errors"
	"fmt"

	abnfp "github.com/um7a/abnf-parser"
)

type Http11Request struct {
	Method        []byte
	RequestTarget []byte
	HttpVersion   []byte
	FieldLines    []FieldLine
	MessageBody   []byte
}

func marshalRequestLine(data []byte, req *Http11Request) (remaining []byte, err error) {
	remaining = data

	req.Method, remaining = abnfp.Parse(remaining, NewMethodFinder())
	if len(req.Method) == 0 {
		return data, errors.New("method not found")
	}

	sp, remaining := abnfp.Parse(remaining, abnfp.NewSpFinder())
	if len(sp) == 0 {
		return data, errors.New("SP after method not found")
	}

	req.RequestTarget, remaining = abnfp.Parse(remaining, NewRequestTargetFinder())
	if len(req.RequestTarget) == 0 {
		return data, errors.New("request-target not found")
	}

	sp, remaining = abnfp.Parse(remaining, abnfp.NewSpFinder())
	if len(sp) == 0 {
		return data, errors.New("SP after request-target not found")
	}

	req.HttpVersion, remaining = abnfp.Parse(remaining, NewHttpVersionFinder())
	if len(req.HttpVersion) == 0 {
		return data, errors.New("http-version not found")
	}

	return
}

func (req *Http11Request) Marshal(data []byte) (err error) {
	remaining := data

	remaining, err = marshalRequestLine(remaining, req)
	if err != nil {
		return err
	}

	crlf, remaining := abnfp.Parse(remaining, abnfp.NewCrLfFinder())
	if len(crlf) == 0 {
		return errors.New("CRLF after request-line not found")
	}

	req.FieldLines, remaining, err = marshalFieldLines(remaining)
	if err != nil {
		return err
	}
	fmt.Printf("%s\n", remaining)

	crlf, remaining = abnfp.Parse(remaining, abnfp.NewCrLfFinder())
	if len(crlf) == 0 {
		return errors.New("CRLF before message-body not found")
	}
	req.MessageBody = remaining
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

func (req Http11Request) String() string {
	bytes := req.Unmarshal()
	return string(bytes)
}

func (req Http11Request) GetHeader(name string) []byte {
	for _, fieldLine := range req.FieldLines {
		if string(fieldLine.FieldName) == name {
			return fieldLine.FieldValue
		}
	}
	return nil
}
