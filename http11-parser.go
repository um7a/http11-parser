package http11p

import (
	abnfp "github.com/um7a/abnf-parser"
	urip "github.com/um7a/uri-parser"
)

// RFC9110 - 4.1. URI References
//
//  uri-host      = <host, see [URI], Section 3.2.2>
//

func FindUriHost(data []byte) []int {
	return urip.FindHost(data)
}

// RFC9110 - 4.1. URI References
//
//  absolute-path = 1*( "/" segment )
//

func FindAbsolutePath(data []byte) []int {
	findAbsolutePath := abnfp.NewFindVariableRepetitionMin(
		1,
		abnfp.NewFindConcatenation([]abnfp.FindFunc{
			abnfp.NewFindByte('/'),
			urip.FindSegment,
		}),
	)
	return findAbsolutePath(data)
}

// RFC9110 - 5.1. Field Names
//
//  field-name     = token
//

func FindFieldName(data []byte) []int {
	return FindToken(data)
}

// RFC9110 - 5.5. Field Values
//
//  field-value    = *field-content
//

func FindFieldValue(data []byte) []int {
	return abnfp.NewFindVariableRepetition(FindFieldContent)(data)
}

// RFC9110 - 5.5. Field Values
//
//  field-content  = field-vchar
//  								 [ 1*( SP / HTAB / field-vchar ) field-vchar ]
//

func FindFieldContent(data []byte) []int {
	findFieldContent := abnfp.NewFindConcatenation([]abnfp.FindFunc{
		FindFieldVChar,
		abnfp.NewFindOptionalSequence(
			abnfp.NewFindConcatenation([]abnfp.FindFunc{
				abnfp.NewFindVariableRepetitionMin(1,
					abnfp.NewFindAlternatives([]abnfp.FindFunc{
						abnfp.FindSp,
						abnfp.FindHTab,
						FindFieldVChar,
					}),
				),
				FindFieldVChar,
			}),
		),
	})
	return findFieldContent(data)
}

// RFC9110 - 5.5. Field Values
//
//  field-vchar    = VCHAR / obs-text
//

func FindFieldVChar(data []byte) []int {
	findFieldVChar := abnfp.NewFindAlternatives([]abnfp.FindFunc{
		abnfp.FindVChar,
		FindObsText,
	})
	return findFieldVChar(data)
}

// RFC9110 - 5.5. Field Values
//
//  obs-text       = %x80-FF
//

func FindObsText(data []byte) []int {
	return abnfp.NewFindValueRangeAlternatives(0x80, 0xff)(data)
}

// RFC9110 - 5.6.2. Tokens
//
// token          = 1*tchar
//

func FindToken(data []byte) []int {
	return abnfp.NewFindVariableRepetitionMin(1, FindTChar)(data)
}

// RFC9110 - 5.6.2. Tokens
//
//  tchar          = "!" / "#" / "$" / "%" / "&" / "'" / "*"
//                 / "+" / "-" / "." / "^" / "_" / "`" / "|" / "~"
//                 / DIGIT / ALPHA
//                 ; any VCHAR, except delimiters
//

func FindTChar(data []byte) []int {
	findTChar := abnfp.NewFindAlternatives([]abnfp.FindFunc{
		abnfp.NewFindBytes([]byte("!")),
		abnfp.NewFindBytes([]byte("#")),
		abnfp.NewFindBytes([]byte("$")),
		abnfp.NewFindBytes([]byte("%")),
		abnfp.NewFindBytes([]byte("&")),
		abnfp.NewFindBytes([]byte("'")),
		abnfp.NewFindBytes([]byte("*")),
		abnfp.NewFindBytes([]byte("+")),
		abnfp.NewFindBytes([]byte("-")),
		abnfp.NewFindBytes([]byte(".")),
		abnfp.NewFindBytes([]byte("^")),
		abnfp.NewFindBytes([]byte("_")),
		abnfp.NewFindBytes([]byte("`")),
		abnfp.NewFindBytes([]byte("|")),
		abnfp.NewFindBytes([]byte("~")),
		abnfp.FindDigit,
		abnfp.FindAlpha,
	})
	return findTChar(data)
}

// RFC9110 - 5.6.3. Whitespace
//
//  OWS            = *( SP / HTAB )
//  ; optional whitespace
//

func FindOws(data []byte) []int {
	findOws := abnfp.NewFindVariableRepetition(
		abnfp.NewFindAlternatives([]abnfp.FindFunc{
			abnfp.FindSp,
			abnfp.FindHTab,
		}),
	)
	return findOws(data)
}

// RFC9110 - 5.6.3. Whitespace
//
//  RWS            = 1*( SP / HTAB )
//  ; required whitespace
//

func FindRws(data []byte) []int {
	findOws := abnfp.NewFindVariableRepetitionMin(
		1,
		abnfp.NewFindAlternatives([]abnfp.FindFunc{
			abnfp.FindSp,
			abnfp.FindHTab,
		}),
	)
	return findOws(data)
}

// RFC9110 - 5.6.3. Whitespace
//
//  BWS            = OWS
//  ; "bad" whitespace
//

func FindBws(data []byte) []int {
	return FindOws(data)
}

// RFC9110 - 5.6.4. Quoted Strings
//
//  quoted-string  = DQUOTE *( qdtext / quoted-pair ) DQUOTE
//

func FindQuotedString(data []byte) []int {
	findQuotedString := abnfp.NewFindConcatenation([]abnfp.FindFunc{
		abnfp.FindDQuote,
		abnfp.NewFindVariableRepetition(
			abnfp.NewFindAlternatives([]abnfp.FindFunc{
				FindQdText,
				FindQuotedPair,
			}),
		),
		abnfp.FindDQuote,
	})
	return findQuotedString(data)
}

// RFC9110 - 5.6.4. Quoted Strings
//
//  qdtext         = HTAB / SP / %x21 / %x23-5B / %x5D-7E / obs-text
//

// NOTE
// x21    : !
// x23-5B : #, $, %, & ' ( ) * + , - . / 0-9, : ; < = > ? @ A-Z [
// x5D-7E : ] ^ _ ` a-z { | } ~
func FindQdText(data []byte) []int {
	findQdText := abnfp.NewFindAlternatives([]abnfp.FindFunc{
		abnfp.FindHTab,
		abnfp.FindSp,
		abnfp.NewFindByte(0x21),
		abnfp.NewFindValueRangeAlternatives(0x23, 0x5b),
		abnfp.NewFindValueRangeAlternatives(0x5d, 0x7e),
		FindObsText,
	})
	return findQdText(data)
}

// RFC9110 - 5.6.4. Quoted Strings
//
//  quoted-pair    = "\" ( HTAB / SP / VCHAR / obs-text )
//

func FindQuotedPair(data []byte) []int {
	findQuotedPair := abnfp.NewFindConcatenation([]abnfp.FindFunc{
		abnfp.NewFindByte('\\'),
		abnfp.NewFindAlternatives([]abnfp.FindFunc{
			abnfp.FindHTab,
			abnfp.FindSp,
			abnfp.FindVChar,
			FindObsText,
		}),
	})
	return findQuotedPair(data)
}

// RFC9112 - 2.1. Message Format
//
//  HTTP-message   = start-line CRLF
//                   *( field-line CRLF )
//                   CRLF
//                   [ message-body ]
//

func FindHttpMessage(data []byte) []int {
	findHttpMessage := abnfp.NewFindConcatenation([]abnfp.FindFunc{
		FindStartLine,
		abnfp.FindCrLf,
		abnfp.NewFindVariableRepetition(
			abnfp.NewFindConcatenation([]abnfp.FindFunc{
				FindFieldLine,
				abnfp.FindCrLf,
			}),
		),
		abnfp.FindCrLf,
		abnfp.NewFindOptionalSequence(FindMessageBody),
	})
	return findHttpMessage(data)
}

// RFC9112 - 2.1. Message Format
//
//  start-line     = request-line / status-line
//

func FindStartLine(data []byte) []int {
	findStartLine := abnfp.NewFindAlternatives([]abnfp.FindFunc{
		FindRequestLine,
		FindStatusLine,
	})
	return findStartLine(data)
}

// RFC9112 - 2.3. HTTP Version
//
//  HTTP-version  = HTTP-name "/" DIGIT "." DIGIT
//

func FindHttpVersion(data []byte) []int {
	findHttpVersion := abnfp.NewFindConcatenation([]abnfp.FindFunc{
		FindHttpName,
		abnfp.NewFindBytes([]byte("/")),
		abnfp.FindDigit,
		abnfp.NewFindBytes([]byte(".")),
		abnfp.FindDigit,
	})
	return findHttpVersion(data)
}

// RFC9112 - 2.3. HTTP Version
//
//  HTTP-name     = %s"HTTP"
//

func FindHttpName(data []byte) []int {
	return abnfp.NewFindBytes([]byte("HTTP"))(data)
}

// RFC9112 - 3. Request Line
//
//  request-line   = method SP request-target SP HTTP-version
//

func FindRequestLine(data []byte) []int {
	findRequestLine := abnfp.NewFindConcatenation([]abnfp.FindFunc{
		FindMethod,
		abnfp.FindSp,
		FindRequestTarget,
		abnfp.FindSp,
		FindHttpVersion,
	})
	return findRequestLine(data)
}

// RFC9112 - 3.1. Method
//
//  method         = token
//

func FindMethod(data []byte) []int {
	return FindToken(data)
}

// RFC9112 - 3.2. Request Target
//
//  request-target = origin-form
//                 / absolute-form
//                 / authority-form
//                 / asterisk-form
//

func FindRequestTarget(data []byte) []int {
	findRequestTarget := abnfp.NewFindAlternatives([]abnfp.FindFunc{
		FindOriginForm,
		FindAbsoluteForm,
		FindAuthorityForm,
		FindAsteriskForm,
	})
	return findRequestTarget(data)
}

// RFC9112 - 3.2.1. origin-form
//
//  origin-form    = absolute-path [ "?" query ]
//

func FindOriginForm(data []byte) []int {
	findOriginForm := abnfp.NewFindConcatenation([]abnfp.FindFunc{
		FindAbsolutePath,
		abnfp.NewFindOptionalSequence(
			abnfp.NewFindConcatenation([]abnfp.FindFunc{
				abnfp.NewFindBytes([]byte("?")),
				urip.FindQuery,
			}),
		),
	})
	return findOriginForm(data)
}

// RFC9112 - 3.2.2. absolute-form
//
//  absolute-form  = absolute-URI
//

func FindAbsoluteForm(data []byte) []int {
	return urip.FindAbsoluteUri(data)
}

// RFC9112 - 3.2.3. authority-form
//
//  authority-form = uri-host ":" port
//

func FindAuthorityForm(data []byte) []int {
	findAuthorityForm := abnfp.NewFindConcatenation([]abnfp.FindFunc{
		FindUriHost,
		abnfp.NewFindByte(':'),
		urip.FindPort,
	})
	return findAuthorityForm(data)
}

// RFC9112 - 3.2.4. asterisk-form
//
//  asterisk-form  = "*"
//

func FindAsteriskForm(data []byte) []int {
	return abnfp.NewFindByte('*')(data)
}

// RFC9112 - 4. Status Line
//
//  status-line = HTTP-version SP status-code SP [ reason-phrase ]
//

func FindStatusLine(data []byte) []int {
	findStatusLine := abnfp.NewFindConcatenation([]abnfp.FindFunc{
		FindHttpVersion,
		abnfp.FindSp,
		FindStatusCode,
		abnfp.FindSp,
		abnfp.NewFindOptionalSequence(FindReasonPhrase),
	})
	return findStatusLine(data)
}

// RFC9112 - 4. Status Line
//
//  status-code    = 3DIGIT
//

func FindStatusCode(data []byte) []int {
	return abnfp.NewFindSpecificRepetition(3, abnfp.FindDigit)(data)
}

// RFC9112 - 4. Status Line
//
//  reason-phrase  = 1*( HTAB / SP / VCHAR / obs-text )
//

func FindReasonPhrase(data []byte) []int {
	findReasonPhrase := abnfp.NewFindVariableRepetitionMin(
		1,
		abnfp.NewFindAlternatives([]abnfp.FindFunc{
			abnfp.FindHTab,
			abnfp.FindSp,
			abnfp.FindVChar,
			FindObsText,
		}),
	)
	return findReasonPhrase(data)
}

// RFC9112 - 5. Field Syntax
//
//  field-line   = field-name ":" OWS field-value OWS
//

func FindFieldLine(data []byte) []int {
	findFieldLine := abnfp.NewFindConcatenation([]abnfp.FindFunc{
		FindFieldName,
		abnfp.NewFindByte(':'),
		FindOws,
		FindFieldValue,
		FindOws,
	})
	return findFieldLine(data)
}

// RFC9112 - 6. Message Body
//
//  message-body = *OCTET
//

func FindMessageBody(data []byte) []int {
	return abnfp.NewFindVariableRepetition(abnfp.FindOctet)(data)
}
