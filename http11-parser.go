package http11p

import (
	abnfp "github.com/um7a/abnf-parser"
	urip "github.com/um7a/uri-parser"
)

// RFC9110 - 4.1. URI References
//
//  uri-host      = <host, see [URI], Section 3.2.2>
//

func NewUriHostFinder() abnfp.Finder {
	return urip.NewHostFinder()
}

// RFC9110 - 4.1. URI References
//
//  absolute-path = 1*( "/" segment )
//

func NewAbsolutePathFinder() abnfp.Finder {
	return abnfp.NewVariableRepetitionMinFinder(
		1,
		abnfp.NewConcatenationFinder([]abnfp.Finder{
			abnfp.NewByteFinder('/'),
			urip.NewSegmentFinder(),
		}),
	)
}

// RFC9110 - 5.1. Field Names
//
//  field-name     = token
//

func NewFieldNameFinder() abnfp.Finder {
	return NewTokenFinder()
}

// RFC9110 - 5.5. Field Values
//
//  field-value    = *field-content
//

func NewFieldValueFinder() abnfp.Finder {
	return abnfp.NewVariableRepetitionFinder(NewFieldContentFinder())
}

// RFC9110 - 5.5. Field Values
//
//  field-content  = field-vchar
//  								 [ 1*( SP / HTAB / field-vchar ) field-vchar ]
//

func NewFieldContentFinder() abnfp.Finder {
	return abnfp.NewConcatenationFinder([]abnfp.Finder{
		NewFieldVCharFinder(),
		abnfp.NewOptionalSequenceFinder(
			abnfp.NewConcatenationFinder([]abnfp.Finder{
				abnfp.NewVariableRepetitionMinFinder(1,
					abnfp.NewAlternativesFinder([]abnfp.Finder{
						abnfp.NewSpFinder(),
						abnfp.NewHTabFinder(),
						NewFieldVCharFinder(),
					}),
				),
				NewFieldVCharFinder(),
			}),
		),
	})
}

// RFC9110 - 5.5. Field Values
//
//  field-vchar    = VCHAR / obs-text
//

func NewFieldVCharFinder() abnfp.Finder {
	return abnfp.NewAlternativesFinder([]abnfp.Finder{
		abnfp.NewVCharFinder(),
		NewObsTextFinder(),
	})
}

// RFC9110 - 5.5. Field Values
//
//  obs-text       = %x80-FF
//

func NewObsTextFinder() abnfp.Finder {
	return abnfp.NewValueRangeAlternativesFinder(0x80, 0xff)
}

// RFC9110 - 5.6.2. Tokens
//
// token          = 1*tchar
//

func NewTokenFinder() abnfp.Finder {
	return abnfp.NewVariableRepetitionMinFinder(1, NewTCharFinder())
}

// RFC9110 - 5.6.2. Tokens
//
//  tchar          = "!" / "#" / "$" / "%" / "&" / "'" / "*"
//                 / "+" / "-" / "." / "^" / "_" / "`" / "|" / "~"
//                 / DIGIT / ALPHA
//                 ; any VCHAR, except delimiters
//

func NewTCharFinder() abnfp.Finder {
	return abnfp.NewAlternativesFinder([]abnfp.Finder{
		abnfp.NewByteFinder('!'),
		abnfp.NewByteFinder('#'),
		abnfp.NewByteFinder('$'),
		abnfp.NewByteFinder('%'),
		abnfp.NewByteFinder('&'),
		abnfp.NewByteFinder('\''),
		abnfp.NewByteFinder('*'),
		abnfp.NewByteFinder('+'),
		abnfp.NewByteFinder('-'),
		abnfp.NewByteFinder('.'),
		abnfp.NewByteFinder('^'),
		abnfp.NewByteFinder('_'),
		abnfp.NewByteFinder('`'),
		abnfp.NewByteFinder('|'),
		abnfp.NewByteFinder('~'),
		abnfp.NewDigitFinder(),
		abnfp.NewAlphaFinder(),
	})
}

// RFC9110 - 5.6.3. Whitespace
//
//  OWS            = *( SP / HTAB )
//  ; optional whitespace
//

func NewOwsFinder() abnfp.Finder {
	return abnfp.NewVariableRepetitionFinder(
		abnfp.NewAlternativesFinder([]abnfp.Finder{
			abnfp.NewSpFinder(),
			abnfp.NewHTabFinder(),
		}),
	)
}

// RFC9110 - 5.6.3. Whitespace
//
//  RWS            = 1*( SP / HTAB )
//  ; required whitespace
//

func NewRwsFinder() abnfp.Finder {
	return abnfp.NewVariableRepetitionMinFinder(
		1,
		abnfp.NewAlternativesFinder([]abnfp.Finder{
			abnfp.NewSpFinder(),
			abnfp.NewHTabFinder(),
		}),
	)
}

// RFC9110 - 5.6.3. Whitespace
//
//  BWS            = OWS
//  ; "bad" whitespace
//

func NewBwsFinder() abnfp.Finder {
	return NewOwsFinder()
}

// RFC9110 - 5.6.4. Quoted Strings
//
//  quoted-string  = DQUOTE *( qdtext / quoted-pair ) DQUOTE
//

func NewQuotedStringFinder() abnfp.Finder {
	return abnfp.NewConcatenationFinder([]abnfp.Finder{
		abnfp.NewDQuoteFinder(),
		abnfp.NewVariableRepetitionFinder(
			abnfp.NewAlternativesFinder([]abnfp.Finder{
				NewQdTextFinder(),
				NewQuotedPairFinder(),
			}),
		),
		abnfp.NewDQuoteFinder(),
	})
}

// RFC9110 - 5.6.4. Quoted Strings
//
//  qdtext         = HTAB / SP / %x21 / %x23-5B / %x5D-7E / obs-text
//

// NOTE
// x21    : !
// x23-5B : #, $, %, & ' ( ) * + , - . / 0-9, : ; < = > ? @ A-Z [
// x5D-7E : ] ^ _ ` a-z { | } ~
func NewQdTextFinder() abnfp.Finder {
	return abnfp.NewAlternativesFinder([]abnfp.Finder{
		abnfp.NewHTabFinder(),
		abnfp.NewSpFinder(),
		abnfp.NewByteFinder(0x21),
		abnfp.NewValueRangeAlternativesFinder(0x23, 0x5b),
		abnfp.NewValueRangeAlternativesFinder(0x5d, 0x7e),
		NewObsTextFinder(),
	})
}

// RFC9110 - 5.6.4. Quoted Strings
//
//  quoted-pair    = "\" ( HTAB / SP / VCHAR / obs-text )
//

func NewQuotedPairFinder() abnfp.Finder {
	return abnfp.NewConcatenationFinder([]abnfp.Finder{
		abnfp.NewByteFinder('\\'),
		abnfp.NewAlternativesFinder([]abnfp.Finder{
			abnfp.NewHTabFinder(),
			abnfp.NewSpFinder(),
			abnfp.NewVCharFinder(),
			NewObsTextFinder(),
		}),
	})
}

// RFC9112 - 2.1. Message Format
//
//  HTTP-message   = start-line CRLF
//                   *( field-line CRLF )
//                   CRLF
//                   [ message-body ]
//

func NewHttpMessageFinder() abnfp.Finder {
	return abnfp.NewConcatenationFinder([]abnfp.Finder{
		NewStartLineFinder(),
		abnfp.NewCrLfFinder(),
		abnfp.NewVariableRepetitionFinder(
			abnfp.NewConcatenationFinder([]abnfp.Finder{
				NewFieldLineFinder(),
				abnfp.NewCrLfFinder(),
			}),
		),
		abnfp.NewCrLfFinder(),
		abnfp.NewOptionalSequenceFinder(NewMessageBodyFinder()),
	})
}

// RFC9112 - 2.1. Message Format
//
//  start-line     = request-line / status-line
//

func NewStartLineFinder() abnfp.Finder {
	return abnfp.NewAlternativesFinder([]abnfp.Finder{
		NewRequestLineFinder(),
		NewStatusLineFinder(),
	})
}

// RFC9112 - 2.3. HTTP Version
//
//  HTTP-version  = HTTP-name "/" DIGIT "." DIGIT
//

func NewHttpVersionFinder() abnfp.Finder {
	return abnfp.NewConcatenationFinder([]abnfp.Finder{
		NewHttpNameFinder(),
		abnfp.NewByteFinder('/'),
		abnfp.NewDigitFinder(),
		abnfp.NewByteFinder('.'),
		abnfp.NewDigitFinder(),
	})
}

// RFC9112 - 2.3. HTTP Version
//
//  HTTP-name     = %s"HTTP"
//

func NewHttpNameFinder() abnfp.Finder {
	return abnfp.NewBytesFinder([]byte("HTTP"))
}

// RFC9112 - 3. Request Line
//
//  request-line   = method SP request-target SP HTTP-version
//

func NewRequestLineFinder() abnfp.Finder {
	return abnfp.NewConcatenationFinder([]abnfp.Finder{
		NewMethodFinder(),
		abnfp.NewSpFinder(),
		NewRequestTargetFinder(),
		abnfp.NewSpFinder(),
		NewHttpVersionFinder(),
	})
}

// RFC9112 - 3.1. Method
//
//  method         = token
//

func NewMethodFinder() abnfp.Finder {
	return NewTokenFinder()
}

// RFC9112 - 3.2. Request Target
//
//  request-target = origin-form
//                 / absolute-form
//                 / authority-form
//                 / asterisk-form
//

func NewRequestTargetFinder() abnfp.Finder {
	return abnfp.NewAlternativesFinder([]abnfp.Finder{
		NewOriginFormFinder(),
		NewAbsoluteFormFinder(),
		NewAuthorityFormFinder(),
		NewAsteriskFormFinder(),
	})
}

// RFC9112 - 3.2.1. origin-form
//
//  origin-form    = absolute-path [ "?" query ]
//

func NewOriginFormFinder() abnfp.Finder {
	return abnfp.NewConcatenationFinder([]abnfp.Finder{
		NewAbsolutePathFinder(),
		abnfp.NewOptionalSequenceFinder(
			abnfp.NewConcatenationFinder([]abnfp.Finder{
				abnfp.NewByteFinder('?'),
				urip.NewQueryFinder(),
			}),
		),
	})
}

// RFC9112 - 3.2.2. absolute-form
//
//  absolute-form  = absolute-URI
//

func NewAbsoluteFormFinder() abnfp.Finder {
	return urip.NewAbsoluteUriFinder()
}

// RFC9112 - 3.2.3. authority-form
//
//  authority-form = uri-host ":" port
//

func NewAuthorityFormFinder() abnfp.Finder {
	return abnfp.NewConcatenationFinder([]abnfp.Finder{
		NewUriHostFinder(),
		abnfp.NewByteFinder(':'),
		urip.NewPortFinder(),
	})
}

// RFC9112 - 3.2.4. asterisk-form
//
//  asterisk-form  = "*"
//

func NewAsteriskFormFinder() abnfp.Finder {
	return abnfp.NewByteFinder('*')
}

// RFC9112 - 4. Status Line
//
//  status-line = HTTP-version SP status-code SP [ reason-phrase ]
//

func NewStatusLineFinder() abnfp.Finder {
	return abnfp.NewConcatenationFinder([]abnfp.Finder{
		NewHttpVersionFinder(),
		abnfp.NewSpFinder(),
		NewStatusCodeFinder(),
		abnfp.NewSpFinder(),
		abnfp.NewOptionalSequenceFinder(NewReasonPhraseFinder()),
	})
}

// RFC9112 - 4. Status Line
//
//  status-code    = 3DIGIT
//

func NewStatusCodeFinder() abnfp.Finder {
	return abnfp.NewSpecificRepetitionFinder(3, abnfp.NewDigitFinder())
}

// RFC9112 - 4. Status Line
//
//  reason-phrase  = 1*( HTAB / SP / VCHAR / obs-text )
//

func NewReasonPhraseFinder() abnfp.Finder {
	return abnfp.NewVariableRepetitionMinFinder(
		1,
		abnfp.NewAlternativesFinder([]abnfp.Finder{
			abnfp.NewHTabFinder(),
			abnfp.NewSpFinder(),
			abnfp.NewVCharFinder(),
			NewObsTextFinder(),
		}),
	)
}

// RFC9112 - 5. Field Syntax
//
//  field-line   = field-name ":" OWS field-value OWS
//

func NewFieldLineFinder() abnfp.Finder {
	return abnfp.NewConcatenationFinder([]abnfp.Finder{
		NewFieldNameFinder(),
		abnfp.NewByteFinder(':'),
		NewOwsFinder(),
		NewFieldValueFinder(),
		NewOwsFinder(),
	})
}

// RFC9112 - 6. Message Body
//
//  message-body = *OCTET
//

func NewMessageBodyFinder() abnfp.Finder {
	return abnfp.NewVariableRepetitionFinder(abnfp.NewOctetFinder())
}
