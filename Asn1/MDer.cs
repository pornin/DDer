using System;
using System.Collections;
using System.Collections.Generic;
using System.IO;
using System.Text;

using BigInt;

namespace Asn1 {

/*
 * This class implements a custom syntax for building and parsing ASN.1
 * objects. The syntax describes the object elements and accepts dynamic
 * parameters. When building an object (MDer.Build()), the parameter
 * values are used to populate the object fields at the places
 * referenced in the syntax (similar in concept the the C printf()
 * call). When parsing an object (MDer.Parse()), the parameter values
 * are populated with values found in the source object.
 *
 * An "ASN.1 object" is any instance that implements IAsn1 and can thus
 * be represented as an AsnElt instance; when an ASN.1 object is returned
 * during a parsing process, it is an AsnElt instance. This class does not
 * handle low-level (DER) encoding or decoding.
 *
 *
 * Syntax:
 * -------
 *
 * A semicolon (';') outside of a literal string introduces a comment that
 * spans until the end of the current line (i.e. up to the next LF character).
 * A comment counts as whitespace.
 *
 * 'param-ref' is %nnn with 'nnn' being a decimal number that is the index
 * of the parameter in the provided array (starting at 0). There must be at
 * least one decimal digit; all consecutive decimal digits are used.
 *
 *
 *    param-ref
 *    (param-ref)
 *    ([tagvalue] param-ref)
 *    ([tagclass tagvalue] param-ref)
 *
 *       Uses the parameter as an object.
 *
 *       When building: parameter can be null, in which case the whole object
 *       is considered optional and missing. Otherwise, it MUST be an IAsn1.
 *       If a tag is specified, and the parameter is not null, then the tag
 *       replaces the one of the parameter object (this is implicit tagging).
 *
 *       When parsing: the tag, if present, is checked to match the object.
 *       The parameter slot is set to the object value.
 *
 *       tagclass: one of:
 *           univ  universal
 *           app  application
 *           priv  private
 *           context
 *
 *       tagvalue: either a decimal integer, or one of:
 *           bool  boolean
 *           int  integer
 *           bits  bitstring  bit-string
 *           bytes  blob  octet-string
 *           null
 *           oid  object-identifier
 *           enum  enumerated
 *           utf8  utf-8  utf8string
 *           sequence
 *           set
 *           numeric  numericstring
 *           printable  printablestring
 *           ia5  ia5string
 *           teletex  telextexstring
 *           genstring  generalstring
 *           utf8  utf-8  utf8string
 *           utf16  utf-16  bmp  bmpstring
 *           utf32  utf-32  universal  universalstring
 *           utc  utctime
 *           gentime  generalizedtime
 *
 *       Either or both of tagvalue and tagclass may be a parameter
 *       reference.
 *       Building:
 *        - tagclass must be a string or an int; valid range is 0 to 3
 *        - tagvalue must be a string or an int; valid range is 0 to
 *          2147483647
 *       Parsing:
 *        - tagclass and/or tagvalue parameter is set to an int
 *       When the tagclass is not provided, CONTEXT is assumed.
 *
 *       When tagvalue is provided, but not tagclass, then:
 *        - if tagvalue is one of the symbolic strings above, then the
 *          tag class is UNIVERSAL;
 *        - otherwise, the tag class is CONTEXT.
 *
 *
 *    (type value)
 *    ([tagvalue] type value)
 *    ([tagclass tagvalue] type value)
 *
 *       'type' is a keyword that specifies the object type. 'value'
 *       depends on the object type, and may be a parameter ref.
 *
 *       When building: If the value is a parameter and the parameter is
 *       null, then the whole object is considered optional and missing.
 *
 *       When parsing: the value may be '.', in which case its contents
 *       are ignored. Otherwise, the contents are (recursively) matched with
 *       the input.
 *
 * Type keywords are not case-sensitive.
 * Object types and corresponding rules for values:
 *
 *    bool
 *    boolean
 *       BOOLEAN object. Value is one of:
 *         true   on   yes  1       -> value is TRUE
 *         false  off  no   0       -> value is FALSE
 *         parameter of .NET type Boolean
 *       Parsing: produces a Boolean value.
 *
 *    int
 *    integer
 *       INTEGER object. Value is either a string representation as
 *       accepted by ZInt.Parse(), or a parameter with type ZInt or
 *       one of the core .NET integer types (sbyte, byte, short, ushort,
 *       int, uint, long or ulong).
 *       Parsing: produces a ZInt value.
 *
 *    enum
 *    enumerated
 *       ENUMERATED object. Rules are the same as for INTEGER; only the
 *       produced tag value changes (if not overridden).
 *
 *    bits
 *       BIT STRING object. Two sub-values are expected: the number of
 *       ignored bits, and the bits themselves.
 *       Ignored bits value (must be between 0 and 7):
 *           int         literal integer
 *           param-ref   parameter must be of type int, or null
 *       Value bits:
 *           hex         hexadecimal data blob
 *           (...)       nested object (bits are its DER encoding)
 *           param-ref   parameter must be byte[], IAsn1 or null
 *
 *       Building:
 *        - If either the number of ignored bits or the value bits are
 *          a parameter reference and the parameter is null, then the
 *          object is considered absent.
 *        - When the bits are a parameter of type IAsn1, the DER encoding
 *          of the object is used as value.
 *        - When the bits are specified as a nested object or as a
 *          parameter of type IAsn1, then the number of ignored bits
 *          is verified to be zero. Otherwise, the number of ignored bits
 *          is verified to be between 0 and 7, and the ignored bits in the
 *          provided hex value are verified to have value 0.
 *
 *       Parsing:
 *        - If the number of ignored bits is a parameter ref, then the
 *          parameter is set to a value of type int containing that
 *          number.
 *        - If the value bits are a parameter reference, then the parameter
 *          is set to a byte[]. The ignored bits are forced to 0.
 *        - If the value bits are a nested object, then the number of ignored
 *          bits are verified to be 0, and the value bits are decoded as
 *          a DER object which is explored recursively.
 *
 *    blob
 *    bytes
 *       OCTET STRING object.
 *       Value depends on the next non-whitespace character:
 *           hex digit   hexadecimal data blob
 *           '('         nested object
 *           '%'         parameter ref; must be byte[], IAsn1 or null
 *       If the value is IAsn1, then its DER-encoding is used.
 *       Parsing:
 *        - hex blob: matched with the object
 *        - parameter ref: set to a byte[]
 *        - nested object: explored recursively
 *
 *    null
 *       NULL object. Value is empty.
 *
 *    oid
 *       OBJECT IDENTIFIER object. Value is one of:
 *           decimal-dotted notation for an OID
 *           symbolic identifier for a well-known OID
 *           parameter ref; must be string or null
 *       When a parameter of type string is used, the string value must
 *       be a correctly formed decimal-dotted notation, or a well-known
 *       OID identifier.
 *       Parsing:
 *        - literal OID (or symbolic identifier): matched with the object
 *        - parameter ref: set to a string (decimal-dotted)
 *
 *    numeric  numericstring
 *    printable  printablestring
 *    ia5  ia5string
 *    teletex  telextexstring
 *    genstring  generalstring
 *    utf8  utf-8  utf8string
 *    utf16  utf-16  bmp  bmpstring
 *    utf32  utf-32  universal  universalstring
 *    utc  utctime
 *    gentime  generalizedtime
 *       Character string object (including time objects). Value is one of:
 *          literal string  (in double-quotes)
 *          parameter ref; must be string or null
 *       In a literal string, a backslash introduces an escape sequence:
 *          \\         backslash
 *          \"         double-quote character
 *          \n         LF (character value 0x0A)
 *          \r         CR (character value 0x0D)
 *          \t         tabulation (character value 0x09)
 *          \xNN       character with value 'NN' (two hexadecimal digits)
 *          \uNNNN     character with value 'NNNN' (four hexadecimal digits)
 *          \UNNNNNN   character with value 'NNNNNN' (six hexadecimal digits)
 *       The string value is verified to match the specified type, with the
 *       following caveats:
 *        - For UTCTime and GeneralizedTime, only verification is that all
 *          characters are within the 'PrintableString' charset.
 *        - For TeletexString and GeneralString, "latin-1" semantics are
 *          used (all characters should be in the 0..255 range).
 *
 *       Parsing:
 *        - literal string: matched with the object (ordinal match)
 *        - parameter ref: set to a string, except for UTCTime and
 *          GeneralizedTime, in which case the date is parsed and the
 *          parameter is set to a DateTime (UTC)
 *
 *    set
 *    sequence
 *       Value is a sequence of sub-objects.
 *
 *       Building:
 *          (...)         a sub-object spec (explored recursively)
 *          *(...)        multiple sub-objects (see below)
 *          param-ref     a parameter reference; should be IAsn1 or null
 *          *param-ref    shorthand for *(param-ref)
 *       When using the '*' or '+' operators, the sub-specification should
 *       include at least one parameter reference with a parameter value
 *       which implements IEnumerable; if there is none, then this sub-object
 *       is omitted. Sub-objects are built for each element in the
 *       IEnumerable (except where null values imply omission). If the
 *       sub-specification uses several IEnumerable parameters, then
 *       the building of the list of sub-objects stops as soon as one of
 *       these enumerations is exhausted.
 *
 *       Additional rules for building:
 *        - Sub-objects are included in the order they appear. There is
 *          no sorting step for SETs.
 *        - null/omitted sub-objects are skipped.
 *        - The only difference between 'set' and 'sequence' here is the
 *          tag value (if the tag is overriden with an explicit
 *          specification, then this difference has no impact).
 *
 *       Parsing: each sub-value may be:
 *          (...)         a sub-object spec (explored recursively)
 *          ?(...)        an optional sub-object spec (explored recursively
 *                        if present)
 *          ?(...):repl   an optional sub-object spec with a replacement
 *                        action if not present (see below)
 *          param-ref     parameter is set to the sub-object (AsnElt)
 *          ?param-ref    parameter is set to the sub-object (AsnElt), if
 *                        present; null otherwise. This matches any
 *                        sub-object; use a sub-object spec with explicit
 *                        tagging to match specific sub-objects.
 *          *spec         all remaining objects are explored with the spec
 *          +spec         all remaining objects are explored with the spec
 *                        (there must be at least one remaining object)
 *       When using '*' or '+', the recursive operation applies the spec
 *       repeatedly; whenever a parameter value is gathered, the parameter
 *       array slot is set to a list of the specifie type (List<string>,...)
 *       (created if necessary) and the value is added to it.
 *       The '+' operator is similar to '*' except that it enforces the
 *       presence of at least one sub-object.
 *
 *       Replacement actions are sequences of store values into parameters.
 *       This is meant to provide for default values, in particular when
 *       accumulating elements from a sequence. Syntax of 'repl' is:
 *        - an opening parenthesis
 *        - one or several pairs:
 *             param-ref (type value)
 *        - a closing parenthesis
 *
 *    setof
 *       This behaves like a 'set', except that after all sub-object values
 *       are gathered, they are sorted by lexicographic ordering of their
 *       respective encodings (exact duplicates are removed).
 *       Parsing: no check is done on order.
 *
 *    setder
 *       This behaves like a 'set', except that after all sub-object values
 *       are gathered, they are sorted by tag class and value (as mandated
 *       by DER for SETs which are not SET OF). If two sub-objects have the
 *       same tag class and value, then an error is reported.
 *       Parsing: no check is done on order.
 *
 *    set-nz
 *    sequence-nz
 *    setof-nz
 *    setder-nz
 *       These are equivalent to set, sequence, setof and setder,
 *       respectively, except that an empty resulting object is suppressed
 *       and treated as optional and absent instead.
 *       Parsing: input is verified not to be empty.
 *
 *    tag
 *       Value is a single sub-object; if that sub-object is null, then
 *       the tag object is removed as well. An error is reported if this
 *       type is used without specifying a tag class and value.
 *       Parsing: similar to parsing a 'sequence' with a single element.
 *
 *
 * Usage:
 * ------
 *
 * MDer.Build() for building, MDer.Parse() for parsing. The syntax can
 * be provided as either a string or a TextReader.
 *
 * Errors in the format syntax are reported with a FormatException.
 *
 * When building, a FormatException may also be thrown if a parameter
 * value has a type which is not compatible with the context in which
 * it is used (e.g. the value is used in a BOOLEAN but is not a bool
 * or null).
 *
 * When parsing, errors in the source object (including values that can
 * be decoded as ASN.1/DER but do not match the provided format) are
 * reported with an AsnException (which extends IOException).
 *
 * MDer.Build() only reads parameter values. MDer.Parse() only writes
 * parameter values. When parsing, the provided array is not cleared
 * first; the caller is responsible for that task. Moreover, in case of
 * a parse error, parameter values that were set prior to detecting the
 * error are still set.
 */

public class MDer {

	TextReader input;
	int lookAhead;
	object[] pp;
	bool paramAccumulate;

	MDer(TextReader input, object[] pp)
	{
		this.input = input;
		lookAhead = -1;
		if (pp == null) {
			pp = new object[0];
		}
		this.pp = pp;
		paramAccumulate = false;
	}

	/*
	 * Build an ASN.1 object using the provided format string with
	 * optional parameters. null may be returned if the syntax
	 * specifies to use a parameter value which has value null.
	 *
	 * In case of trailing garbage (non-whitespace after the object
	 * specification), then this function throws a FormatException.
	 */
	public static AsnElt Build(string fmt, params object[] pp)
	{
		MDer md = new MDer(new StringReader(fmt), pp);
		AsnElt ae = md.Build();
		if (md.PeekNextChar() != -1) {
			throw new FormatException("trailing garbage after object in format string");
		}
		return ae;
	}

	/*
	 * Build an ASN.1 object using the provided format string with
	 * optional parameters. null may be returned if the syntax
	 * specifies to use a parameter value which has value null.
	 *
	 * This function reads only as many characters as it requires
	 * for building purposes. Since specifications are normally
	 * self-terminated, this means that characters after the final
	 * ')' character remain unread.
	 */
	public static AsnElt Build(TextReader fmt, params object[] pp)
	{
		MDer md = new MDer(fmt, pp);
		return md.Build();
	}

	/*
	 * Build an ASN.1 object using the provided format string with
	 * optional parameters. The object value is set in 'ae'. That
	 * value may be null if the syntax specifies to use a parameter
	 * value which has value null.
	 *
	 * This function reads only as many characters as it requires
	 * for building purposes. Since specifications are normally
	 * self-terminated, this means that characters after the final
	 * ')' character remain unread.
	 *
	 * This function sets the built object in 'ae' and returns true.
	 * If the input stream only contains whitespace, and no actual
	 * object specification, then 'ae' is set to null and the return
	 * value is false.
	 */
	public static bool TryBuild(TextReader fmt, out AsnElt ae,
		params object[] pp)
	{
		MDer md = new MDer(fmt, pp);
		bool eof;
		ae = md.BuildNext(out eof);
		if (eof) {
			int c = md.PeekNextChar();
			if (c != -1) {
				throw new FormatException(string.Format("unexpected character in specification: U+{0:X4}", c));
			}
			return false;
		}
		return true;
	}

	/*
	 * Parse an ASN.1 object using the provided specification string,
	 * and output parameter array.
	 *
	 * In case of trailing garbage (non-whitespace after the
	 * specification string), then this function throws an Exception.
	 */
	public static void Parse(string fmt, AsnElt ae, params object[] pp)
	{
		MDer md = new MDer(new StringReader(fmt), pp);
		md.Parse(ae);
		if (md.PeekNextChar() != -1) {
			throw new FormatException("trailing garbage after object in format string");
		}
	}

	/*
	 * Parse an ASN.1 object using the provided specification text,
	 * and output parameter array.
	 *
	 * This function reads only as many characters as it requires
	 * for parsing purposes. Since specifications are normally
	 * self-terminated, this means that characters after the final
	 * ')' character remain unread.
	 */
	public static void Parse(TextReader fmt, AsnElt ae, params object[] pp)
	{
		MDer md = new MDer(fmt, pp);
		md.Parse(ae);
	}

	AsnElt Build()
	{
		bool eof;
		AsnElt ae = BuildNext(out eof);
		if (eof) {
			throw new FormatException("no valid object at start of format string");
		}
		return ae;
	}

	void Parse(AsnElt d)
	{
		int c = PeekNextChar();
		switch (c) {
		case '(':
		case '%':
		case '.':
			Parse(new AsnElt[] { d }, 0);
			break;
		default:
			throw new FormatException("no valid object at start of format string");
		}
	}

	/*
	 * Check whether a character is whitespace. Whitespace is all ASCII
	 * control characters (0x00 to 0x1F), ASCII space (0x20), and
	 * latin-1 unbreakable space (0xA0).
	 */
	static bool IsWS(int c)
	{
		return c <= 32 || c == 160;
	}

	/*
	 * Check whether a character is a decimal digit ('0' to '9').
	 */
	static bool IsDigit(int c)
	{
		return c >= '0' && c <= '9';
	}

	/*
	 * Check whether a character is an hexadecimal digit.
	 */
	static bool IsHexDigit(int c)
	{
		return (c >= '0' && c <= '9')
			|| (c >= 'A' && c <= 'F')
			|| (c >= 'a' && c <= 'f');
	}

	static bool[] WORD_CHAR = new bool[128];
	const string WORD_EXTRA_CHARS = "$_-+.,";

	/*
	 * Check whether a character is a "word character". Words consist
	 * of ASCII letters (lowercase and uppercase), ASCII digits, and
	 * the characters: $ _ - + . ,
	 */
	static bool IsWordChar(int c)
	{
		return c >= 0 && c < 128 && WORD_CHAR[c];
	}

	/*
	 * Peek at the next character in the source stream (without
	 * skipping whitespace).
	 */
	int LowPeek()
	{
		if (lookAhead < 0) {
			lookAhead = input.Read();
		}
		return lookAhead;
	}

	/*
	 * Read the next character from the source stream (without skipping
	 * whitespace).
	 */
	int LowRead()
	{
		int v = LowPeek();
		lookAhead = -1;
		return v;
	}

	/*
	 * Read the next character from the source stream; each sequence of
	 * consecutive whitespace is coalesced into a single space character.
	 */
	int NextCharWS()
	{
		int c = LowPeek();
		if (c < 0) {
			return -1;
		} else if (IsWS(c) || c == ';') {
			for (;;) {
				c = LowPeek();
				if (c < 0) {
					break;
				} else if (IsWS(c)) {
					LowRead();
					continue;
				} else if (c == ';') {
					do {
						c = LowRead();
					} while (c >= 0 && c != '\n');
					continue;
				} else {
					break;
				}
			}
			return ' ';
		} else {
			LowRead();
			return c;
		}
	}

	/*
	 * Peek at the next non-whitespace character. Whitespace is skipped
	 * (including comments).
	 */
	int PeekNextChar()
	{
		for (;;) {
			int c = LowPeek();
			if (c < 0) {
				return -1;
			}
			if (IsWS(c)) {
				LowRead();
				continue;
			}

			/*
			 * Semicolon introduces a comment that spans to
			 * the end of the current line.
			 */
			if (c == ';') {
				do {
					c = LowRead();
					if (c < 0) {
						return -1;
					}
				} while (c != '\n');
				continue;
			}

			/*
			 * An opening brace starts a comment that stops
			 * on the matching closing brace. We must take
			 * care of nested semicolon-comments and string
			 * literals: braces in those don't count.
			 */
			if (c == '{') {
				LowRead();
				int count = 1;
				while (count > 0) {
					c = LowRead();
					if (c < 0) {
						return -1;
					}
					if (c == ';') {
						do {
							c = LowRead();
							if (c < 0) {
								return -1;
							}
						} while (c != '\n');
						continue;
					}
					if (c == '"') {
						bool lcwb = false;
						for (;;) {
							c = LowRead();
							if (c < 0) {
								return -1;
							}
							if (lcwb) {
								lcwb = false;
							} else if (c == '\\') {
								lcwb = true;
							} else if (c == '"') {
								break;
							}
						}
						continue;
					}
					if (c == '{') {
						count ++;
					} else if (c == '}') {
						count --;
					}
				}
				continue;
			}
			return c;
		}
	}

	/*
	 * Read the next non-whitespace character. Whitespace is skipped
	 * (including comments).
	 */
	int NextChar()
	{
		int c = PeekNextChar();
		if (c >= 0) {
			LowRead();
		}
		return c;
	}

	/*
	 * Find the closing parenthesis for the current context. If
	 * 'sb' is not null, then read characters are accumulated in it
	 * (whitespace sequences are replaced with a single space).
	 */
	void FindClosingParenthesis(StringBuilder sb)
	{
		int nump = 1;
		while (nump > 0) {
			int c = NextCharWS();
			if (c < 0) {
				throw new FormatException("unmatched opening parenthesis");
			}
			if (sb != null) {
				sb.Append((char)c);
			}
			switch (c) {
			case '(':
				nump ++;
				break;
			case ')':
				nump --;
				break;
			case '"':
				// for a literal string, we must use LowRead()
				// to avoid whitespace/comment processing.
				bool lwb = false;
				for (;;) {
					c = LowRead();
					if (c < 0) {
						throw new FormatException("unfinished literal string");
					}
					if (sb != null) {
						sb.Append((char)c);
					}
					if (lwb) {
						lwb = false;
					} else if (c == '\\') {
						lwb = true;
					} else if (c == '"') {
						break;
					}
				}
				break;
			}
		}
	}


	/*
	 * Read a word (sequence of word characters). The first character
	 * has already been read, and is provided as 'fc'.
	 */
	string ReadWord(int fc)
	{
		StringBuilder sb = new StringBuilder();
		sb.Append((char)fc);
		for (;;) {
			int c = LowPeek();
			if (!IsWordChar(c)) {
				return sb.ToString();
			}
			sb.Append((char)LowRead());
		}
	}

	/*
	 * Read a word (sequence of word characters). Whitespace before
	 * the word is skipped. An exception is thrown if there is no
	 * remaining non-whitespace character (end-of-stream reached) or
	 * if the next non-whitespace character is not a word character.
	 */
	string ReadWord()
	{
		int fc = NextChar();
		if (fc < 0) {
			throw new FormatException("truncated input");
		}
		if (!IsWordChar(fc)) {
			throw new FormatException(string.Format("unexpected U+{0:X4} character", fc));
		}
		return ReadWord(fc);
	}

	/*
	 * Read a parameter reference. It is assumed that the first
	 * reference character ('%') has been peeked at but not read.
	 * Returned value is parameter index (which has been verified
	 * to be within range of the parameter array).
	 */
	int ReadParamRef()
	{
		if (NextChar() != '%') {
			throw new FormatException("expected parameter reference");
		}
		bool first = true;
		int x = 0;
		for (;;) {
			int c = LowPeek();
			if (!IsDigit(c)) {
				break;
			}
			first = false;
			LowRead();
			if (x > 214748364) {
				throw new FormatException("parameter number overflow");
			}
			x *= 10;
			c -= '0';
			if (x > 2147483647 - c) {
				throw new FormatException("parameter number overflow");
			}
			x += c;
		}
		if (first) {
			throw new FormatException("missing parameter number");
		}
		if (x >= pp.Length) {
			throw new FormatException(string.Format("invalid parameter number: {0} (max: {1})", x, pp.Length - 1));
		}
		return x;
	}

	/*
	 * Read a parameter reference. It is assumed that the first
	 * reference character ('%') has been peeked at but not read.
	 * Returned value is the parameter value (which may be null).
	 */
	object ReadParamVal()
	{
		return pp[ReadParamRef()];
	}

	/*
	 * Get the value of a character as an hexadecimal digit. If the
	 * character is not an hex digit, then -1 is returned.
	 */
	int HexValue(int c)
	{
		if (c >= '0' && c <= '9') {
			return c - '0';
		} else if (c >= 'A' && c <= 'F') {
			return c - ('A' - 10);
		} else if (c >= 'a' && c <= 'f') {
			return c - ('a' - 10);
		} else {
			return -1;
		}
	}

	/*
	 * Return the next source character (no whitespace skipping) and
	 * obtain its value as an hexadecimal digit; an exception is thrown
	 * if there is no such character (end-of-stream) or if the next
	 * character is not an hex digit.
	 */
	int ReadHexChar()
	{
		int c = LowRead();
		if (c < 0) {
			throw new FormatException("truncated input: unfinished string literal");
		}
		int d = HexValue(c);
		if (d < 0) {
			throw new FormatException(string.Format("invalid character U+{0:X4}, expecting hex digit", c));
		}
		return d;
	}

	/*
	 * Read a literal string value. Leading whitespace is skipped.
	 */
	string ReadLiteralString()
	{
		int c = PeekNextChar();
		if (c != '"') {
			throw new FormatException("expected literal string");
		}
		LowRead();
		StringBuilder sb = new StringBuilder();
		bool lwb = false;
		for (;;) {
			c = LowRead();
			if (c < 0) {
				throw new FormatException("truncated input: unfinished string literal");
			}
			if (lwb) {
				switch ((char)c) {
				case 'n': c = '\n'; break;
				case 't': c = '\t'; break;
				case 'r': c = '\r'; break;
				case 'x':
					c = ReadHexChar();
					c = (c << 4) + ReadHexChar();
					break;
				case 'u':
					c = ReadHexChar();
					c = (c << 4) + ReadHexChar();
					c = (c << 4) + ReadHexChar();
					c = (c << 4) + ReadHexChar();
					break;
				case 'U':
					c = ReadHexChar();
					c = (c << 4) + ReadHexChar();
					c = (c << 4) + ReadHexChar();
					c = (c << 4) + ReadHexChar();
					c = (c << 4) + ReadHexChar();
					c = (c << 4) + ReadHexChar();
					break;
				}
				if (c > 0x10FFFF) {
					throw new FormatException("invalid Unicode codepoint: " + c);
				} else if (c > 0xFFFF) {
					c -= 0x10000;
					sb.Append((char)(0xD800 + (c >> 10)));
					sb.Append((char)(0xDC00 + (c & 0x3FF)));
				} else {
					sb.Append((char)c);
				}
				lwb = false;
			} else {
				switch ((char)c) {
				case '\\':
					lwb = true;
					continue;
				case '"':
					return sb.ToString();
				}
				sb.Append((char)c);
			}
		}
	}

	/*
	 * Read a string value. Leading whitespace is skipped. Expected
	 * value is either a double-quoted literal string, or a parameter
	 * reference. If a parameter is found, it must be a string, or null.
	 * An exception is thrown if no literal string or parameter reference
	 * is found.
	 */
	string ReadString()
	{
		int c = PeekNextChar();
		if (c < 0) {
			throw new FormatException("truncated input");
		}
		if (c == '%') {
			object obj = ReadParamVal();
			if (obj == null) {
				return null;
			} else if (obj is string) {
				return (string)obj;
			} else {
				throw new FormatException("unexpected parameter type: " + obj.GetType().FullName);
			}
		}
		if (c != '"') {
			throw new FormatException("not a string literal");
		}
		return ReadLiteralString();
	}

	/*
	 * Read a literal BOOLEAN value.
	 */
	bool ReadLiteralBoolean()
	{
		return ReadLiteralBoolean(ReadWord());
	}

	bool ReadLiteralBoolean(string w)
	{
		switch (w.ToLowerInvariant()) {
		case "true":
		case "on":
		case "yes":
		case "1":
			return true;
		case "false":
		case "off":
		case "no":
		case "0":
			return false;
		default:
			throw new FormatException("unexpected BOOLEAN value: " + w);
		}
	}

	/*
	 * Read a BOOLEAN value.
	 */
	AsnElt ReadBoolean()
	{
		int c = PeekNextChar();
		if (c == '%') {
			object obj = ReadParamVal();
			if (obj == null) {
				return null;
			} else if (obj is Boolean) {
				if ((bool)obj) {
					return AsnElt.BOOL_TRUE;
				} else {
					return AsnElt.BOOL_FALSE;
				}
			} else if (obj is string) {
				return ReadLiteralBoolean((string)obj)
					? AsnElt.BOOL_TRUE : AsnElt.BOOL_FALSE;
			} else {
				throw new FormatException("unexpected parameter type: " + obj.GetType().FullName);
			}
		}
		bool v = ReadLiteralBoolean();
		return v ? AsnElt.BOOL_TRUE : AsnElt.BOOL_FALSE;
	}

	/*
	 * Read a literal INTEGER value.
	 */
	ZInt ReadLiteralInteger()
	{
		return ReadLiteralInteger(ReadWord());
	}

	ZInt ReadLiteralInteger(string w)
	{
		// If the word is not a valid integer value, a proper
		// FormatException is thrown.
		return ZInt.Parse(w);
	}

	/*
	 * Read an INTEGER value.
	 */
	AsnElt ReadInteger()
	{
		int c = PeekNextChar();
		ZInt x;
		if (c == '%') {
			object obj = ReadParamVal();
			if (obj == null) {
				return null;
			}
			if (obj is SByte) {
				x = (ZInt)(sbyte)obj;
			} else if (obj is Byte) {
				x = (ZInt)(byte)obj;
			} else if (obj is Int16) {
				x = (ZInt)(short)obj;
			} else if (obj is UInt16) {
				x = (ZInt)(ushort)obj;
			} else if (obj is Int32) {
				x = (ZInt)(int)obj;
			} else if (obj is UInt32) {
				x = (ZInt)(uint)obj;
			} else if (obj is Int64) {
				x = (ZInt)(long)obj;
			} else if (obj is UInt64) {
				x = (ZInt)(ulong)obj;
			} else if (obj is ZInt) {
				x = (ZInt)obj;
			} else if (obj is string) {
				x = ReadLiteralInteger((string)obj);
			} else {
				throw new FormatException("unexpected parameter type: " + obj.GetType().FullName);
			}
		} else {
			x = ReadLiteralInteger();
		}
		return AsnElt.MakeInteger(x);
	}

	/*
	 * Read literal blob contents (hex dump). Whitespace and ':' are
	 * ignored; processing stop at the first character which is neither
	 * whitespace, ':' or an hexadecimal digit. If the number of hex
	 * digits is odd, an exception is thrown.
	 */
	byte[] ReadLiteralBlobContents()
	{
		MemoryStream ms = new MemoryStream();
		int acc = 0;
		bool high = true;
		for (;;) {
			int c = PeekNextChar();
			if (c == ':') {
				LowRead();
				continue;
			}
			int d = HexValue(c);
			if (d < 0) {
				break;
			}
			LowRead();
			if (high) {
				acc = d;
			} else {
				ms.WriteByte((byte)((acc << 4) + d));
			}
			high = !high;
		}
		if (!high) {
			throw new FormatException("long hex digit (half final byte in value)");
		}
		return ms.ToArray();
	}

	/*
	 * Convert the provided string into bytes. This expects the
	 * string to either contain hex digits, or the description of
	 * an ASN.1 object, which is then built and DER-encoded.
	 */
	byte[] MakeBlobContents(string w)
	{
		int n = w.Length;
		int i = 0;
		for (;;) {
			if (i >= n) {
				return new byte[0];
			}
			int c = w[i];
			if (IsWS(c)) {
				i ++;
				continue;
			}
			if (c == ':' || IsHexDigit(c)) {
				break;
			} else {
				return MDer.Build(w).Encode();
			}
		}

		// Found a colon or hex digit, this should be hex data.
		MemoryStream ms = new MemoryStream();
		int acc = 0;
		bool high = true;
		for (;;) {
			if (i >= n) {
				break;
			}
			int c = w[i ++];
			if (IsWS(c) || c == ':') {
				continue;
			}
			int d = HexValue(c);
			if (d < 0) {
				throw new FormatException(string.Format("not an hexadecimal digit: U+{0:X4}", d));
			}
			if (high) {
				acc = d;
			} else {
				ms.WriteByte((byte)((acc << 4) + d));
			}
			high = !high;
		}
		if (!high) {
			throw new FormatException("long hex digit (half final byte in value)");
		}
		return ms.ToArray();
	}

	/*
	 * Read blob contents; these may be:
	 *   - hexadecimal digits
	 *   - a nested object definition (its DER encoding is the value)
	 *   - a parameter ref for a byte[] or an IAsn1 (in the latter
	 *     case, the ASN.1 object is DER-encoded)
	 */
	byte[] ReadBlobContents()
	{
		int c = PeekNextChar();
		if (c == '%') {
			object obj = ReadParamVal();
			if (obj == null) {
				return null;
			} else if (obj is byte[]) {
				return (byte[])obj;
			} else if (obj is IAsn1) {
				return ((IAsn1)obj).ToAsn1().Encode();
			} else if (obj is string) {
				return MakeBlobContents((string)obj);
			} else {
				throw new FormatException("unexpected parameter type: " + obj.GetType().FullName);
			}
		} else if (IsHexDigit(c)) {
			return ReadLiteralBlobContents();
		} else if (c == '(') {
			bool eof;
			AsnElt ae = BuildNext(out eof);
			if (eof) {
				throw new FormatException("truncated input");
			}
			if (ae == null) {
				return null;
			} else {
				return ae.Encode();
			}
		} else {
			throw new FormatException(string.Format("unexpected character U+{0:X4} in value", c));
		}
	}

	/*
	 * Read a BIT STRING value.
	 */
	AsnElt ReadBitString()
	{
		int c = PeekNextChar();
		int ignb = 0;
		if (IsDigit(c)) {
			ignb = Int32.Parse(ReadWord());
			if (ignb < 0 || ignb > 7) {
				throw new FormatException("invalid number of ignored bits in BIT STRING: " + ignb);
			}
			c = PeekNextChar();
		}
		byte[] bsv = ReadBlobContents();
		if (bsv == null) {
			return null;
		}
		if (ignb != 0) {
			if (bsv.Length == 0) {
				throw new FormatException(string.Format("{0} ignored bit(s) but empty value", ignb));
			}
			if ((bsv[bsv.Length - 1] & ((1 << ignb) - 1)) != 0) {
				throw new FormatException("ignored bit(s) are not zero");
			}
		}
		return AsnElt.MakeBitString(ignb, bsv);
	}

	/*
	 * Read an OCTET STRING value.
	 */
	AsnElt ReadOctetString()
	{
		byte[] v = ReadBlobContents();
		if (v == null) {
			return null;
		} else {
			return AsnElt.MakeBlob(v);
		}
	}

	/*
	 * Read a literal OBJECT IDENTIFIER value (symbolic names are
	 * translated to decimal-dotted notation).
	 */
	string ReadLiteralOID()
	{
		try {
			return AsnOID.ToOID(ReadWord());
		} catch (AsnException ex) {
			throw new FormatException(ex.Message);
		}
	}

	/*
	 * Read an OBJECT IDENTIFIER value.
	 */
	AsnElt ReadOID()
	{
		try {
			int c = PeekNextChar();
			string str;
			if (c == '%') {
				object obj = ReadParamVal();
				if (obj == null) {
					return null;
				} else if (obj is string) {
					str = (string)obj;
				} else if (obj is IAsn1) {
					str = ((IAsn1)obj).ToAsn1().GetOID();
				} else {
					throw new FormatException("unexpected parameter type: " + obj.GetType().FullName);
				}
			} else {
				str = ReadLiteralOID();
			}
			return AsnElt.MakeOID(str);
		} catch (AsnException ex) {
			throw new FormatException(ex.Message);
		}
	}

	/*
	 * Read a string value and return it as an ASN.1 object with the
	 * specified string type. If the string value uses a parameter
	 * reference and the parameter is null, then null is returned.
	 */
	AsnElt ReadString(int stringType)
	{
		try {
			string str = ReadString();
			if (str == null) {
				return null;
			}
			return AsnElt.MakeString(stringType, str);
		} catch (AsnException ex) {
			throw new FormatException(ex.Message);
		}
	}

	/*
	 * Read a time value. This is equivalent to reading a string value,
	 * except that if the value is a parameter reference, then the
	 * parameter may be of type DateTime or DateTimeOffset as well as
	 * a plain string.
	 * The 'type' must be UTCTime or GeneralizedTime.
	 */
	AsnElt ReadTime(int type)
	{
		try {
			int c = PeekNextChar();
			if (c == '%') {
				object obj = ReadParamVal();
				if (obj == null) {
					return null;
				} else if (obj is string) {
					return AsnElt.MakeString(
						type, (string)obj);
				} else if (obj is DateTime) {
					DateTime dt = (DateTime)obj;
					if (dt == DateTime.MinValue) {
						return null;
					}
					return AsnElt.MakeTime(type, dt);
				} else if (obj is DateTimeOffset) {
					DateTimeOffset dto =
						(DateTimeOffset)obj;
					if (dto == DateTimeOffset.MinValue) {
						return null;
					}
					return AsnElt.MakeTime(type, dto);
				} else {
					throw new FormatException("unexpected parameter type: " + obj.GetType().FullName);
				}
			}
			return ReadString(type);
		} catch (AsnException ex) {
			throw new FormatException(ex.Message);
		}
	}

	const int ORDER_TAG = 1;
	const int ORDER_VALUE = 2;

	/*
	 * Read a constructed element, with the specified tag. If
	 * 'noEmpty' is true, then an empty object is suppressed (replaced
	 * with null). If 'order' is not zero, then it designates a
	 * specific ordering rule:
	 *    ORDER_TAG      order by tag value (DER rule for SET)
	 *    ORDER_VALUE    order by value (lexicographic, for SET OF)
	 * When ordering by tag, an exception is thrown if two elements
	 * have the same tag class and value. When ordering by value,
	 * exact duplicates are merged.
	 */
	AsnElt ReadConstructed(int tagValue, bool noEmpty, int order)
	{
		List<AsnElt> r = new List<AsnElt>();
		for (;;) {
			int c = PeekNextChar();
			if (c == '*') {
				// Multiple sub-objects from a single
				// specification.
				LowRead();
				c = PeekNextChar();
				string spec;
				if (c == '%') {
					int id = ReadParamRef();
					spec = string.Format("(%{0})", id);
				} else if (c == '(') {
					LowRead();
					StringBuilder sb = new StringBuilder();
					sb.Append("(");
					FindClosingParenthesis(sb);
					spec = sb.ToString();
				} else {
					throw new FormatException(string.Format("unexpected character U+{0:X4} after '*' operator", c));
				}
				ReadMultiple(r, spec);
				continue;
			}
			if (c == '%') {
				object obj = ReadParamVal();
				if (obj == null) {
					continue;
				} else if (obj is IAsn1) {
					r.Add(((IAsn1)obj).ToAsn1());
				} else if (obj is string) {
					r.Add(MDer.Build((string)obj));
				} else {
					throw new FormatException("unexpected parameter type: " + obj.GetType().FullName);
				}
			} else {
				bool eof;
				AsnElt ae = BuildNext(out eof);
				if (eof) {
					break;
				}
				if (ae != null) {
					r.Add(ae);
				}
			}
		}

		if (r.Count == 0 && noEmpty) {
			return null;
		}

		try {
			AsnElt[] subs = r.ToArray();
			if (order == ORDER_TAG) {
				return AsnElt.MakeImplicit(tagValue,
					AsnElt.MakeSetDER(subs));
			} else if (order == ORDER_VALUE) {
				return AsnElt.MakeImplicit(tagValue,
					AsnElt.MakeSetOf(subs));
			} else {
				return AsnElt.Make(tagValue, subs);
			}
		} catch (AsnException ex) {
			throw new FormatException(ex.Message);
		}
	}

	void ReadMultiple(List<AsnElt> r, string spec)
	{
		// Find all referenced parameters in the specification
		// whose value implements IEnumerable. The string gathering
		// process replaced all whitespace with simple spaces,
		// hence removing the comments; we only have to take care
		// of literal strings here.
		IEnumerator[] ee = new IEnumerator[pp.Length];

		int n = spec.Length;
		bool inString = false;
		bool hasEnum = false;
		for (int i = 0; i < n; i ++) {
			int c = spec[i];
			if (inString) {
				if (c == '\\') {
					i ++;
				} else if (c == '"') {
					inString = false;
				}
				continue;
			}
			if (c == '"') {
				inString = true;
				continue;
			}
			if (c != '%') {
				continue;
			}
			int x = 0;
			bool hasDigit = false;
			for (;;) {
				if ((i + 1) >= n) {
					break;
				}
				c = spec[i + 1];
				if (!IsDigit(c)) {
					break;
				}
				i ++;
				hasDigit = true;
				if (x > 214748364) {
					throw new FormatException("parameter number overflow");
				}
				x *= 10;
				c -= '0';
				if (x > 2147483647 - c) {
					throw new FormatException("parameter number overflow");
				}
				x += c;
			}
			if (!hasDigit) {
				throw new FormatException("missing parameter number");
			}
			if (x >= pp.Length) {
				throw new FormatException(string.Format("invalid parameter number: {0} (max: {1})", x, pp.Length - 1));
			}
			if (ee[x] == null && pp[x] is IEnumerable) {
				ee[x] = ((IEnumerable)pp[x]).GetEnumerator();
				hasEnum = true;
			}
		}

		// If there is no IEnumerable in the spec, then we can
		// simply return (this happens when all relevant parameters
		// are null, which is taken to have the same meaning as an
		// empty collection).
		if (!hasEnum) {
			return;
		}

		// We must now parse the specification repeatedly, replacing
		// the relevant parameter values with what the enumerators
		// return.
		TextReader oldInput = input;
		int oldLookAhead = lookAhead;
		object[] oldPp = pp;

		pp = new object[pp.Length];
		bool finished = false;
		for (;;) {
			// Get next objects from enumerators. Exit if one
			// of the enumerators is exhausted.
			for (int i = 0; i < ee.Length; i ++) {
				if (ee[i] == null) {
					continue;
				}
				if (!ee[i].MoveNext()) {
					finished = true;
					break;
				}
				pp[i] = ee[i].Current;
			}
			if (finished) {
				break;
			}

			// Parse the specification and build the next
			// sub-object.
			input = new StringReader(spec);
			lookAhead = -1;
			AsnElt ae = Build();
			if (ae != null) {
				r.Add(ae);
			}
		}

		// We are finished; restore the saved contents.
		input = oldInput;
		lookAhead = oldLookAhead;
		pp = oldPp;
	}

	/*
	 * This function reads the next object. It may return null in
	 * case an object reference or structure was read, but ultimately
	 * was found to be optional and absent (i.e. relying on a parameter
	 * whose value is null). If the end of the current level is reached,
	 * then 'eof' is set to true and null is returned; otherwise, 'eof'
	 * is set to false.
	 */
	AsnElt BuildNext(out bool eof)
	{
		eof = false;
		int c = PeekNextChar();

		if (c == '%') {
			object obj = ReadParamVal();
			if (obj == null) {
				return null;
			}
			if (obj is IAsn1) {
				return ((IAsn1)obj).ToAsn1();
			}
			throw new FormatException("unexpected parameter type: " + obj.GetType().FullName);
		}

		// If we do not get an opening parenthesis, then this is
		// the last value at this level (caller should check that
		// it got the expected closing parenthesis).
		if (c != '(') {
			eof = true;
			return null;
		}
		LowRead();
		c = PeekNextChar();

		// Read an optional tag specification.
		int tagClass = -1;
		int tagValue = -1;
		if (c == '[') {
			LowRead();
			c = PeekNextChar();
			object obj1;
			if (c == '%') {
				obj1 = ReadParamVal();
			} else if (IsWordChar(c)) {
				obj1 = ReadWord();
			} else {
				throw new FormatException("expected tag class/value");
			}
			c = PeekNextChar();
			object obj2;
			if (c == '%') {
				obj2 = ReadParamVal();
			} else if (c == ']') {
				obj2 = null;
			} else if (IsWordChar(c)) {
				obj2 = ReadWord();
			} else {
				throw new FormatException("expected tag value");
			}
			c = NextChar();
			if (c != ']') {
				throw new FormatException("invalid tag specification");
			}
			if (obj2 == null) {
				tagValue = ReadTagValue(obj1, out tagClass);
			} else {
				tagClass = ReadTagClass(obj1);
				tagValue = ReadTagValue(obj2);
			}
			c = PeekNextChar();
		}

		// Check for a truncated input.
		if (c < 0) {
			throw new FormatException("truncated input");
		}

		// Now we should have a type name or a nested ASN.1
		// object (in the latter case, the specified tag is an
		// implicit tag). Since there was an explicit opening
		// parenthesis, then we need to match a closing
		// parenthesis.
		if (c == '%') {
			object obj = ReadParamVal();
			c = NextChar();
			if (c != ')') {
				throw new FormatException("missing closing parenthesis");
			}
			if (obj is IAsn1) {
				AsnElt ae = ((IAsn1)obj).ToAsn1();
				if (tagClass >= 0) {
					ae = AsnElt.MakeImplicit(
						tagClass, tagValue, ae);
				}
				return ae;
			}
			if (obj == null) {
				return null;
			}
			throw new FormatException("unexpected parameter type: " + obj.GetType().FullName);
		}

		// Read a type name.
		string tn = ReadWord();
		AsnElt ret;
		switch (tn.ToLowerInvariant()) {
		case "bool":
		case "boolean":
			ret = ReadBoolean();
			break;
		case "int":
		case "integer":
			ret = ReadInteger();
			break;
		case "enum":
		case "enumerated":
			ret = ReadInteger();
			if (ret != null) {
				ret = AsnElt.MakeImplicit(
					AsnElt.UNIVERSAL, AsnElt.ENUMERATED,
					ret);
			}
			break;
		case "bits":
			ret = ReadBitString();
			break;
		case "blob":
		case "bytes":
			ret = ReadOctetString();
			break;
		case "null":
			ret = AsnElt.NULL_V;
			break;
		case "oid":
			ret = ReadOID();
			break;
		case "numeric":
		case "numericstring":
			ret = ReadString(AsnElt.NumericString);
			break;
		case "printable":
		case "printablestring":
			ret = ReadString(AsnElt.PrintableString);
			break;
		case "ia5":
		case "ia5string":
			ret = ReadString(AsnElt.IA5String);
			break;
		case "teletex":
		case "teletexstring":
			ret = ReadString(AsnElt.TeletexString);
			break;
		case "genstring":
		case "generalstring":
			ret = ReadString(AsnElt.GeneralString);
			break;
		case "utf8":
		case "utf-8":
		case "utf8string":
			ret = ReadString(AsnElt.UTF8String);
			break;
		case "utf16":
		case "utf-16":
		case "bmp":
		case "bmpstring":
			ret = ReadString(AsnElt.BMPString);
			break;
		case "utf32":
		case "utf-32":
		case "universal":
		case "universalstring":
			ret = ReadString(AsnElt.UniversalString);
			break;
		case "utc":
		case "utctime":
			ret = ReadTime(AsnElt.UTCTime);
			break;
		case "gentime":
		case "generalizedtime":
			ret = ReadTime(AsnElt.GeneralizedTime);
			break;
		case "set":
			ret = ReadConstructed(AsnElt.SET, false, 0);
			break;
		case "sequence":
			ret = ReadConstructed(AsnElt.SEQUENCE, false, 0);
			break;
		case "setder":
			ret = ReadConstructed(AsnElt.SET, false, ORDER_TAG);
			break;
		case "setof":
			ret = ReadConstructed(AsnElt.SET, false, ORDER_VALUE);
			break;
		case "set-nz":
			ret = ReadConstructed(AsnElt.SET, true, 0);
			break;
		case "sequence-nz":
			ret = ReadConstructed(AsnElt.SEQUENCE, true, 0);
			break;
		case "setder-nz":
			ret = ReadConstructed(AsnElt.SET, true, ORDER_TAG);
			break;
		case "setof-nz":
			ret = ReadConstructed(AsnElt.SET, true, ORDER_VALUE);
			break;
		case "tag":
			if (tagClass < 0) {
				throw new FormatException("missing tag specification");
			}
			bool z2;
			ret = BuildNext(out z2);
			if (z2) {
				throw new FormatException("missing value for tag");
			}
			if (ret != null) {
				ret = AsnElt.Make(tagClass, tagValue, ret);
			}
			break;
		default:
			throw new FormatException("unknown type name: " + tn);
		}
		if (NextChar() != ')') {
			throw new FormatException("expected closing parenthesis");
		}

		/*
		 * Apply the implicit tag, if any.
		 */
		if (ret != null && tagClass >= 0) {
			ret = AsnElt.MakeImplicit(tagClass, tagValue, ret);
		}
		return ret;
	}

	static int ReadTagClass(object obj)
	{
		if (obj is int) {
			int tc = (int)obj;
			if (tc < 0 || tc > 3) {
				throw new FormatException("invalid tag class: " + tc);
			}
			return tc;
		} else if (obj is string) {
			string w = (string)obj;
			switch (w.ToLowerInvariant()) {
			case "univ":
			case "universal":
				return AsnElt.UNIVERSAL;
			case "app":
			case "application":
				return AsnElt.APPLICATION;
			case "context":
				return AsnElt.CONTEXT;
			case "priv":
			case "private":
				return AsnElt.PRIVATE;
			}
			int tc;
			if (Int32.TryParse(w, out tc) && tc >= 0 && tc <= 3) {
				return tc;
			}
			throw new FormatException("unknown tag class: " + w);
		} else {
			if (obj == null) {
				throw new FormatException("invalid tag class (null)");
			} else {
				throw new FormatException("invalid type for tag class: " + obj.GetType().FullName);
			}
		}
	}

	static int ReadTagValue(object obj)
	{
		int x;
		return ReadTagValue(obj, out x);
	}

	static int ReadTagValue(object obj, out int defTagClass)
	{
		if (obj is int) {
			int tv = (int)obj;
			if (tv < 0) {
				throw new FormatException("invalid tag value: " + tv);
			}
			defTagClass = AsnElt.CONTEXT;
			return tv;
		} else if (obj is string) {
			defTagClass = AsnElt.UNIVERSAL;
			string w = (string)obj;
			switch (w.ToLowerInvariant()) {
			case "bool":
			case "boolean":
				return AsnElt.BOOLEAN;
			case "int":
			case "integer":
				return AsnElt.INTEGER;
			case "bits":
			case "bitstring":
			case "bit-string":
				return AsnElt.BIT_STRING;
			case "bytes":
			case "blob":
			case "octet-string":
				return AsnElt.OCTET_STRING;
			case "null":
				return AsnElt.NULL;
			case "oid":
			case "object-identifier":
				return AsnElt.OBJECT_IDENTIFIER;
			case "enum":
			case "enumerated":
				return AsnElt.ENUMERATED;
			case "sequence":
				return AsnElt.SEQUENCE;
			case "set":
				return AsnElt.SET;
			case "numeric":
			case "numericstring":
				return AsnElt.NumericString;
			case "printable":
			case "printablestring":
				return AsnElt.PrintableString;
			case "ia5":
			case "ia5string":
				return AsnElt.IA5String;
			case "teletex":
			case "telextexstring":
				return AsnElt.TeletexString;
			case "genstring":
			case "generalstring":
				return AsnElt.GeneralString;
			case "utf8":
			case "utf-8":
			case "utf8string":
				return AsnElt.UTF8String;
			case "utf16":
			case "utf-16":
			case "bmp":
			case "bmpstring":
				return AsnElt.BMPString;
			case "utf32":
			case "utf-32":
			case "universal":
			case "universalstring":
				return AsnElt.UniversalString;
			case "utc":
			case "utctime":
				return AsnElt.UTCTime;
			case "gentime":
			case "generalizedtime":
				return AsnElt.GeneralizedTime;
			}
			int tv;
			if (Int32.TryParse(w, out tv) && tv >= 0) {
				defTagClass = AsnElt.CONTEXT;
				return tv;
			}
			throw new FormatException("unknown tag value: " + w);
		} else {
			if (obj == null) {
				throw new FormatException("invalid tag value (null)");
			} else {
				throw new FormatException("invalid type for tag value: " + obj.GetType().FullName);
			}
		}
	}

	void SetParam<T>(int off, T val)
	{
		if (paramAccumulate) {
			IList<T> r;
			if (pp[off] == null) {
				r = new List<T>();
				pp[off] = r;
			} else {
				r = (IList<T>)pp[off];
			}
			r.Add(val);
		} else {
			pp[off] = val;
		}
	}

	/*
	 * Treatment of a string (when parsing); tag has already been matched.
	 */
	void ParseString(AsnElt d, int stringType)
	{
		string dstr = d.GetString(stringType);
		if (PeekNextChar() == '%') {
			SetParam(ReadParamRef(), dstr);
		} else {
			string hstr = ReadLiteralString();
			if (StringComparer.Ordinal.Compare(dstr, hstr) != 0) {
				throw new AsnException(string.Format("mismatch on string value: got '{0}' (expected '{1}')", dstr, hstr));
			}
		}
	}

	/*
	 * Treatment of a date (when parsing); tag has already been matched.
	 */
	void ParseTime(AsnElt d, int timeType)
	{
		if (PeekNextChar() == '%') {
			SetParam(ReadParamRef(), d.GetTime(timeType));
		} else {
			// Value is provided as a literal string; we do an
			// exact string match.
			string dt = d.GetString(timeType);
			string ht = ReadLiteralString();
			if (StringComparer.Ordinal.Compare(dt, ht) != 0) {
				throw new AsnException(string.Format("mismatch on time value: got '{0}' (expected '{1}')", dt, ht));
			}
		}
	}

	/*
	 * Skip a replacement action, if present. This is called after
	 * matching an object spec.
	 */
	void SkipReplacement()
	{
		int c = PeekNextChar();
		if (c != ':') {
			return;
		}
		LowRead();
		c = NextChar();
		if (c != '(') {
			throw new FormatException("invalid replacement action syntax");
		}
		FindClosingParenthesis(null);
	}

	/*
	 * Read an apply some replacement actions. Upon entry, the next
	 * character to read should be the ':'.
	 */
	void ApplyReplacement()
	{
		if (NextChar() != ':' || NextChar() != '(') {
			throw new FormatException("invalid replacement action syntax");
		}
		for (;;) {
			int c = PeekNextChar();
			if (c == ')') {
				LowRead();
				break;
			}
			int idx = ReadParamRef();
			c = NextChar();
			if (c != '(') {
				throw new FormatException("invalid replacement action syntax");
			}
			string vn = ReadWord();
			switch (vn.ToLowerInvariant()) {
			case "asn":
			case "asn1":
				MDer md = new MDer(input, pp);
				md.lookAhead = lookAhead;
				AsnElt ad0 = md.Build();
				lookAhead = md.lookAhead;
				SetParam(idx, ad0);
				break;
			case "boolean":
			case "bool":
				SetParam(idx, ReadLiteralBoolean());
				break;
			case "integer":
			case "int":
				SetParam(idx, ReadLiteralInteger());
				break;
			case "bytes":
			case "blob":
				SetParam(idx, ReadLiteralBlobContents());
				break;
			case "oid":
				SetParam(idx, ReadLiteralOID());
				break;
			case "numeric":
			case "numericstring":
			case "printable":
			case "printablestring":
			case "ia5":
			case "ia5string":
			case "teletex":
			case "teletexstring":
			case "genstring":
			case "generalstring":
			case "utf8":
			case "utf-8":
			case "utf8string":
			case "utf16":
			case "utf-16":
			case "bmp":
			case "bmpstring":
			case "utf32":
			case "utf-32":
			case "universal":
			case "universalstring":
				SetParam(idx, ReadLiteralString());
				break;
			case "utc":
			case "utctime":
				AsnElt ad1 = AsnElt.MakeString(
					AsnElt.UTCTime,
					ReadLiteralString());
				SetParam(idx,
					ad1.GetTime(AsnElt.UTCTime));
				break;
			case "gentime":
			case "generalizedtime":
				AsnElt ad2 = AsnElt.MakeString(
					AsnElt.GeneralizedTime,
					ReadLiteralString());
				SetParam(idx,
					ad2.GetTime(AsnElt.GeneralizedTime));
				break;
			default:
				throw new FormatException("unknown type in replacement action: " + vn);
			}
			c = NextChar();
			if (c != ')') {
				throw new FormatException("invalid replacement action syntax");
			}
		}
	}

	/*
	 * This function reads the next specification element for parsing.
	 * Source object is the provided array of elements, starting at the
	 * provided offset; returned value is the new offset.
	 */
	int Parse(AsnElt[] ae, int off)
	{
		int c = PeekNextChar();

		// '*' or '+' must be followed by a parameter ref, '.',
		// or an opening parenthesis.
		if (c == '*' || c == '+') {
			if (c == '+' && off >= ae.Length) {
				throw new AsnException("missing non-optional value");
			}
			LowRead();
			c = PeekNextChar();
			if (c == '.') {
				LowRead();
			} else if (c == '%') {
				int idx = ReadParamRef();
				bool oldAcc = paramAccumulate;
				paramAccumulate = true;
				while (off < ae.Length) {
					SetParam(idx, ae[off ++]);
				}
				paramAccumulate = oldAcc;
			} else if (c == '(') {
				// Get the spec for the repeated object.
				LowRead();
				StringBuilder sb = new StringBuilder();
				sb.Append('(');
				FindClosingParenthesis(sb);
				string spec = sb.ToString();

				// Remember the current state.
				bool oldAcc = paramAccumulate;
				TextReader oldInput = input;
				int oldLookAhead = lookAhead;

				// Apply the spec on the objects, repeatedly.
				// Since the spec starts with '(', i.e. a
				// non-optional object, each invocation will
				// necessarily use one object.
				paramAccumulate = true;
				while (off < ae.Length) {
					input = new StringReader(spec);
					lookAhead = -1;
					off = Parse(ae, off);
				}

				// Restore the state.
				paramAccumulate = oldAcc;
				input = oldInput;
				lookAhead = oldLookAhead;
			} else {
				throw new FormatException("invalid multiple-match operator");
			}
			off = ae.Length;
			return off;
		}

		// '?' is for an optional value.
		bool optional = false;
		if (c == '?') {
			LowRead();
			optional = true;
			c = PeekNextChar();
		}

		// Single parameter reference.
		if (c == '%') {
			int idx = ReadParamRef();
			if (!optional && off >= ae.Length) {
				throw new AsnException("missing non-optional value");
			}
			SetParam(idx, ae[off ++]);
			SkipReplacement();
			return off;
		}

		// Single 'ignore' value.
		if (c == '.') {
			LowRead();
			if (!optional && off >= ae.Length) {
				throw new AsnException("missing non-optional value");
			}
			off ++;
			SkipReplacement();
			return off;
		}

		// At this point we should have an opening parenthesis for
		// a "true" sub-object.
		if (c != '(') {
			throw new FormatException("expected opening parenthesis");
		}
		LowRead();
		c = PeekNextChar();

		// Read an optional tag specification.
		//   (no spec)             match anything
		//   string                match UNIVERSAL + tag value
		//   int                   match CONTEXT + tag value
		//   param-ref             match CONTEXT, read tag value
		//   string string         match tag class + tag value
		//   string int            match tag class + tag value
		//   int string            match tag class + tag value
		//   int int               match tag class + tag value
		//   string param-ref      match tag class, read tag value
		//   int param-ref         match tag class, read tag value
		//   param-ref param-ref   read tag class, read tag value
		int matchClass = -1;
		int readClassIdx = -1;
		int matchValue = -1;
		int readValueIdx = -1;
		bool hasTagSpec = false;
		if (c == '[') {
			hasTagSpec = true;
			LowRead();
			c = PeekNextChar();
			int idx1 = -1;
			int idx2 = -1;
			string w1 = null;
			string w2 = null;
			if (c == '%') {
				idx2 = ReadParamRef();
				c = PeekNextChar();
			} else if (IsWordChar(c)) {
				w2 = ReadWord();
				c = PeekNextChar();
			}
			if (c == '%') {
				idx1 = idx2;
				w1 = w2;
				idx2 = ReadParamRef();
				w2 = null;
			} else if (IsWordChar(c)) {
				idx1 = idx2;
				w1 = w2;
				idx2 = -1;
				w2 = ReadWord();
			}
			c = NextChar();
			if (c != ']') {
				throw new FormatException("invalid tag specification");
			}

			if (idx1 >= 0) {
				// param-ref param-ref
				if (idx2 >= 0) {
					readClassIdx = idx1;
					readValueIdx = idx2;
				} else {
					throw new FormatException("invalid tag specification");
				}
			} else if (w1 != null) {
				// string string
				// string int
				// int string
				// int int
				// string param-ref
				// int param-ref
				matchClass = ReadTagClass(w1);
				if (idx2 >= 0) {
					readValueIdx = idx2;
				} else {
					matchValue = ReadTagValue(w2);
				}
			} else if (idx2 >= 0) {
				// param-ref
				matchClass = AsnElt.CONTEXT;
				readValueIdx = idx2;
			} else if (w2 != null) {
				// string
				// int
				matchValue = ReadTagValue(w2, out matchClass);
			} else {
				throw new FormatException("invalid tag specification");
			}

			c = PeekNextChar();
		}

		// We now should have either a dot, a parameter reference,
		// or a keyword. For a keyword, we normalize the word, and
		// we use it to complete the expected tag class and value.
		int paramIdx = -1;
		string tn;
		bool expectValue = false;
		bool expectSeveralValues = false;
		bool noEmpty = false;
		if (c == '.') {
			LowRead();
			tn = ".";
		} else if (c == '%') {
			paramIdx = ReadParamRef();
			tn = ".";
		} else {
			expectValue = true;
			tn = ReadWord();
			int ktag = -1;
			switch (tn.ToLowerInvariant()) {
			case "bool":
			case "boolean":
				tn = "bool";
				ktag = AsnElt.BOOLEAN;
				break;
			case "int":
			case "integer":
				tn = "int";
				ktag = AsnElt.INTEGER;
				break;
			case "enum":
			case "enumerated":
				tn = "enum";
				ktag = AsnElt.ENUMERATED;
				break;
			case "bits":
				// 'bits' expects two values (number of ignored
				// bits, and the value bits)
				tn = "bits";
				ktag = AsnElt.BIT_STRING;
				expectSeveralValues = true;
				break;
			case "blob":
			case "bytes":
				tn = "blob";
				ktag = AsnElt.OCTET_STRING;
				break;
			case "null":
				// Note: 'null' does not expect a value.
				tn = "null";
				ktag = AsnElt.NULL;
				expectValue = false;
				break;
			case "oid":
				tn = "oid";
				ktag = AsnElt.OBJECT_IDENTIFIER;
				break;
			case "numeric":
			case "numericstring":
				tn = "numeric";
				ktag = AsnElt.NumericString;
				break;
			case "printable":
			case "printablestring":
				tn = "printable";
				ktag = AsnElt.PrintableString;
				break;
			case "ia5":
			case "ia5string":
				tn = "ia5";
				ktag = AsnElt.IA5String;
				break;
			case "teletex":
			case "teletexstring":
				tn = "teletex";
				ktag = AsnElt.TeletexString;
				break;
			case "genstring":
			case "generalstring":
				tn = "genstring";
				ktag = AsnElt.GeneralString;
				break;
			case "utf8":
			case "utf-8":
			case "utf8string":
				tn = "utf8";
				ktag = AsnElt.UTF8String;
				break;
			case "utf16":
			case "utf-16":
			case "bmp":
			case "bmpstring":
				tn = "bmp";
				ktag = AsnElt.BMPString;
				break;
			case "utf32":
			case "utf-32":
			case "universal":
			case "universalstring":
				tn = "utf32";
				ktag = AsnElt.UniversalString;
				break;
			case "utc":
			case "utctime":
				tn = "utc";
				ktag = AsnElt.UTCTime;
				break;
			case "gentime":
			case "generalizedtime":
				tn = "gentime";
				ktag = AsnElt.GeneralizedTime;
				break;
			case "set":
			case "setder":
			case "setof":
				tn = "set";
				ktag = AsnElt.SET;
				expectSeveralValues = true;
				break;
			case "sequence":
				tn = "sequence";
				ktag = AsnElt.SEQUENCE;
				expectSeveralValues = true;
				break;
			case "set-nz":
			case "setder-nz":
			case "setof-nz":
				tn = "set";
				ktag = AsnElt.SET;
				expectSeveralValues = true;
				noEmpty = true;
				break;
			case "sequence-nz":
				tn = "sequence";
				ktag = AsnElt.SEQUENCE;
				expectSeveralValues = true;
				noEmpty = true;
				break;
			case "tag":
				tn = "tag";
				if (!hasTagSpec) {
					throw new FormatException("no tag specified for tag construct");
				}
				break;
			default:
				throw new FormatException("unknown type keyword: " + tn);
			}

			if (!hasTagSpec) {
				matchClass = AsnElt.UNIVERSAL;
				matchValue = ktag;
			}
		}

		// Match the tag.
		bool skipValue = false;
		AsnElt d = null;
		if (off >= ae.Length) {
			skipValue = true;
		} else {
			d = ae[off];
			int tc = d.TagClass;
			int tv = d.TagValue;
			if ((matchClass != -1 && matchClass != tc)
				|| (matchValue != -1 && matchValue != tv))
			{
				skipValue = true;
			} else {
				if (readClassIdx >= 0) {
					SetParam(readClassIdx, (ZInt)tc);
				}
				if (readValueIdx >= 0) {
					SetParam(readValueIdx, (ZInt)tv);
				}
			}
		}

		// On mismatch, we complain, unless the value is marked
		// optional, in which case we should skip it. Skipping
		// implies finding the matching closing parenthesis in
		// the next input, taking care not to match parentheses
		// that occur in literal strings.
		if (skipValue) {
			if (!optional) {
				throw new AsnException("missing non-optional value");
			}
			FindClosingParenthesis(null);
			c = PeekNextChar();
			if (c == ':') {
				// There is a replacement action, we apply it.
				ApplyReplacement();
			}
			return off;
		}

		// Tag is correct. Matched object is in 'd'.
		off ++;

		// Now we know that the value is present, and the tag
		// was processed. We harvest or match the value. The
		// value may be '.' (ignored), a parameter ref, a literal
		// to match, or sub-objects to explore.
		c = PeekNextChar();
		if (expectValue && !expectSeveralValues) {
			if (c == '.') {
				LowRead();
				c = PeekNextChar();
				tn = ".";
			}
		}
		switch (tn) {
		case ".":
			// This case covers both ignored values, and
			// raw parameter references.
			if (paramIdx >= 0) {
				SetParam(paramIdx, d);
			}
			break;
		case "bool":
			bool dbool = d.GetBoolean();
			if (c == '%') {
				SetParam(ReadParamRef(), dbool);
			} else {
				if (ReadLiteralBoolean() != dbool) {
					throw new AsnException("mismatch on BOOLEAN value");
				}
			}
			break;
		case "int":
			ZInt dint = d.GetLargeInteger();
			if (c == '%') {
				SetParam(ReadParamRef(), dint);
			} else {
				if (ReadLiteralInteger() != dint) {
					throw new AsnException("mismatch on INTEGER value");
				}
			}
			break;
		case "enum":
			ZInt denum = d.GetLargeInteger();
			if (c == '%') {
				SetParam(ReadParamRef(), denum);
			} else {
				if (ReadLiteralInteger() != denum) {
					throw new AsnException("mismatch on ENUMERATED value");
				}
			}
			break;
		case "bits":
			int dbitsnum;
			byte[] dbits = d.GetBitString(out dbitsnum);
			if (c == '%') {
				SetParam(ReadParamRef(), (ZInt)dbitsnum);
			} else if (c == '.') {
				LowRead();
			} else {
				if (dbitsnum != Int32.Parse(ReadWord())) {
					throw new AsnException("mismatch on BIT STRING value (number of ignored bits)");
				}
			}
			c = PeekNextChar();
			if (c == '%') {
				SetParam(ReadParamRef(), dbits);
			} else if (c == '.') {
				LowRead();
			} else if (c == '(') {
				if (dbitsnum != 0) {
					throw new AsnException("mismatch on BIT STRING value (partial final byte for DER)");
				}
				Parse(AsnElt.Decode(dbits));
			} else {
				byte[] hbits = ReadLiteralBlobContents();
				if (!Equals(dbits, hbits)) {
					throw new AsnException("mismatch on BIT STRING value (bits value)");
				}
			}
			break;
		case "blob":
			byte[] dblob = d.GetOctetString();
			if (c == '%') {
				SetParam(ReadParamRef(), dblob);
			} else if (c == '(') {
				Parse(AsnElt.Decode(dblob));
			} else {
				byte[] hblob = ReadLiteralBlobContents();
				if (!Equals(dblob, hblob)) {
					throw new AsnException("mismatch on OCTET STRING value");
				}
			}
			break;
		case "null":
			d.CheckNull();
			break;
		case "oid":
			string doid = d.GetOID();
			if (c == '%') {
				SetParam(ReadParamRef(), doid);
			} else {
				string hoid = ReadLiteralOID();
				if (doid != hoid) {
					throw new AsnException("mismatch on OBJECT IDENTIFIER value");
				}
			}
			break;
		case "numeric":
			ParseString(d, AsnElt.NumericString);
			break;
		case "printable":
			ParseString(d, AsnElt.PrintableString);
			break;
		case "ia5":
			ParseString(d, AsnElt.IA5String);
			break;
		case "teletex":
			ParseString(d, AsnElt.TeletexString);
			break;
		case "genstring":
			ParseString(d, AsnElt.GeneralString);
			break;
		case "utf8":
			ParseString(d, AsnElt.UTF8String);
			break;
		case "bmp":
			ParseString(d, AsnElt.BMPString);
			break;
		case "utf32":
			ParseString(d, AsnElt.UniversalString);
			break;
		case "utc":
			ParseTime(d, AsnElt.UTCTime);
			break;
		case "gentime":
			ParseTime(d, AsnElt.GeneralizedTime);
			break;
		case "sequence":
		case "set":
			d.CheckConstructed();
			if (noEmpty && d.Sub.Length == 0) {
				throw new AsnException("mismatch in constructed value (empty)");
			}
			int doff = 0;
			while (PeekNextChar() != ')') {
				doff = Parse(d.Sub, doff);
			}
			if (doff < d.Sub.Length) {
				throw new AsnException("mismatch in constructed value (extra elements)");
			}
			break;
		case "tag":
			d.CheckNumSub(1);
			if (c == '%') {
				SetParam(ReadParamRef(), d.GetSub(0));
			} else if (c == '(') {
				Parse(d.GetSub(0));
			} else {
				throw new FormatException(string.Format("unexpected character U+{0:X4} in tag value", c));
			}
			break;
		default:
			throw new FormatException("unknown type name: " + tn);
		}
		if (NextChar() != ')') {
			throw new FormatException("expected closing parenthesis");
		}

		SkipReplacement();
		return off;
	}

	static bool Equals(byte[] b1, byte[] b2)
	{
		if (b1 == null && b2 == null) {
			return true;
		}
		if (b1 == null || b2 == null) {
			return false;
		}
		int n = b1.Length;
		if (n != b2.Length) {
			return false;
		}
		for (int i = 0; i < n; i ++) {
			if (b1[i] != b2[i]) {
				return false;
			}
		}
		return true;
	}

	static MDer()
	{
		for (int c = 'A'; c <= 'Z'; c ++) {
			WORD_CHAR[c] = true;
		}
		for (int c = 'a'; c <= 'z'; c ++) {
			WORD_CHAR[c] = true;
		}
		for (int c = '0'; c <= '9'; c ++) {
			WORD_CHAR[c] = true;
		}
		foreach (char c in WORD_EXTRA_CHARS) {
			WORD_CHAR[c] = true;
		}
	}
}

}
