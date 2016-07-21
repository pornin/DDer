using System;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using System.Text;

using Asn1;

public class MDer {

	static TextReader input;
	static int lookAhead = -1;

	public static void Main(string[] args)
	{
		try {
			if (args.Length != 2) {
				Usage();
			}
			string iname = args[0];
			string oname = args[1];
			if (iname == "-") {
				input = Console.In;
			} else {
				input = new StreamReader(
					File.OpenRead(iname), true);
			}
			Stream output;
			if (oname == "-") {
				output = Console.OpenStandardOutput();
			} else {
				output = File.Create(oname);
			}
			for (;;) {
				AsnElt ae = BuildNext();
				if (ae == null) {
					break;
				}
				byte[] enc = ae.Encode();
				output.Write(enc, 0, enc.Length);
			}
			if (LowPeek() >= 0) {
				throw new IOException(
					"trailing garbage on input");
			}
			output.Close();
		} catch (Exception e) {
			Console.Error.WriteLine(e.ToString());
			Environment.Exit(1);
		}
	}

	static void Usage()
	{
		Console.Error.WriteLine(
"usage: mder.exe input output");
		Environment.Exit(1);
	}

	static bool IsWS(int c)
	{
		return c <= 32 || c == 160;
	}

	static bool[] WORD_CHAR = new bool[128];
	const string WORD_EXTRA_CHARS = "$_-+.,";

	static bool IsWordChar(int c)
	{
		return c >= 0 && c < 128 && WORD_CHAR[c];
	}

	static int LowPeek()
	{
		if (lookAhead < 0) {
			lookAhead = input.Read();
		}
		return lookAhead;
	}

	static int LowRead()
	{
		int v = LowPeek();
		lookAhead = -1;
		return v;
	}

	static int PeekNextChar()
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

	static int NextChar()
	{
		int c = PeekNextChar();
		if (c >= 0) {
			LowRead();
		}
		return c;
	}

	static string ParseWord(int fc)
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

	static string ParseWord()
	{
		int fc = NextChar();
		if (fc < 0) {
			throw new IOException("truncated input");
		}
		if (!IsWordChar(fc)) {
			throw new IOException(String.Format(
				"unexpected U+{0:X4} character", fc));
		}
		return ParseWord(fc);
	}

	static int HexValue(int c)
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

	static int ReadHexChar()
	{
		int c = LowRead();
		if (c < 0) {
			throw new IOException("truncated input:"
				+ " unfinished string literal");
		}
		int d = HexValue(c);
		if (d < 0) {
			throw new IOException(String.Format("invalid character"
				+ " U+{0:X4}, expecting hex digit", c));
		}
		return d;
	}

	static string ParseString()
	{
		int c = NextChar();
		if (c < 0) {
			throw new IOException("missing string literal");
		}
		if (IsWordChar(c)) {
			return ParseWord(c);
		}
		if (c != '"') {
			throw new IOException("not a string literal");
		}
		StringBuilder sb = new StringBuilder();
		bool lwb = false;
		for (;;) {
			c = LowRead();
			if (c < 0) {
				throw new IOException("truncated input:"
					+ " unfinished string literal");
			}
			if (lwb) {
				switch ((char)c) {
				case 'n': c = '\n'; break;
				case 't': c = '\t'; break;
				case 'r': c = '\r'; break;
				case 'u':
					c = ReadHexChar();
					c = (c << 4) + ReadHexChar();
					c = (c << 4) + ReadHexChar();
					c = (c << 4) + ReadHexChar();
					break;
				}
				sb.Append((char)c);
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
	 * Build next element; will return null if (and only if) the next
	 * non-whitespace character is not an opening parenthesis.
	 */
	static AsnElt BuildNext()
	{
		int c = PeekNextChar();
		if (c != '(') {
			return null;
		}
		LowRead();
		c = NextChar();
		int tagClass = -1;
		int tagValue = -1;
		if (c == '[') {
			c = NextChar();
			if (!IsWordChar(c)) {
				throw new IOException(
					"expected tag class/value");
			}
			string w1 = ParseWord(c);
			c = NextChar();
			string w2 = null;
			if (IsWordChar(c)) {
				w2 = ParseWord(c);
				c = NextChar();
			}
			if (c != ']') {
				throw new IOException(
					"invalid tag specification");
			}
			if (w2 == null) {
				tagClass = AsnElt.CONTEXT;
				tagValue = ParseTagValue(w1);
			} else {
				tagClass = ParseTagClass(w1);
				tagValue = ParseTagValue(w2);
			}
			c = NextChar();
		}
		if (c < 0) {
			throw new IOException("truncated input");
		}
		if (!IsWordChar(c)) {
			throw new IOException("expected type name");
		}
		string tn = ParseWord(c);
		AsnElt ret;
		switch (tn.ToLowerInvariant()) {
		case "bool":
		case "boolean":
			string bv = ParseWord();
			switch (bv.ToLowerInvariant()) {
			case "true":
			case "on":
			case "yes":
			case "1":
				ret = AsnElt.BOOL_TRUE;
				break;
			case "false":
			case "off":
			case "no":
			case "0":
				ret = AsnElt.BOOL_FALSE;
				break;
			default:
				throw new IOException(
					"invalid boolean value: " + bv);
			}
			break;
		case "int":
		case "integer":
			string iv = ParseWord();
			ret = BuildInteger(iv);
			break;
		case "bits":
			string ibw = ParseWord();
			int ignb;
			if (!Int32.TryParse(ibw, out ignb)
				|| ignb < 0 || ignb > 7)
			{
				throw new IOException("invalid number of"
					+ " ignored bits: " + ibw);
			}
			byte[] bsb = ParseHexBytes();
			int imask = 0xFF >> (8 - ignb);
			if (ignb > 0 && (bsb.Length == 0
				|| (bsb[bsb.Length - 1] & imask) != 0))
			{
				throw new IOException("non-zero ignored bits");
			}
			ret = AsnElt.MakeBitString(ignb, bsb);
			break;
		case "blob":
		case "bytes":
			ret = AsnElt.MakeBlob(ParseHexBytes());
			break;
		case "null":
			ret = AsnElt.NULL_V;
			break;
		case "oid":
			string oid = AsnOID.ToOID(ParseWord());
			ret = AsnElt.MakeOID(oid);
			break;
		case "numeric":
		case "numericstring":
			ret = AsnElt.MakeString(
				AsnElt.NumericString, ParseString());
			break;
		case "printable":
		case "printablestring":
			ret = AsnElt.MakeString(
				AsnElt.PrintableString, ParseString());
			break;
		case "ia5":
		case "ia5string":
			ret = AsnElt.MakeString(
				AsnElt.IA5String, ParseString());
			break;
		case "teletex":
		case "teletexstring":
			ret = AsnElt.MakeString(
				AsnElt.TeletexString, ParseString());
			break;
		case "utf8":
		case "utf-8":
		case "utf8string":
			ret = AsnElt.MakeString(
				AsnElt.UTF8String, ParseString());
			break;
		case "utf16":
		case "utf-16":
		case "bmp":
		case "bmpstring":
			ret = AsnElt.MakeString(
				AsnElt.BMPString, ParseString());
			break;
		case "utf32":
		case "utf-32":
		case "universal":
		case "universalstring":
			ret = AsnElt.MakeString(
				AsnElt.UniversalString, ParseString());
			break;
		case "utc":
		case "utctime":
			ret = AsnElt.MakeString(
				AsnElt.UTCTime, ParseString());
			break;
		case "gentime":
		case "generalizedtime":
			ret = AsnElt.MakeString(
				AsnElt.GeneralizedTime, ParseString());
			break;
		case "setof":
			ret = BuildSetOf();
			break;
		case "set":
			ret = BuildConstructed(AsnElt.SET);
			break;
		case "sequence":
			ret = BuildConstructed(AsnElt.SEQUENCE);
			break;
		default:
			throw new IOException("unknown type name: " + tn);
		}
		if (NextChar() != ')') {
			throw new IOException("expected closing parenthesis");
		}

		/*
		 * Apply the implicit tag, if any.
		 */
		if (tagClass >= 0) {
			ret = AsnElt.MakeImplicit(tagClass, tagValue, ret);
		}
		return ret;
	}

	static int ParseTagClass(string w)
	{
		switch (w.ToLowerInvariant()) {
		case "universal":
			return AsnElt.UNIVERSAL;
		case "application":
			return AsnElt.APPLICATION;
		case "context":
			return AsnElt.CONTEXT;
		case "private":
			return AsnElt.PRIVATE;
		}
		throw new IOException("unknown tag class: " + w);
	}

	static int ParseTagValue(string w)
	{
		try {
			int v = Int32.Parse(w);
			if (v >= 0) {
				return v;
			}
		} catch (Exception) {
			// ignored
		}
		throw new IOException("invalid tag value: " + w);
	}

	static AsnElt BuildInteger(string iv)
	{
		/*
		 * If the string can be parsed as a 64-bit integer (signed
		 * or unsigned) then we can encoded it right away.
		 */
		long v;
		if (Int64.TryParse(iv, out v)) {
			return AsnElt.MakeInteger(v);
		}
		ulong uv;
		if (UInt64.TryParse(iv, out uv)) {
			return AsnElt.MakeInteger(uv);
		}

		/*
		 * For longer values we need ZInt.
		 */
		try {
			ZInt z = ZInt.Parse(iv);
			return AsnElt.MakePrimitive(
				AsnElt.INTEGER, z.ToBytesBE());
		} catch {
			throw new IOException(
				"could not convert value to integer: " + iv);
		}
	}

	static byte[] ParseHexBytes()
	{
		/*
		 * We accept to parse a sub-element instead of hex values,
		 * to support nested values in OCTET STRING / BIT STRING.
		 */
		AsnElt s = BuildNext();
		if (s != null) {
			return s.Encode();
		}

		MemoryStream ms = new MemoryStream();
		int acc = 0;
		bool high = true;
		for (;;) {
			int c = PeekNextChar();
			if (c < 0) {
				throw new IOException("truncated input");
			}
			if (c == ')') {
				break;
			}
			LowRead();
			int d = HexValue(c);
			if (d < 0) {
				if (IsWS(c) || c == ':') {
					continue;
				}
				throw new IOException("not an hexadecimal"
					+ " character: " + (char)c);
			}
			if (high) {
				acc = d;
			} else {
				ms.WriteByte((byte)((acc << 4) + d));
			}
			high = !high;
		}
		if (!high) {
			throw new IOException("lone hexdigit");
		}
		return ms.ToArray();
	}

	static AsnElt BuildConstructed(int type)
	{
		List<AsnElt> subs = new List<AsnElt>();
		for (;;) {
			AsnElt s = BuildNext();
			if (s == null) {
				break;
			}
			subs.Add(s);
		}
		return AsnElt.Make(type, subs.ToArray());
	}

	static AsnElt BuildSetOf()
	{
		List<AsnElt> subs = new List<AsnElt>();
		for (;;) {
			AsnElt s = BuildNext();
			if (s == null) {
				break;
			}
			subs.Add(s);
		}
		return AsnElt.MakeSetOf(subs.ToArray());
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

	/* obsolete
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
		AppDomain.CurrentDomain.AssemblyResolve +=
			new ResolveEventHandler(AssemblyLoader);
	}

	static Assembly AssemblyLoader(object sender, ResolveEventArgs args)
	{
		string name = "AssemblyLoadingAndReflection."
			+ new AssemblyName(args.Name).Name + ".dll";
		using (Stream s = Assembly.GetExecutingAssembly()
			.GetManifestResourceStream(name))
		{
			byte[] d = new byte[(int)s.Length];
			s.Read(d, 0, d.Length);
			return Assembly.Load(d);
		}
	}
	*/
}
