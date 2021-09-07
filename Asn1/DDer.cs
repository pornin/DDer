using System;
using System.Collections.Generic;
using System.IO;
using System.Text;

namespace Asn1 {

/*
 * A DDer instance can convert ASN.1 objects (AsnElt instances) to a
 * string representation which is compatible with what is expected by
 * MDer for building and parsing purposes; see MDer for details.
 */

public class DDer {

	/*
	 * If false, then recognized OIDs are returned under their
	 * symbolic name. If true, then all OIDs are returned in
	 * numeric (decimal-dotted) format. Default is false.
	 */
	public bool NumericOID {
		get; set;
	}

	/*
	 * Indentation prefix for each level. Default is a sequence of
	 * four spaces.
	 *
	 * If set to null, then no indentation is performed, and line breaks
	 * are suppressed; a single space is used between the type and the
	 * value. Moreover, inline comments (between braces) are no longer
	 * emitted.
	 */
	public string IndentPrefix {
		get; set;
	}

	/*
	 * Create a new instance. The instance contains the conversion
	 * parameters (NumericOID, IndentPrefix).
	 */
	public DDer()
	{
		NumericOID = false;
		IndentPrefix = "    ";
	}

	/*
	 * Convert the provided object to a string. The string does not
	 * include a terminating newline character.
	 */
	public string ToString(AsnElt ae)
	{
		StringWriter sw = new StringWriter();
		ToString(sw, 0, ae);
		return sw.ToString();
	}

	/*
	 * Convert the provided object to text, written onto the provided
	 * TextWriter. No newline character is appended.
	 */
	public void ToString(TextWriter tw, AsnElt ae)
	{
		ToString(tw, 0, ae);
	}

	void NewLine(TextWriter tw)
	{
		if (IndentPrefix == null) {
			tw.Write(" ");
		} else {
			tw.WriteLine();
		}
	}

	void Indent(TextWriter tw, int depth)
	{
		string p = IndentPrefix;
		if (p != null) {
			while (depth -- > 0) {
				tw.Write(p);
			}
		}
	}

	void ToString(TextWriter tw, int depth, AsnElt ae)
	{
		Indent(tw, depth);
		tw.Write("(");
		switch (ae.TagClass) {
		case AsnElt.APPLICATION:
			tw.Write("[application " + ae.TagValue + "]");
			break;
		case AsnElt.CONTEXT:
			tw.Write("[" + ae.TagValue + "]");
			break;
		case AsnElt.PRIVATE:
			tw.Write("[private " + ae.TagValue + "]");
			break;
		default:
			switch (ae.TagValue) {
			case AsnElt.BOOLEAN:
				tw.Write("bool " + ae.GetBoolean() + ")");
				return;
			case AsnElt.INTEGER:
				tw.Write("int " + ae.GetIntegerHex() + ")");
				return;
			case AsnElt.BIT_STRING:
				int bitLen;
				byte[] bs = ae.GetBitString(out bitLen);
				tw.Write("bits "
					+ (bs.Length * 8 - bitLen));
				PrintBytes(tw, depth, bs);
				tw.Write(")");
				return;
			case AsnElt.OCTET_STRING:
				tw.Write("blob");
				PrintBytes(tw, depth, ae.CopyValue());
				tw.Write(")");
				return;
			case AsnElt.NULL:
				ae.CheckNull();
				tw.Write("null)");
				return;
			case AsnElt.OBJECT_IDENTIFIER:
				string oid = ae.GetOID();
				if (!NumericOID) {
					oid = AsnOID.ToName(oid);
				}
				tw.Write("oid " + oid + ")");
				return;
			case AsnElt.NumericString:
				tw.Write("numeric "
					+ EscapeString(ae.GetString()) + ")");
				return;
			case AsnElt.PrintableString:
				tw.Write("printable "
					+ EscapeString(ae.GetString()) + ")");
				return;
			case AsnElt.IA5String:
				tw.Write("ia5 "
					+ EscapeString(ae.GetString()) + ")");
				return;
			case AsnElt.GeneralString:
				tw.Write("genstring "
					+ EscapeString(ae.GetString()) + ")");
				return;
			case AsnElt.TeletexString:
				tw.Write("teletex "
					+ EscapeString(ae.GetString()) + ")");
				return;
			case AsnElt.UTF8String:
				tw.Write("utf8 "
					+ EscapeString(ae.GetString()) + ")");
				return;
			case AsnElt.BMPString:
				tw.Write("bmp "
					+ EscapeString(ae.GetString()) + ")");
				return;
			case AsnElt.UniversalString:
				tw.Write("utf32 "
					+ EscapeString(ae.GetString()) + ")");
				return;
			case AsnElt.UTCTime:
				tw.Write("utc ");
				tw.Write(EscapeString(ae.GetString()));
				if (IndentPrefix != null) {
					tw.Write(" {");
					tw.Write(TimeToString(ae.GetTime()));
					tw.Write("}");
				}
				tw.Write(")");
				return;
			case AsnElt.GeneralizedTime:
				tw.Write("gentime ");
				tw.Write(EscapeString(ae.GetString()));
				if (IndentPrefix != null) {
					tw.Write(" {");
					tw.Write(TimeToString(ae.GetTime()));
					tw.Write("}");
				}
				tw.Write(")");
				return;
			case AsnElt.SEQUENCE:
				if (!ae.Constructed) {
					throw new AsnException(
						"Non-constructed SEQUENCE");
				}
				tw.Write("sequence");
				ParseSubs(tw, depth, ae);
				tw.Write(")");
				return;
			case AsnElt.SET:
				if (!ae.Constructed) {
					throw new AsnException(
						"Non-constructed SET");
				}
				tw.Write("set");
				ParseSubs(tw, depth, ae);
				tw.Write(")");
				return;
			default:
				tw.Write(
					"[universal " + ae.TagValue + "]");
				break;
			}
			break;
		}
		if (ae.Constructed) {
			tw.Write("sequence");
			ParseSubs(tw, depth, ae);
			tw.Write(")");
		} else {
			tw.Write("blob");
			PrintBytes(tw, depth, ae.CopyValue());
			tw.Write(")");
		}
	}

	void ParseSubs(TextWriter tw, int depth, AsnElt ae)
	{
		foreach (AsnElt s in ae.Sub) {
			NewLine(tw);
			ToString(tw, depth + 1, s);
		}
	}

	void PrintBytes(TextWriter tw, int depth, byte[] buf)
	{
		PrintBytes(tw, depth, buf, 0, buf.Length);
	}

	void PrintBytes(TextWriter tw, int depth,
		byte[] buf, int off, int len)
	{
		/*
		 * First, try to decode the bytes as an encapsulated
		 * DER object.
		 *
		 * We need to check that reencoding would properly
		 * conserve the value: the decoder may accept some BER,
		 * or string encoding variants, that would not be
		 * reencoded identically.
		 */
		try {
			AsnElt ae = AsnElt.Decode(buf, off, len);
			byte[] buf2 = Reencode(ae);
			if (Equals(buf, off, len, buf2, 0, buf2.Length)) {
				StringWriter sw = new StringWriter();
				ToString(sw, depth + 1, ae);
				NewLine(tw);
				tw.Write(sw.ToString());
				return;
			}
		} catch (Exception) {
			/*
			 * Not an encapsulated DER object.
			 */
		}

		/*
		 * Print out the bytes.
		 */
		bool isASCII = true;
		if (IndentPrefix == null) {
			tw.Write(" ");
		}
		for (int i = 0; i < len; i ++) {
			if (IndentPrefix != null) {
				if (i % 16 == 0) {
					NewLine(tw);
					Indent(tw, depth + 1);
				} else if (i % 8 == 0) {
					tw.Write("  ");
				} else {
					tw.Write(" ");
				}
			}
			byte b = buf[off + i];
			tw.Write("{0:x2}", b);
			if (b > 126) {
				isASCII = false;
			} else if (b < 32) {
				if (b != 9 && b != 10 && b != 13) {
					isASCII = false;
				}
			}
		}

		/*
		 * The bytes might be an encoded ASCII string; in that
		 * case, we write it out as a comment. We do not do that
		 * when there are no line breaks.
		 */
		if (isASCII && IndentPrefix != null) {
			StringBuilder sb = new StringBuilder();
			for (int i = 0; i < len; i ++) {
				sb.Append((char)buf[off + i]);
			}
			NewLine(tw);
			Indent(tw, depth + 1);
			tw.Write("{{ {0} }}", EscapeString(sb.ToString()));
		}
	}

	static string EscapeString(string s)
	{
		StringBuilder sb = new StringBuilder();
		sb.Append('"');
		foreach (char c in s) {
			if (c >= 32 && c <= 126) {
				switch (c) {
				case '"':
				case '\\':
					sb.Append('\\');
					break;
				}
				sb.Append(c);
			} else {
				switch ((int)c) {
				case 9:
					sb.Append("\\t");
					break;
				case 10:
					sb.Append("\\n");
					break;
				case 13:
					sb.Append("\\r");
					break;
				default:
					sb.AppendFormat("\\u{0:X4}", (int)c);
					break;
				}
			}
		}
		sb.Append('"');
		return sb.ToString();
	}

	/*
	 * Reencode() simulates a DDer+MDer action: it is used to check
	 * that whatever we decode can be reencoded identically from its
	 * string representation. This is needed for tentative decoding
	 * as sub-objects.
	 *
	 * We cannot simply call ae.Encode() because the AsnElt object
	 * will keep a copy of the encoded source, and use it. We thus
	 * duplicate the whole structure, taking care to decode and
	 * reencode values which could be subject to variants (e.g.
	 * integers and strings).
	 */
	static byte[] Reencode(AsnElt ae)
	{
		return Duplicate(ae).Encode();
	}

	static AsnElt Duplicate(AsnElt ae)
	{
		if (ae.Constructed) {
			int n = ae.Sub.Length;
			AsnElt[] ss = new AsnElt[n];
			for (int i = 0; i < n; i ++) {
				ss[i] = Duplicate(ae.Sub[i]);
			}
			return AsnElt.Make(ae.TagClass, ae.TagValue, ss);
		}

		if (ae.TagClass == AsnElt.UNIVERSAL) {
			switch (ae.TagValue) {
			case AsnElt.BOOLEAN:
				return ae.GetBoolean()
					? AsnElt.BOOL_TRUE : AsnElt.BOOL_FALSE;

			case AsnElt.INTEGER:
				return AsnElt.MakeIntegerSigned(
					ae.CopyValue());

			case AsnElt.OBJECT_IDENTIFIER:
				return AsnElt.MakeOID(ae.GetOID());

			case AsnElt.NumericString:
			case AsnElt.PrintableString:
			case AsnElt.IA5String:
			case AsnElt.GeneralString:
			case AsnElt.TeletexString:
			case AsnElt.UTF8String:
			case AsnElt.BMPString:
			case AsnElt.UniversalString:
			case AsnElt.UTCTime:
			case AsnElt.GeneralizedTime:
				return AsnElt.MakeString(
					ae.TagValue, ae.GetString());
			}
		}

		/*
		 * All other primitive types will be treated as blobs.
		 * We still need to duplicate them in order to avoid
		 * variants in tag/length encoding.
		 */
		return AsnElt.MakePrimitive(ae.TagClass,
			ae.TagValue, ae.CopyValue());
	}

	static bool Equals(byte[] b1, int off1, int len1,
		byte[] b2, int off2, int len2)
	{
		if (len1 != len2) {
			return false;
		}
		for (int i = 0; i < len1; i ++) {
			if (b1[off1 + i] != b2[off2 + i]) {
				return false;
			}
		}
		return true;
	}

	static string TimeToString(DateTime dt)
	{
		dt = dt.ToUniversalTime();
		string s = string.Format(
			"{0:d4}-{1:d2}-{2:d2} {3:d2}:{4:d2}:{5:d2}",
			dt.Year, dt.Month, dt.Day,
			dt.Hour, dt.Minute, dt.Second);
		long ticks = dt.Ticks % 1000000;
		if (ticks != 0) {
			s += string.Format(".{0:d7}", ticks);
		}
		return s + " UTC";
	}
}

}
