using System;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using System.Text;

using Asn1;

public class DDer {

	static bool numOID = false;

	public static void Main(string[] args)
	{
		try {
			List<string> r = new List<string>();
			foreach (string a in args) {
				string b = a.ToLowerInvariant();
				switch (b) {
				case "-n":
					numOID = true;
					break;
				default:
					r.Add(a);
					break;
				}
			}
			args = r.ToArray();
			if (args.Length == 0) {
				Usage();
			}
			foreach (string a in args) {
				ProcessFile(a);
			}
		} catch (Exception e) {
			Console.WriteLine(e.ToString());
			Environment.Exit(1);
		}
	}

	static void Usage()
	{
		Console.WriteLine(
"Usage: dder.exe [ -n ] file...");
		Environment.Exit(1);
	}

	static void ProcessFile(string fname)
	{
		StringBuilder sb = new StringBuilder();
		foreach (byte b in Encoding.UTF8.GetBytes(fname)) {
			if (b >= 32 && b <= 126 && b != (byte)'%') {
				sb.Append((char)b);
			} else {
				sb.AppendFormat("%{0:X2}", (int)b);
			}
		}
		Console.WriteLine("; ##### " + sb.ToString());
		try {
			byte[] enc;
			if (fname == "-") {
				enc = ReadAllBytes(Console.OpenStandardInput());
			} else {
				enc = File.ReadAllBytes(fname);
			}
			enc = AsnIO.FindBER(enc);
			if (enc == null) {
				throw new IOException(
					"no BER object in file " + fname);
			}
			AsnElt ae = AsnElt.Decode(enc);
			Parse(Console.Out, 0, ae);
			Console.WriteLine();
		} catch (Exception e) {
			Console.Error.WriteLine(e.ToString());
			Environment.Exit(1);
		}
	}

	static byte[] ReadAllBytes(Stream s)
	{
		MemoryStream ms = new MemoryStream();
		byte[] buf = new byte[8192];
		for (;;) {
			int len = s.Read(buf, 0, buf.Length);
			if (len <= 0) {
				break;
			}
			ms.Write(buf, 0, len);
		}
		return ms.ToArray();
	}

	static void Parse(TextWriter tw, int depth, AsnElt ae)
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
				if (!numOID) {
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
				tw.Write("utc "
					+ EscapeString(ae.GetString())
					+ " {" + ae.GetTime() + "} )");
				return;
			case AsnElt.GeneralizedTime:
				tw.Write("gentime "
					+ EscapeString(ae.GetString())
					+ " {" + ae.GetTime() + "} )");
				return;
			case AsnElt.SEQUENCE:
				tw.Write("sequence");
				ParseSubs(tw, depth, ae);
				tw.Write(")");
				return;
			case AsnElt.SET:
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

	static void ParseSubs(TextWriter tw, int depth, AsnElt ae)
	{
		foreach (AsnElt s in ae.Sub) {
			tw.WriteLine();
			Parse(tw, depth + 1, s);
		}
	}

	static void Indent(TextWriter tw, int depth)
	{
		while (depth -- > 0) {
			tw.Write("    ");
		}
	}

	static void PrintBytes(TextWriter tw, int depth, byte[] buf)
	{
		PrintBytes(tw, depth, buf, 0, buf.Length);
	}

	static void PrintBytes(TextWriter tw, int depth,
		byte[] buf, int off, int len)
	{
		/*
		 * First, try to decode the bytes as an encapsulated
		 * DER object.
		 */
		try {
			AsnElt ae = AsnElt.Decode(buf, off, len);
			StringWriter sw = new StringWriter();
			Parse(sw, depth + 1, ae);
			tw.WriteLine();
			tw.Write(sw.ToString());
			return;
		} catch (Exception) {
			/*
			 * Not an encapsulated DER object.
			 */
		}

		/*
		 * Print out the bytes.
		 */
		bool isASCII = true;
		for (int i = 0; i < len; i ++) {
			if (i % 16 == 0) {
				tw.WriteLine();
				Indent(tw, depth + 1);
			} else if (i % 8 == 0) {
				tw.Write("  ");
			} else {
				tw.Write(" ");
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
		 * case, we write it out as a comment.
		 */
		if (isASCII) {
			StringBuilder sb = new StringBuilder();
			for (int i = 0; i < len; i ++) {
				sb.Append((char)buf[off + i]);
			}
			tw.WriteLine();
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

	/* obsolete
	static DDer()
	{
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
