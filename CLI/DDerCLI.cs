using System;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using System.Text;

using Asn1;
using BigInt;

/*
 * Command-line interface for DDer.
 */

public class DDerCLI {

	static bool numOID = false;
	static string indentPrefix = "    ";

	public static void Main(string[] args)
	{
		try {
			List<string> r = new List<string>();
			for (int i = 0; i < args.Length; i ++) {
				string a = args[i];
				string b = a.ToLowerInvariant();
				switch (b) {
				case "-h":
				case "-help":
				case "--help":
					Usage();
					break;
				case "-n":
					numOID = true;
					break;
				case "-i":
					if (++ i >= args.Length) {
						Usage();
					}
					indentPrefix = args[i];
					break;
				default:
					r.Add(a);
					break;
				}
			}
			if (indentPrefix.ToLowerInvariant() == "none") {
				indentPrefix = null;
			}
			if (r.Count == 0) {
				r.Add("-");
			}
			args = r.ToArray();
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
"Usage: dder.exe [ -n ] [ -i pref ] file...");
		Console.WriteLine(
"Use '-' as file name for standard input.");
		Console.WriteLine(
"  -h        Print this help");
		Console.WriteLine(
"  -n        Produce numeric OIDs only");
		Console.WriteLine(
"  -i pref   Use string 'pref' for each indent level (default: four spaces)");
		Console.WriteLine(
"            (use the string 'none' to remove indentation and line breaks)");
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
			DDer d = new DDer();
			d.NumericOID = numOID;
			d.IndentPrefix = indentPrefix;
			d.ToString(Console.Out, ae);
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
}
