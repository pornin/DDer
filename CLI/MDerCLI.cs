using System;
using System.Collections.Generic;
using System.IO;
using System.Reflection;
using System.Text;

using Asn1;
using BigInt;

/*
 * Command-line interface for MDer.
 */

public class MDerCLI {

	public static void Main(string[] args)
	{
		try {
			if (args.Length < 2) {
				Usage();
			}
			string iname = args[0];
			string oname = args[1];
			TextReader input;
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
			object[] pp = new object[args.Length - 2];
			for (int i = 0; i < pp.Length; i ++) {
				pp[i] = args[i + 2];
			}
			for (;;) {
				AsnElt ae;
				if (!MDer.TryBuild(input, out ae, pp)) {
					break;
				}
				if (ae == null) {
					continue;
				}
				byte[] enc = ae.Encode();
				output.Write(enc, 0, enc.Length);
			}
			output.Close();
		} catch (Exception e) {
			Console.Error.WriteLine(e.ToString());
			Environment.Exit(1);
		}
	}

	static void Usage()
	{
		Console.WriteLine(
"usage: mder.exe input output [ params... ]");
		Console.WriteLine(
"Use '-' as file name for standard input and standard output.");
		Environment.Exit(1);
	}
}
