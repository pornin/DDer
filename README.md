# DDer / MDer

## Overview

This repository contains a generic ASN.1/DER parsing library, written
in C#, that has the following features:

  - Arbitrary ASN.1/DER object can be decoded into object instances that
    can be explored programmatically.
  - Such instances can also be built programmatically, and encoded.
  - Decoding supports binary DER as well as Base64 and PEM.
  - A text-based structure syntax can be used to describe values. The
    syntax is supported as output (convert an object to a human-readable
    text format), as input (convert a human-writable format into an
    ASN.1 object that can be encoded), and as a parsing template
    (exploring a decoded ASN.1 object, to check the presence of expected
    structures and elements, and to gather values from elements).

**DDer.exe** is a simple command-line tool that converts encoded ASN.1
object (DER or BER) to the structured text-based syntax that is
reminiscent of Lisp (i.e. it uses parentheses). **MDer.exe** performs
the reverse operation. These tools are meant to allow easy analysis of
DER-encoded objects (in particular X.509 certificates) and creation of
synthetic objects from a text editor or a scripting environment.
**MDer.exe** can additionally use parameters to insert sub-objects and
elements at various places. The internal classes `DDer` and `MDer`
provide programmatic access to these fonctionalities, in particular with
powerful parametrization features to allow easier building and parsing
of objects as used in some complicated ASN.1-based protocols (e.g.
exploring X.509 certificate contents).

**ZInt** is a self-contained big integer implementation, in pure C#.
It is implemented in the [ZInt.cs](BigInt/ZInt.cs) file. This file
defines the `ZInt` struct type, which can be used basically like plain
integers thanks to operator overloads. It offers functionalities
similar to that of `System.Numerics.BigInteger`, with the following
differences:

  - ZInt is much faster on small values: when the value would fit in a
    signed 32-bit type (`int`), then ZInt use entails no dynamic
    (GC-based) memory allocation. This makes ZInt more appropriate for
    computations over integers that are usually small but may
    occasionally exceed the range of `int`.

  - ZInt also works on old C#/.NET (pre-4.0) that do not support
    `System.Numerics.BigInteger`.

  - ZInt has a few extra number-theoretic functions. In particular,
    it can return the Bézout coefficients when computing a GCD;
    it also includes primality tests, and random generation.

ZInt is useful for some mathematics-related tasks, e.g. involving some
kinds of cryptography, with the following important caveat: it is not
constant-time, and thus MUST NOT be used to manipulate private data.
ZInt is meant to support research tasks and prototyping.

## License

License is MIT-like: you acknowledge that the code is provided without
any guarantee of anything, and that I am not liable for anything which
follows from using it. Subject to these conditions, you can do whatever
you want with the code. See the `LICENSE` file in the source code for
the legal wording.

## Installation

The source code is obtained from
[GitHub](https://github.com/pornin/DDer/); use the "Download
ZIP" to obtain a fresh snapshot, or use `git` to clone the repository.
In the source tree, you will find the simple build scripts, `build.cmd`
(for Windows) and `build.sh` (for Linux and OS X).

The Windows script invokes the command-line compiler (`csc.exe`) that is
found in the v2.0.50727 .NET framework. This framework is installed by
default on Windows 7. More recent versions of Windows do not have the
.NET 2.0 framework, but a more recent version (4.x or later). Though
these framework versions are not completely compatible with each other,
TestSSLServer uses only features that work identically on both, so you
can compile TestSSLServer with either .NET version. The resulting
TestSSLServer.exe is stand-alone and needs no further "installation";
you simply copy the file where you want it to be, and run it from a
console (`cmd.exe`) with the appropriate arguments.

The Linux / OS X script tries to invoke the Mono C# compiler under the
names `mono-csc` (which works on Ubuntu) and `dmcs` (which works on OS
X). On Ubuntu, install the `mono-devel` package; it should pull as
dependencies the runtime and the compiler. On OS X, fetch a package from
the [Mono project](http://www.mono-project.com/) and install it; it
should provide the `mono` command-line tool to run compiled asemblies,
and `dmcs` to invoke the C# compiler.

## Usage

On Windows, the compiled `DDer.exe` and `MDer.exe` files can be launched
directly. On Linux and OS X, use `mono DDer.exe` and `mono MDer.exe`.

**DDer.exe** expects one or several file names; in each file, a single ASN.1
object will be decoded. Files may contain the raw object (in binary), a
Base64-encoded object, or a PEM object (Base64-encoding with the
`-----BEGIN XXX-----` and `-----END XXX-----` headers). Object type is
automatically detected. Decoded format is written on standard output, so
use a shell redirection to store it in a file. If no file name is provided,
then standard input is used.

A file name given as "`-`" (a single minus character) designates
standard input. Since DDer.exe reads each input source as a whole, the
"`-`" source can be given only once on the command-line.

The `-n` command-line option forces DDer.exe to produce numerical output for
all OIDs. Without that option, DDer.exe will recognize some standard OIDs and
provide their name (e.g. if the OID is 2.5.29.15, DDer will print its
symbolic name `id-ce-keyUsage`).

The `-i pref` command-line option makes DDer.exe use the string provided
as the `pref` parameter for each indentation level; normally, `pref`
will consist of one or several spaces. Default indentation prefix is
four spaces. If `pref` is set to `none`, then no indentation is used,
and newlines are suppressed (the output will fit on a single line of
text).

**MDer.exe** expects two arguments: first one is the name of the source
file (text encoding of the value), second one is the name of the output
file to produce. Output is always binary DER (no Base64). If the name of
the input file is "`-`" (a single minus character), then the source text
is read from standard input. Similarly, if the output file name is
"`-`", then the encoded DER object will be written on standard output
(as binary).

Extra arguments to `MDer.exe` are extra values that can be inserted in
the output object by using parameter references such as `%0`, `%1`...
See the [`MDer` class](Asn1/MDer.cs) for details. The command-line tool
can only use string parameters; the `MDer` class gives programmatic
access to parameterized object building which can use constructed
objects.

## Syntax

We describe here the base text syntax, as is produced by DDer.exe and
expected by MDer.exe. This does not cover use of parameters for
programmatic building or parsing; see the [`MDer` class](Asn1/MDer.cs)
for details.

Text format consists in tokens, with the following rules:

 - Input is supposed to be UTF-8. An UTF-16 input with a starting BOM
   should work.

 - Whitespace consists in all ASCII control characters (so this includes
   CR, LF, and tabulations), ASCII space, and U+00A0 unbreakable space.
   Whitespace may appear anywhere between two tokens, and is
   insignificant except insofar as it separates tokens. Whitespace
   characters within string literals is significant.

 - A semicolon "`;`" starts a comment, that extends to the end of the
   current line. Comments are equivalent to whitespace.

 - An opening brace "`{`" starts a comment. The comment extends to the
   matching closing brace "`}`". Such comments may nest and may extend
   over several lines. Comments are equivalent to whitespace.

   Within a brace-comment, MDer counts opening and closing braces so
   that comment nesting works; it still properly ignores braces that
   appear as part of semicolon-comments and literal strings. Brace
   comments can thus be used to "comment out" large chunks of data.

 - A _word_ is a sequence of characters taken among: uppercase ASCII
   letters, lowercase ASCII letters, digits, "`$`", "`_`", "`-`", "`+`",
   "`.`", and "`,`". A word stops at the first character which is not
   part of these sets. Words, in general, are symbolic identifiers;
   such identifiers are _not_ case-sensitive.

 - The characters "`(`" (opening parenthesis), "`)`" (closing
   parenthesis), "`[`" (opening bracket) and "`]`" (closing bracket) are
   all tokens on their own.

 - String literals begin with a double-quote character, and end on the
   next double-quote character. Within a string literal, the backslash "`\`"
   introduces an escape sequence:

    - "`\n`" encodes a LF (U+000A).
    - "`\r`" encodes a CR (U+000D).
    - "`\t`" encodes a tabulation (U+0009).
    - "`\uXXXX`", where "XXXX" are exactly four hexadecimal characters,
      encodes an arbitrary Unicode code point (for code points beyond
      the first plane, use two sequences for a surrogate pair).
    - "`\`" followed by any other character encodes that specific character.
      In particular, "`\\`" encodes a backslash, and "`\"`" encodes a
      double-quote character that does not end the string literal.

 - In some cases, input is parsed as hexadecimal bytes, up to the next
   closing parenthesis. Whitespace and colon characters ("`:`") are
   ignored within hexadecimal bytes; other characters shall be
   hexadecimal digits (ASCII digits, ASCII letters from `A` to `F`,
   ASCII letters from `a` to `f`). The total number of hexadecimal
   digits shall be even. An empty value is allowed (no hexadecimal
   digit at all).

   When hexadecimal bytes are expected, a sub-object can be provided
   instead. The sub-object begins with its own opening parenthesis, and
   follows the object format. In that case, the DER-encoded object is
   used for the byte values. This supports encoding formats that use
   `BIT STRING` or `OCTET STRING` whose values are themselves ASN.1
   objects (e.g. public keys in `SubjectPublicKeyIdentifier`
   structures).

An ASN.1 object has the following generic format:

    ( [ class tag ] name value )

with the following rules:

 - The "`[class tag]`" sequence is optional; the presence of the initial
   opening bracket indicates its presence. This sequence encodes an
   ASN.1 tag value that overrides the normal (universal) tag of the
   object.

    - The "`class`" is a word, among `universal`, `application`,
      `context` and `private`. This is the tag class. It can be omitted,
      in which case the tag has class `context`.

    - The "`tag`" is a word which is parsed as an integer (signed 32-bit).
      Tag value must be nonnegative.

 - The "`name`" is a symbolic identifier for the object type. This
   indicates the parsing rules for the value; it also sets the object
   tag, unless overridden with an explicit "`[class tag]`" sequence.

The following object types are defined:

 - `bool` and `boolean`: a `BOOLEAN` object. The value is a word, which
   must be one of `true`, `on`, `yes` or `1` (for `TRUE`), or one of
   `false`, `off`, `no` or `0` (for `FALSE`).

 - `int` and `integer`: an `INTEGER` object. The value is a word, which is
   then parsed as an integer:

    - a starting minus sign is used for a negative integer;
    - the integer is normally decoded in decimal, but an explicit `0x`
      header can be used for hexadecimal, or `0b` for binary;
    - arbitrarily long integers are supported (no 32-bit or 64-bit limit).

 - `bits`: a `BIT STRING` object. The value should be a word, parsed as
   an integer with value 0 to 7, followed by hexadecimal bytes (or a
   sub-object). The initial integer indicates the number of ignored bits
   in the last value byte; the hexadecimal bytes encode the `BIT STRING`
   contents themselves.

 - `blob` or `bytes`: an `OCTET STRING` object. The value consists in
   hexadecimal bytes (or a sub-object).

 - `null`: a `NULL` object. Value is empty.

 - `oid`: an `OBJECT IDENTIFIER`. The value is a word, which must be
   either the OID in decimal-dotted format (e.g. `2.5.29.15`) or a
   symbolic identifier for one of the standard OID (e.g.
   `id-ce-keyUsage`).

 - `numeric` or `numericstring`: a `NumericString`. The value is a
   string literal.

 - `printable` or `printablestring`: a `PrintableString`. The value
   is a string literal.

 - `ia5` or `ia5string`: an `IA5String`. The value is a string literal.

 - `teletex` or `teletexstring`: a `TeletexString`. The value
   is a string literal.

   How exactly Teletex strings are supposed to be encoded is a mystery
   shrouded in many layers of ill-documented committee meetings. DDer
   and MDer follow the commonly encountered tradition of using latin-1
   (ISO-8859-1).

 - `utf8`, `utf-8` or `utf8string`: an `UTF8String`. The value is a
   string literal.

   Upon decoding, DDer recognizes a BOM (leading U+FEFF) and removes it.
   Upon encoding, no BOM is produced.

 - `utf16`, `utf-16`, `bmp` or `bmpstring`: a `BMPString`. The value is
   a string literal.

   While a `BMPString` is nominally limited to the first Unicode plane,
   DDer and MDer use UTF-16 (surrogate pairs) for upper planes. When
   decoding, DDer recognizes a BOM (leading U+FEFF) and removes it;
   decoding uses big-endian convention, unless a leading little-endian
   BOM is present. When encoding, MDer uses big-endian with no BOM.

 - `utf32`, `utf-32`, `universal` or `universalstring`: a
   `UniversalString`. The value is a string literal.

   When decoding, DDer recognizes a BOM (leading U+FEFF) and removes it;
   decoding uses big-endian convention, unless a leading little-endian
   BOM is present. When encoding, MDer uses big-endian with no BOM.
   While `UniversalString` values are 32-bit numbers, code points must
   have a value in the 0 to 0x10FFFF range.

 - `utc` or `utctime`: a `UTCTime`. The value is a string literal.

   When encoding, MDer does not check time values; the value is expected
   to be in a proper format. When decoding, DDer interprets time values
   along a proleptic Gregorian calendar.

 - `gentime` or `generalizedtime`: a `GeneralizedTime`. The value is
   a string literal.

   When encoding, MDer does not check time values; the value is expected
   to be in a proper format. When decoding, DDer interprets time values
   along a proleptic Gregorian calendar.

 - `set`: a `SET`. The value is a concatenation of 0, 1 or more
   sub-objects.

   Objects will be encoded in the order they are provided (thus, this
   will be strict DER only if objects are already in DER-mandated tag
   order).

 - `sequence`: a `SEQUENCE`. The value is a concatenation of 0, 1 or
   more sub-objects, encoding in the order they are provided.

 - `setof`: a `SET OF` object. The value is a concatenation of 0, 1 or
   more sub-objects.

   When encoding a `SET OF`, MDer will sort the value elements in
   lexicographic ascending order of their respective DER-encoded values,
   as mandated by DER.

## Notes

### Sub-Objects for Blobs

When decoding a `BIT STRING` or `OCTET STRING`, DDer will check if the
value is itself a valid DER-encoded object. If it is, then the
"sub-object" syntax is used; otherwise, hexadecimal bytes are used. It
can thus happen that a binary value turns out to be interpreted as a
sub-object; e.g., if a 20-byte key identifier in a certificate
(nominally a hash output) starts with bytes 0x04 0x12, then it will
"look like" a DER-encoded `OCTET STRING` and will be decoded as such. In
practice, this occurs very rarely.

DDer takes care not to use a sub-object if MDer would not reencode the
value exactly. Such things may happen because many encoding variants are
accepted (e.g. endianness in character strings, minimality of integer
values, BER indefinite lengths...) but not transcribed in the text
output of DDer. If the output would not be reencoded exactly, then
hexadecimal output is produced instead of a sub-object.

### Checks on Strings

DDer and MDer check that string contents match their respective types.
Therefore, if you want to produce (for testing reasons) an "invalid"
string, you should use another type with a tag override. For instance,
this:

    ([universal 19] ia5 "foo&bar")

produces a value with the tag for `PrintableString` (universal 19), but
the contents include a "`&`" character which is not allowed in a
`PrintableString`. When decoding it back, DDer will complain
("unexpected character U+0026 in string of type 19").

### Tentative String Decoding

If an `OCTET STRING` or a `BIT STRING` contains bytes that appear to be
"plain ASCII" (all byte values are 9, 10, 13, or between 32 and 126,
inclusive), then DDer assumes that the bytes may be an encoded ASCII
string, and prints out the string contents as a string literal enclosed
in a brace-delimited comment. This is done in addition to the normal
hexadecimal printout for such values.

This is used for instance with `GeneralName` structures, which are
commonly encountered in certificates for encoding URL (the format for
such an URL is an `IA5String` with a contextual tag override of value 6,
so the fact that it is an `IA5String` is not known to DDer).

### GeneralString and TeletexString

The ASN.1 `GeneralString` and `TeletexString` types are handled as
ISO-8859-1, aka "Latin-1", i.e. as sequences of characters with a
one-byte-per-character mapping. This does not conform to the _de jure_
ASN.1 standard, but aligns with common practice in protocols that
use such types. In any case, this allows reading and writing arbitrary
string contents through `\x` escape sequences in string literals.

### Date and Time Processing

When decoding a time string (`UTCTime` or `GeneralizedTime`), DDer
produces both the string contents as a string literal, and a human
readable date and time in a brace-delimited comment. Note that a
`DateTime` object is used internally, with the following consequences:

 - The date is converted to UTC. Any time zone offset in the string is
   processed and applied.
 - In `GeneralizedTime` values, only up to seven fractional digits are
   read (i.e. 'ticks' of 100ns); other digits are ignored.
 - Year 0 is not supported (`DateTime` starts at year 1).
 - The calendar is a "proleptic Gregorian calendar", which means that
   the Gregorian rules, theoretically valid only from October 15th, 1589 AD
   onwards, are retroactively applied to previous dates.
 - Leap seconds are ignored: if the second count is 60, it is internally
   converted to 59. No attempt is made to check whether the leap second
   really occurred, or even _might_ have occurred at that date, as per
   UTC rules.

All this only matters for the human-readable printout, which is a
comment. The string literal still contains the complete string, as it
was received.

### Memory Allocation Behaviour

When decoding, the underlying ASN.1 library copies the whole input
buffer exactly once, then keeps references within that buffer. This
should make it immune to, or at least robust against, malformed inputs
with extra-large announced lengths in headers: if a 20-byte object
begins with a header that claims the value length to be one gigabyte,
DDer will _not_ allocate a one-gigabyte array.

### Accepted Variants

DDer accepts as input a number of variants which are not strict DER,
but are still unambiguous. These variants include the following:

 - Non-minimal tag and length encoding: encodings that use more bytes than
   the strict minimum are accepted.

 - Indefinite lengths (BER) are accepted. Note that DDer does not
   perform reassembly of parts for primitive values that were split
   into chunks.

 - Non-zero values for the value byte of a `BOOLEAN` are considered to
   encode `TRUE` (in strict DER, only 0xFF may be used for `TRUE`).

 - Non-minimal integer encodings: extra leading 0x00 (for nonnegative
   integers) or 0xFF (for negative integers) are tolerated.

 - Ignored bits in the last byte of a `BIT STRING` may have non-zero
   value (strict DER mandates that these bits are set to zero).

 - Non-minimal OID element encodings: each numerical element uses the "7E"
   encoding (big-endian, 7 bits per byte) but extra leading bytes are
   allowed.

 - `UTF8String`, `BMPString` and `UniversalString` may use an explicit
   BOM, which is removed upon decoding.

 - Little-endian decoding is accepted for `BMPString` and
   `UniversalString` if a BOM is included, and indicates such an
   encoding (strict DER mandates big-endian with no BOM).

 - When decoding `UTF8String` and `UniversalString`, surrogates are
   accepted, and pairs will be internally reunited.

### Numerical Limits

DDer and MDer operate under the following constraints:

 - The complete ASN.1 object must fit in RAM. Processing is not
   streamed. Moreover, 32-bit signed integers are used for lengths, so
   total object length may not exceed 2 gigabytes.

 - Tag value must fit on a 32-bit signed integer.

 - Individual OID components can have arbitrary size; be aware that many
   other existing ASN.1 libraries cannot handle components beyond 32 bits
   or so, therefore larger components should be avoided for better
   interoperability.

 - Dates must have year 1 to 9999. Year 0 is not supported.

Values which exceed these limits are detected and trigger exceptions.

## Author

Question and comments can be sent to: Thomas Pornin `<pornin@bolet.org>`
