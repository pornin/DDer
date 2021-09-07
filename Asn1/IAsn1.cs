using System;

namespace Asn1 {

/*
 * Objects that extend the IAsn1 interface provide the ToAsn1() method
 * that encodes the object into an AsnElt instance.
 */

public interface IAsn1 {

	AsnElt ToAsn1();
}

}
