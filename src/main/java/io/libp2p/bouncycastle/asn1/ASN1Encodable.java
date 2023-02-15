package io.libp2p.bouncycastle.asn1;
public interface ASN1Encodable
{
    /**
     * Return an object, possibly constructed, of ASN.1 primitives
     * @return an ASN.1 primitive.
     */
    ASN1Primitive toASN1Primitive();
}