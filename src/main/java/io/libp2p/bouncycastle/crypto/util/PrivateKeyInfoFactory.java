package io.libp2p.bouncycastle.crypto.util;

import java.io.IOException;

import io.libp2p.bouncycastle.asn1.ASN1Set;
import io.libp2p.bouncycastle.asn1.DERNull;
import io.libp2p.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import io.libp2p.bouncycastle.asn1.pkcs.RSAPrivateKey;
import io.libp2p.bouncycastle.asn1.x509.AlgorithmIdentifier;
import io.libp2p.bouncycastle.crypto.params.AsymmetricKeyParameter;

import io.libp2p.bouncycastle.crypto.params.RSAKeyParameters;
import io.libp2p.bouncycastle.crypto.params.RSAPrivateCrtKeyParameters;
import io.libp2p.bouncycastle.asn1.pkcs.PrivateKeyInfo;


/**
 * Factory to create ASN.1 private key info objects from lightweight private keys.
 */
public class PrivateKeyInfoFactory
{

    private PrivateKeyInfoFactory()
    {

    }

    /**
     * Create a PrivateKeyInfo representation of a private key.
     *
     * @param privateKey the key to be encoded into the info object.
     * @return the appropriate PrivateKeyInfo
     * @throws java.io.IOException on an error encoding the key
     */
    public static PrivateKeyInfo createPrivateKeyInfo(AsymmetricKeyParameter privateKey)
        throws IOException
    {
        return createPrivateKeyInfo(privateKey, null);
    }

    /**
     * Create a PrivateKeyInfo representation of a private key with attributes.
     *
     * @param privateKey the key to be encoded into the info object.
     * @param attributes the set of attributes to be included.
     * @return the appropriate PrivateKeyInfo
     * @throws java.io.IOException on an error encoding the key
     */
    public static PrivateKeyInfo createPrivateKeyInfo(AsymmetricKeyParameter privateKey, ASN1Set attributes)
        throws IOException
    {
        if (privateKey instanceof RSAKeyParameters)
        {
            RSAPrivateCrtKeyParameters priv = (RSAPrivateCrtKeyParameters)privateKey;

            return new PrivateKeyInfo(new AlgorithmIdentifier(PKCSObjectIdentifiers.rsaEncryption, DERNull.INSTANCE),
                new RSAPrivateKey(priv.getModulus(), priv.getPublicExponent(), priv.getExponent(), priv.getP(), priv.getQ(), priv.getDP(), priv.getDQ(), priv.getQInv()),
                attributes);
        }
        else
        {
            throw new IOException("key parameters not recognized");
        }
    }
}
