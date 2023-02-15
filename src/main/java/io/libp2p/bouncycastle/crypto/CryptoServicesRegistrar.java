package io.libp2p.bouncycastle.crypto;

import java.security.SecureRandom;
import java.util.concurrent.atomic.AtomicReference;


/**
 * Basic registrar class for providing defaults for cryptography services in this module.
 */
public final class CryptoServicesRegistrar
{    private static final SecureRandomProvider defaultRandomProviderImpl = new SecureRandomProvider()
    {
        public SecureRandom get()
        {
            return new SecureRandom();
        }
    };


    private static final AtomicReference<SecureRandomProvider> defaultSecureRandomProvider = new AtomicReference<SecureRandomProvider>();


    /**
     * Return the default source of randomness.
     *
     * @return the default SecureRandom
     */
    public static SecureRandom getSecureRandom()
    {
        defaultSecureRandomProvider.compareAndSet(null, defaultRandomProviderImpl);

        return defaultSecureRandomProvider.get().get();
    }

}
