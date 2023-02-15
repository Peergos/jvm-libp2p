package io.libp2p.core.crypto

import java.security.MessageDigest
import java.security.NoSuchAlgorithmException
import javax.crypto.Mac

fun hmacSha(algorithm: String): Mac {
    try {
        return Mac.getInstance(algorithm)
    } catch (e: NoSuchAlgorithmException) {
        throw IllegalArgumentException(e)
    }
}
// fun sha1(data: ByteArray): ByteArray = hash(data, "SHA-1")
fun sha256(data: ByteArray): ByteArray = hash(data, "SHA-256")
// fun sha512(data: ByteArray): ByteArray = hash(data, "SHA-512")

// fun sha3(data: ByteArray, algorithm: String): ByteArray = hash(data, algorithm)
fun hash(input: ByteArray, algorithm: String): ByteArray {
    return try {
        val md = MessageDigest.getInstance(algorithm)
        md.update(input)
        md.digest()
    } catch (e: NoSuchAlgorithmException) {
        throw IllegalArgumentException(e)
    }
}
