package io.libp2p.transport

import io.libp2p.core.Connection
import io.libp2p.core.multistream.MultistreamProtocol
import io.libp2p.core.multistream.ProtocolBinding
import io.libp2p.core.mux.NegotiatedStreamMuxer
import io.libp2p.core.mux.StreamMuxer
import io.libp2p.core.security.SecureChannel
import io.libp2p.etc.getP2PChannel
import io.libp2p.etc.types.forward
import io.libp2p.etc.util.netty.nettyInitializer
import java.util.concurrent.CompletableFuture

/**
 * ConnectionUpgrader is a utility class that Transports can use to shim secure channels and muxers when those
 * capabilities are not provided natively by the transport.
 */
open class ConnectionUpgrader(
    private val secureMultistream: MultistreamProtocol,
    private val secureChannels: List<SecureChannel>,
    private val muxerMultistream: MultistreamProtocol,
    private val muxers: List<StreamMuxer>,
) {
    open fun establishSecureChannel(connection: Connection): CompletableFuture<SecureChannel.Session> {
        return establish(
            secureMultistream,
            connection,
            secureChannels
        )
    } // establishSecureChannel

    open fun establishMuxer(connection: Connection): CompletableFuture<StreamMuxer.Session> {
        return establish(
            muxerMultistream,
            connection,
            muxers
        )
    }

    private fun <T : ProtocolBinding<R>, R> establish(
        multistreamProtocol: MultistreamProtocol,
        connection: Connection,
        bindings: List<T>
    ): CompletableFuture<R> {
        val multistream = multistreamProtocol.createMultistream(bindings)
        return multistream.initChannel(connection)
    } // establish

    companion object {
        fun establishMuxer(muxer: NegotiatedStreamMuxer, connection: Connection): CompletableFuture<StreamMuxer.Session> {
            val res = CompletableFuture<StreamMuxer.Session>()
            connection.pushHandler(
                nettyInitializer {
                    muxer.initChannel(it.channel.getP2PChannel()).forward(res)
                }
            )
            return res
        }
    }
} // ConnectionUpgrader
