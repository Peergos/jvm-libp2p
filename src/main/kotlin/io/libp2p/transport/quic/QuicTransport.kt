package io.libp2p.transport.quic

import io.libp2p.core.*
import io.libp2p.core.crypto.PrivKey
import io.libp2p.core.multiformats.Multiaddr
import io.libp2p.core.multiformats.MultiaddrDns
import io.libp2p.core.multiformats.Protocol.*
import io.libp2p.core.multistream.ProtocolBinding
import io.libp2p.core.mux.StreamMuxer
import io.libp2p.core.security.SecureChannel
import io.libp2p.core.transport.Transport
import io.libp2p.crypto.keys.generateEcdsaKeyPair
import io.libp2p.crypto.keys.generateEd25519KeyPair
import io.libp2p.etc.types.lazyVar
import io.libp2p.etc.types.toVoidCompletableFuture
import io.libp2p.etc.util.netty.nettyInitializer
import io.libp2p.security.tls.*
import io.libp2p.transport.implementation.ConnectionOverNetty
import io.netty.bootstrap.Bootstrap
import io.netty.bootstrap.ServerBootstrap
import io.netty.buffer.ByteBuf
import io.netty.buffer.PooledByteBufAllocator
import io.netty.channel.*
import io.netty.channel.epoll.Epoll
import io.netty.channel.epoll.EpollDatagramChannel
import io.netty.channel.nio.NioEventLoopGroup
import io.netty.channel.socket.nio.NioDatagramChannel
import io.netty.channel.socket.nio.NioServerSocketChannel
import io.netty.handler.ssl.ClientAuth
import io.netty.incubator.codec.quic.*
import java.net.*
import java.time.Duration
import java.util.*
import java.util.concurrent.CompletableFuture
import java.util.concurrent.TimeUnit

class QuicTransport(
    private val localKey: PrivKey,
    private val certAlgorithm: String,
) : Transport {

    private var closed = false
    var connectTimeout = Duration.ofSeconds(15)

    private val listeners = mutableMapOf<Multiaddr, Channel>()
    private val channels = mutableListOf<Channel>()

    private var workerGroup by lazyVar { NioEventLoopGroup() }
    private var bossGroup by lazyVar { NioEventLoopGroup(1) }
    private var allocator by lazyVar { PooledByteBufAllocator(true) }

    private var client by lazyVar {
        Bootstrap().group(workerGroup)
            .channel(
                if (Epoll.isAvailable()) {
                    EpollDatagramChannel::class.java
                } else {
                    NioDatagramChannel::class.java
                }
            )
            .option(ChannelOption.CONNECT_TIMEOUT_MILLIS, connectTimeout.toMillis().toInt())
    }

    companion object {
        @JvmStatic
        fun Ed25519(k: PrivKey): QuicTransport {
            return QuicTransport(k, "Ed25519")
        }
    }

    private var server by lazyVar {
        ServerBootstrap().apply {
            group(bossGroup, workerGroup)
            channel(NioServerSocketChannel::class.java)
        }
    }

    override val activeListeners: Int
        get() = listeners.size
    override val activeConnections: Int
        get() = channels.size

    override fun listenAddresses(): List<Multiaddr> {
        return listeners.values.map {
            toMultiaddr(it.localAddress() as InetSocketAddress)
        }
    }

    override fun initialize() {
    }

    override fun close(): CompletableFuture<Unit> {
        closed = true

        val unbindsCompleted = listeners
            .map { (_, ch) -> ch }
            .map { it.close().toVoidCompletableFuture() }

        val channelsClosed = channels
            .toMutableList() // need a copy to avoid potential co-modification problems
            .map { it.close().toVoidCompletableFuture() }

        val everythingThatNeedsToClose = unbindsCompleted.union(channelsClosed)
        val allClosed = CompletableFuture.allOf(*everythingThatNeedsToClose.toTypedArray())

        return allClosed.thenApply {
            workerGroup.shutdownGracefully()
            bossGroup.shutdownGracefully()
            Unit
        }
    }

    override fun listen(addr: Multiaddr, connHandler: ConnectionHandler, preHandler: ChannelVisitor<P2PChannel>?): CompletableFuture<Unit> {
        if (closed) throw Libp2pException("Transport is closed")

        val channelHandler = serverTransportBuilder()

        val listener = server.clone()
            .childHandler(
                nettyInitializer { init ->
                    registerChannel(init.channel)
                    init.addLastLocal(channelHandler)
                }
            )

        val bindComplete = listener.bind(fromMultiaddr(addr))

        bindComplete.also {
            synchronized(this@QuicTransport) {
                listeners += addr to it.channel()
                it.channel().closeFuture().addListener {
                    synchronized(this@QuicTransport) {
                        listeners -= addr
                    }
                }
            }
        }

        return bindComplete.toVoidCompletableFuture()
    }

    override fun unlisten(addr: Multiaddr): CompletableFuture<Unit> {
        return listeners[addr]?.close()?.toVoidCompletableFuture()
            ?: throw Libp2pException("No listeners on address $addr")
    }

    override fun dial(addr: Multiaddr, connHandler: ConnectionHandler, preHandler: ChannelVisitor<P2PChannel>?):
        CompletableFuture<Connection> {
        if (closed) throw Libp2pException("Transport is closed")

        val sslContext = quicSslContext(addr.getPeerId())
        val handler = QuicClientCodecBuilder()
            .sslEngineProvider({ q -> sslContext.newEngine(q.alloc()) })
                .maxIdleTimeout(5000, TimeUnit.MILLISECONDS)
            .sslTaskExecutor(workerGroup)
            .build()

        val chanFuture = QuicChannel.newBootstrap(
            client.clone()
                .remoteAddress(fromMultiaddr(addr))
                .handler(handler)
                .connect()
                .channel()
        )
            .streamOption(ChannelOption.ALLOCATOR, allocator)
            .option(ChannelOption.AUTO_READ, true)
            .option(ChannelOption.ALLOCATOR, allocator)
            .remoteAddress(fromMultiaddr(addr))
            .streamHandler(ChannelInboundHandlerAdapter())
            .connect()

        val res = CompletableFuture<Connection>()
        chanFuture.also { registerChannel(it.get()) }
        chanFuture.also {
            val connection = ConnectionOverNetty(it.get(), this, true)
            connection.setMuxerSession(object : StreamMuxer.Session {
                override fun <T> createStream(protocols: List<ProtocolBinding<T>>): StreamPromise<T> {
                    TODO("No multistream yet")
//                    var multistreamProtocol: MultistreamProtocol = MultistreamProtocolV1
//                    var streamMultistreamProtocol: MultistreamProtocol by lazyVar { multistreamProtocol }
//                    it.get().createStream(QuicStreamType.BIDIRECTIONAL, streamMultistreamProtocol.createMultistream(
//                        protocols
//                    ).toStreamHandler())
                }
            })
            val ids = sslContext.sessionContext().ids
            val peerCerts = sslContext.sessionContext().getSession(ids.nextElement()).peerCertificates
            connection.setSecureSession(SecureChannel.Session(
                PeerId.fromPubKey(localKey.publicKey()),
                verifyAndExtractPeerId(peerCerts),
                getPublicKeyFromCert(peerCerts),
                "libp2p"
            ))
            res.complete(connection)
        }
        return res
    }

    private fun registerChannel(ch: Channel) {
        if (closed) {
            ch.close()
            return
        }

        synchronized(this@QuicTransport) {
            channels += ch
            ch.closeFuture().addListener {
                synchronized(this@QuicTransport) {
                    channels -= ch
                }
            }
        }
    }

    protected fun handlesHost(addr: Multiaddr) =
        addr.hasAny(IP4, IP6, DNS4, DNS6, DNSADDR)

    protected fun hostFromMultiaddr(addr: Multiaddr): String {
        val resolvedAddresses = MultiaddrDns.resolve(addr)
        if (resolvedAddresses.isEmpty())
            throw Libp2pException("Could not resolve $addr to an IP address")

        return resolvedAddresses[0].components.find {
            it.protocol in arrayOf(IP4, IP6)
        }?.stringValue ?: throw Libp2pException("Missing IP4/IP6 in multiaddress $addr")
    }
    override fun handles(addr: Multiaddr) =
        handlesHost(addr) &&
            addr.has(UDP) &&
            addr.has(QUIC) &&
            !addr.has(WS)

    fun quicSslContext(expectedRemotePeerId: PeerId?): QuicSslContext {
        val connectionKeys = if (certAlgorithm.equals("ECDSA")) generateEcdsaKeyPair() else generateEd25519KeyPair()
        val javaPrivateKey = getJavaKey(connectionKeys.first)
        val isClient = expectedRemotePeerId != null
        val cert = buildCert(localKey, connectionKeys.first)
        println("Building " + certAlgorithm + " keys and cert")
        return (
                if (isClient)
                    QuicSslContextBuilder.forClient().keyManager(javaPrivateKey, null, cert)
                else
                    QuicSslContextBuilder.forServer(javaPrivateKey, null, cert).clientAuth(ClientAuth.REQUIRE)
                )
            .trustManager(Libp2pTrustManager(Optional.ofNullable(expectedRemotePeerId)))
            .applicationProtocols("libp2p")
            .build()
    }

    fun serverTransportBuilder(): ChannelHandler {
        val sslContext = quicSslContext(null)
        return QuicServerCodecBuilder()
            .sslEngineProvider({ q -> sslContext.newEngine(q.alloc()) })
                .maxIdleTimeout(5000, TimeUnit.MILLISECONDS)
            .sslTaskExecutor(workerGroup)
            .tokenHandler(object: QuicTokenHandler {
                override fun writeToken(out: ByteBuf?, dcid: ByteBuf?, address: InetSocketAddress?): Boolean {
                    TODO("Not yet implemented")
                }

                override fun validateToken(token: ByteBuf?, address: InetSocketAddress?): Int {
                    TODO("Not yet implemented")
                }

                override fun maxTokenLength(): Int {
                    return 32
                }
            })
            .streamHandler(ChannelInboundHandlerAdapter())
            .build()
    }

    fun udpPortFromMultiaddr(addr: Multiaddr) =
        addr.components.find { p -> p.protocol == UDP }
            ?.stringValue?.toInt() ?: throw Libp2pException("Missing UDP in multiaddress $addr")

    fun fromMultiaddr(addr: Multiaddr): SocketAddress {
        val host = hostFromMultiaddr(addr)
        val port = udpPortFromMultiaddr(addr)
        return InetSocketAddress(host, port)
    }

    fun toMultiaddr(addr: InetSocketAddress): Multiaddr {
        val proto = when (addr.address) {
            is Inet4Address -> IP4
            is Inet6Address -> IP6
            else -> throw InternalErrorException("Unknown address type $addr")
        }
        return Multiaddr.empty()
            .withComponent(proto, addr.address.hostAddress)
            .withComponent(UDP, addr.port.toString())
            .withComponent(QUIC)
    }
}
