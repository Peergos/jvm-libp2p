package io.libp2p.transport.quic

import io.libp2p.core.*
import io.libp2p.core.crypto.PrivKey
import io.libp2p.core.multiformats.Multiaddr
import io.libp2p.core.multiformats.MultiaddrDns
import io.libp2p.core.multiformats.Protocol
import io.libp2p.core.multiformats.Protocol.*
import io.libp2p.core.security.SecureChannel
import io.libp2p.core.transport.Transport
import io.libp2p.crypto.keys.generateEcdsaKeyPair
import io.libp2p.crypto.keys.generateEd25519KeyPair
import io.libp2p.etc.REMOTE_PEER_ID
import io.libp2p.etc.types.lazyVar
import io.libp2p.etc.types.toVoidCompletableFuture
import io.libp2p.etc.util.netty.nettyInitializer
import io.libp2p.security.tls.*
import io.libp2p.transport.implementation.ConnectionOverNetty
import io.netty.bootstrap.Bootstrap
import io.netty.bootstrap.ServerBootstrap
import io.netty.buffer.PooledByteBufAllocator
import io.netty.channel.*
import io.netty.channel.epoll.Epoll
import io.netty.channel.epoll.EpollDatagramChannel
import io.netty.channel.nio.NioEventLoopGroup
import io.netty.channel.socket.nio.NioDatagramChannel
import io.netty.channel.socket.nio.NioServerSocketChannel
import io.netty.incubator.codec.quic.QuicChannel
import io.netty.incubator.codec.quic.QuicSslContextBuilder
import java.net.*
import java.time.Duration
import java.util.*
import java.util.concurrent.CompletableFuture

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
            .channel(if (Epoll.isAvailable()) {
                EpollDatagramChannel::class.java
            } else {
                NioDatagramChannel::class.java
            })
            .option(ChannelOption.CONNECT_TIMEOUT_MILLIS, connectTimeout.toMillis().toInt())
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
    } // close

    override fun listen(addr: Multiaddr, connHandler: ConnectionHandler, preHandler: ChannelVisitor<P2PChannel>?): CompletableFuture<Unit> {
        if (closed) throw Libp2pException("Transport is closed")

        val channelHandler = serverTransportBuilder(addr)

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

        val channelHandler = clientTransportBuilder(addr)

        val chanFuture = QuicChannel.newBootstrap(client.clone()
            .remoteAddress(fromMultiaddr(addr))
            .handler(channelHandler)
            .connect().channel())
            // Use the same allocator for the streams.
            .streamOption(ChannelOption.ALLOCATOR, allocator)
            .option(ChannelOption.AUTO_READ, true)
            .option(ChannelOption.ALLOCATOR, allocator)
            .remoteAddress(fromMultiaddr(addr))
            .streamHandler(object : ChannelHandler {
                override fun handlerAdded(ctx: ChannelHandlerContext?) {
                    TODO("Not yet implemented")
                }

                override fun handlerRemoved(ctx: ChannelHandlerContext?) {
                    TODO("Not yet implemented")
                }

                override fun exceptionCaught(ctx: ChannelHandlerContext?, cause: Throwable?) {
                    TODO("Not yet implemented")
                }
            })
            .connect()

        val res = CompletableFuture<Connection>()
        chanFuture.also { registerChannel(it.get()) }
        chanFuture.also {
            val connection = ConnectionOverNetty(it.get(), this, true)
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
    } // registerChannel

    protected fun handlesHost(addr: Multiaddr) =
        addr.hasAny(Protocol.IP4, Protocol.IP6, Protocol.DNS4, Protocol.DNS6, Protocol.DNSADDR)

    protected fun hostFromMultiaddr(addr: Multiaddr): String {
        val resolvedAddresses = MultiaddrDns.resolve(addr)
        if (resolvedAddresses.isEmpty())
            throw Libp2pException("Could not resolve $addr to an IP address")

        return resolvedAddresses[0].components.find {
            it.protocol in arrayOf(Protocol.IP4, Protocol.IP6)
        }?.stringValue ?: throw Libp2pException("Missing IP4/IP6 in multiaddress $addr")
    }
    override fun handles(addr: Multiaddr) =
        handlesHost(addr) &&
            addr.has(UDP) &&
            addr.has(QUIC) &&
            !addr.has(WS)

    internal class QuicClientInitializer(
        private val localKey: PrivKey,
        private val remotePeerId: PeerId?,
        private val certAlgorithm: String
    ) : ChannelInitializer<NioDatagramChannel>() {

        public override fun initChannel(ch: NioDatagramChannel) {
            remotePeerId?.also { ch.attr(REMOTE_PEER_ID).set(it) }
            val pipeline = ch.pipeline()
            val expectedRemotePeerId = ch.attr(REMOTE_PEER_ID).get()
            val handshakeComplete = CompletableFuture<SecureChannel.Session>()
            val connectionKeys = if (certAlgorithm.equals("ECDSA")) generateEcdsaKeyPair() else generateEd25519KeyPair()
            val javaPrivateKey = getJavaKey(connectionKeys.first)
            val sslContext = QuicSslContextBuilder.forClient()
                .keyManager(javaPrivateKey, null, buildCert(localKey, connectionKeys.first))
//                .clientAuth(ClientAuth.REQUIRE)
                .trustManager(Libp2pTrustManager(Optional.ofNullable(expectedRemotePeerId)))
                .applicationProtocols("libp2p")
                .build()
            val handler = sslContext.newHandler(ch.alloc())
            val engine = handler.engine()
            handler.handshakeFuture().also {
                val negotiatedProtocols = sslContext.applicationProtocolNegotiator().protocols()
                if (!negotiatedProtocols.equals(listOf("libp2p")))
                    handshakeComplete.completeExceptionally(IllegalStateException("Quic handshake failed. Negotiated: " + negotiatedProtocols))
                else
                    handshakeComplete.complete(SecureChannel.Session(
                        PeerId.fromPubKey(localKey.publicKey()),
                        verifyAndExtractPeerId(engine.session.peerCertificates),
                        getPublicKeyFromCert(engine.session.peerCertificates),
                        "libp2p"
                    ))
            }
            pipeline.addLast(handler)
//            handshakeComplete.also { ctx.fireChannelActive() }
        }
    }

    fun serverTransportBuilder(
        addr: Multiaddr
    ): ChannelHandler = TODO(addr.toString())

    fun clientTransportBuilder(
        addr: Multiaddr
    ): ChannelHandler = QuicClientInitializer(localKey, addr.getPeerId(), certAlgorithm)

    fun udpPortFromMultiaddr(addr: Multiaddr) =
        addr.components.find { p -> p.protocol == Protocol.UDP }
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
