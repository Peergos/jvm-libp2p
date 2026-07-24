package io.libp2p.transport.implementation

import io.libp2p.core.ChannelVisitor
import io.libp2p.core.Connection
import io.libp2p.core.ConnectionHandler
import io.libp2p.core.Libp2pException
import io.libp2p.core.P2PChannel
import io.libp2p.core.PeerId
import io.libp2p.core.multiformats.Multiaddr
import io.libp2p.core.multiformats.MultiaddrDns
import io.libp2p.core.multiformats.Protocol
import io.libp2p.etc.types.lazyVar
import io.libp2p.etc.types.toCompletableFuture
import io.libp2p.etc.types.toVoidCompletableFuture
import io.libp2p.etc.util.netty.nettyInitializer
import io.libp2p.transport.ConnectionUpgrader
import io.netty.bootstrap.Bootstrap
import io.netty.bootstrap.ServerBootstrap
import io.netty.channel.Channel
import io.netty.channel.ChannelHandler
import io.netty.channel.ChannelOption
import io.netty.channel.MultiThreadIoEventLoopGroup
import io.netty.channel.nio.NioIoHandler
import io.netty.channel.socket.nio.NioChannelOption
import io.netty.channel.socket.nio.NioServerSocketChannel
import io.netty.channel.socket.nio.NioSocketChannel
import org.slf4j.Logger
import org.slf4j.LoggerFactory
import java.net.Inet6Address
import java.net.InetSocketAddress
import java.net.SocketAddress
import java.net.StandardSocketOptions
import java.time.Duration
import java.util.concurrent.CompletableFuture

/**
 * A plain `NettyTransport` without embedded security and muxer
 */
abstract class PlainNettyTransport(
    private val upgrader: ConnectionUpgrader
) : NettyTransport { // class NettyTransportBase
    private var closed = false
    var connectTimeout = Duration.ofSeconds(15)

    private val logger: Logger = LoggerFactory.getLogger(PlainNettyTransport::class.java)

    private val SO_REUSEPORT: ChannelOption<Boolean> = NioChannelOption.of(StandardSocketOptions.SO_REUSEPORT)

    // SO_REUSEPORT lets a dial socket share the listener's port, so our outbound TCP connections
    // originate from our listen port and peers report our real listen mapping in identify's observedAddr -
    // which is what AutoNAT/DCUtR need for a NATed node. Unsupported on some OSes (e.g. Windows), where we
    // dial from ephemeral ports instead. (go-libp2p's reuseport TCP transport does the same.)
    private val soReusePortSupported: Boolean = try {
        java.nio.channels.SocketChannel.open().use { it.supportedOptions().contains(StandardSocketOptions.SO_REUSEPORT) }
    } catch (e: Exception) {
        logger.debug("Could not probe SO_REUSEPORT support, assuming unavailable", e)
        false
    }

    private val listeners = mutableMapOf<Multiaddr, Channel>()
    private val channels = mutableListOf<Channel>()

    private var workerGroup by lazyVar {
        MultiThreadIoEventLoopGroup(NioIoHandler.newFactory())
    }
    private var bossGroup by lazyVar {
        MultiThreadIoEventLoopGroup(1, NioIoHandler.newFactory())
    }

    private var client by lazyVar {
        Bootstrap().apply {
            group(workerGroup)
            channel(NioSocketChannel::class.java)
            option(ChannelOption.CONNECT_TIMEOUT_MILLIS, connectTimeout.toMillis().toInt())
        }
    }

    private var server by lazyVar {
        ServerBootstrap().apply {
            group(bossGroup, workerGroup)
            channel(NioServerSocketChannel::class.java)
            // Let reuse-port dial sockets share this listen port (see dial()).
            option(ChannelOption.SO_REUSEADDR, true)
            if (soReusePortSupported) option(SO_REUSEPORT, true)
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

        return allClosed.thenCompose {
            CompletableFuture.allOf(
                workerGroup.shutdownGracefully().toVoidCompletableFuture(),
                bossGroup.shutdownGracefully().toVoidCompletableFuture()
            ).thenApply { }
        }
    } // close

    override fun listen(
        addr: Multiaddr,
        connHandler: ConnectionHandler,
        preHandler: ChannelVisitor<P2PChannel>?
    ): CompletableFuture<Unit> {
        if (closed) throw Libp2pException("Transport is closed")

        val connectionBuilder = makeConnectionBuilder(connHandler, false, preHandler = preHandler)
        val channelHandler = serverTransportBuilder(connectionBuilder, addr) ?: connectionBuilder

        val listener = server.clone()
            .childHandler(
                nettyInitializer { init ->
                    registerChannel(init.channel)
                    init.addLastLocal(channelHandler)
                }
            )

        val bindComplete = listener.bind(fromMultiaddr(addr))

        bindComplete.also {
            synchronized(this@PlainNettyTransport) {
                listeners += addr to it.channel()
                it.channel().closeFuture().addListener {
                    synchronized(this@PlainNettyTransport) {
                        listeners -= addr
                    }
                }
            }
        }

        return bindComplete.toVoidCompletableFuture()
    } // listener

    protected abstract fun serverTransportBuilder(
        connectionBuilder: ConnectionBuilder,
        addr: Multiaddr
    ): ChannelHandler?

    override fun unlisten(addr: Multiaddr): CompletableFuture<Unit> {
        return listeners[addr]?.close()?.toVoidCompletableFuture()
            ?: throw Libp2pException("No listeners on address $addr")
    } // unlisten

    override fun dial(
        addr: Multiaddr,
        connHandler: ConnectionHandler,
        preHandler: ChannelVisitor<P2PChannel>?
    ): CompletableFuture<Connection> {
        if (closed) throw Libp2pException("Transport is closed")

        val remotePeerId = addr.getPeerId()
        val targetAddr = fromMultiaddr(addr)

        // A single dial attempt. A fresh connectionBuilder/handler is created per attempt because Netty
        // handlers are not @Sharable and cannot be added to a second channel's pipeline on a retry.
        // Returns the connect future (for the retry decision) and the established-connection future.
        fun dialFrom(bootstrap: Bootstrap): Pair<CompletableFuture<Channel>, CompletableFuture<Connection>> {
            val connectionBuilder = makeConnectionBuilder(connHandler, true, remotePeerId, preHandler)
            val channelHandler = clientTransportBuilder(connectionBuilder, addr) ?: connectionBuilder
            val chanFuture = bootstrap
                .handler(channelHandler)
                .connect(targetAddr)
                .also { registerChannel(it.channel()) }
            val connected = chanFuture.toCompletableFuture()
            val connection = connected.thenCompose { connectionBuilder.connectionEstablished }
            connection.whenComplete { _, _ ->
                if (connection.isCancelled) {
                    chanFuture.channel().close()
                }
            }
            return connected to connection
        }

        // Dial from an ephemeral source port (the kernel picks it); peers observe a throwaway source port.
        fun dialFromEphemeralPort(): CompletableFuture<Connection> = dialFrom(client.clone()).second

        // Reuse our listen port for the dial socket (SO_REUSEADDR + SO_REUSEPORT) so outbound connections
        // originate from our listen port; peers then observe our real listen mapping.
        fun dialReusingListenPort(listenPort: Int): Pair<CompletableFuture<Channel>, CompletableFuture<Connection>> =
            dialFrom(
                client.clone()
                    .option(ChannelOption.SO_REUSEADDR, true)
                    .option(SO_REUSEPORT, true)
                    .localAddress(InetSocketAddress(listenPort))
            )

        val listenPort = reusableListenPort(targetAddr)
        return if (soReusePortSupported && listenPort != null) {
            // Fall back to an ephemeral source port if the reuse dial's connect fails: an existing
            // (listenPort -> remote) 4-tuple makes bind/connect fail with EADDRINUSE. (handle+thenCompose
            // rather than exceptionallyCompose, which is Java 12+ and this module targets Java 11.)
            val (connected, connection) = dialReusingListenPort(listenPort)
            connected
                .handle { _, ex -> if (ex != null) dialFromEphemeralPort() else connection }
                .thenCompose { it }
        } else {
            dialFromEphemeralPort()
        }
    } // dial

    protected abstract fun clientTransportBuilder(
        connectionBuilder: ConnectionBuilder,
        addr: Multiaddr
    ): ChannelHandler?

    private fun registerChannel(ch: Channel) {
        if (closed) {
            ch.close()
            return
        }

        synchronized(this@PlainNettyTransport) {
            channels += ch
            ch.closeFuture().addListener {
                synchronized(this@PlainNettyTransport) {
                    channels -= ch
                }
            }
        }
    } // registerChannel

    private fun makeConnectionBuilder(
        connHandler: ConnectionHandler,
        initiator: Boolean,
        remotePeerId: PeerId? = null,
        preHandler: ChannelVisitor<P2PChannel>?
    ) = ConnectionBuilder(
        this,
        upgrader,
        connHandler,
        initiator,
        remotePeerId,
        preHandler
    )

    protected fun handlesHost(addr: Multiaddr) =
        addr.hasAny(Protocol.IP4, Protocol.IP6, Protocol.DNS4, Protocol.DNS6, Protocol.DNSADDR)

    protected fun hostFromMultiaddr(addr: Multiaddr): String {
        val resolvedAddresses = MultiaddrDns.resolve(addr)
        if (resolvedAddresses.isEmpty()) {
            throw Libp2pException("Could not resolve $addr to an IP address")
        }

        return resolvedAddresses[0].components.find {
            it.protocol in arrayOf(Protocol.IP4, Protocol.IP6)
        }?.stringValue ?: throw Libp2pException("Missing IP4/IP6 in multiaddress $addr")
    }

    protected fun portFromMultiaddr(addr: Multiaddr) =
        addr.components.find { p -> p.protocol == Protocol.TCP }
            ?.stringValue?.toInt() ?: throw Libp2pException("Missing TCP in multiaddress $addr")

    private fun fromMultiaddr(addr: Multiaddr): InetSocketAddress {
        val host = hostFromMultiaddr(addr)
        val port = portFromMultiaddr(addr)
        return InetSocketAddress(host, port)
    } // fromMultiaddr

    /** Port of a bound listener of the same address family as [target], for a reuse-port dial, or null. */
    private fun reusableListenPort(target: InetSocketAddress): Int? {
        val targetIsV6 = target.address is Inet6Address
        val listenPort = synchronized(this@PlainNettyTransport) {
            listeners.entries
                .firstOrNull { (addr, ch) ->
                    listenAddrIsV6(addr, ch) == targetIsV6 &&
                        ((ch.localAddress() as? InetSocketAddress)?.port ?: 0) != 0
                }
                ?.let { (_, ch) -> (ch.localAddress() as? InetSocketAddress)?.port }
        } ?: return null
        // Reusing our listen port as the source port while dialing that same port on the loopback
        // interface would connect the socket to itself (TCP simultaneous open), so skip reuse there.
        // Remote peers on the same port number are unaffected: the destination IP differs.
        if (target.address?.isLoopbackAddress == true && target.port == listenPort) {
            return null
        }
        return listenPort
    }

    /**
     * The address family a listener serves, taken from the multiaddr we bound rather than the socket's
     * reported local address: the JVM binds an /ip4/0.0.0.0 listener to a dual-stack `::` socket, so the
     * socket reports IPv6 even though it serves (and should be reuse-dialed for) IPv4. DNS listen addresses,
     * which carry no IP version, fall back to the bound socket's family.
     */
    private fun listenAddrIsV6(addr: Multiaddr, ch: Channel): Boolean = when {
        addr.has(Protocol.IP6) -> true
        addr.has(Protocol.IP4) -> false
        else -> (ch.localAddress() as? InetSocketAddress)?.address is Inet6Address
    }

    override fun localAddress(nettyChannel: Channel): Multiaddr = toMultiaddr(nettyChannel.localAddress())
    override fun remoteAddress(nettyChannel: Channel): Multiaddr = toMultiaddr(nettyChannel.remoteAddress())

    abstract fun toMultiaddr(addr: SocketAddress): Multiaddr
}
