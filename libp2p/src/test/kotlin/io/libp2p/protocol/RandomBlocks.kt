package io.libp2p.protocol

import io.libp2p.core.BadPeerException
import io.libp2p.core.ConnectionClosedException
import io.libp2p.core.Libp2pException
import io.libp2p.core.Stream
import io.libp2p.core.multistream.StrictProtocolBinding
import io.libp2p.etc.types.completedExceptionally
import io.libp2p.etc.types.lazyVar
import io.libp2p.etc.types.toByteArray
import io.libp2p.etc.types.toHex
import io.netty.buffer.ByteBuf
import io.netty.channel.ChannelHandlerContext
import io.netty.handler.codec.ByteToMessageCodec
import java.io.*
import java.time.Duration
import java.util.Collections
import java.util.Random
import java.util.concurrent.CompletableFuture
import java.util.concurrent.Executors
import java.util.concurrent.TimeUnit

interface RandomBlocksController {
    fun requestBlocks(size: Int, count: Int): CompletableFuture<Long>
}

class RandomBlocks() : RandomBlocksBinding(RandomBlocksProtocol())

open class RandomBlocksBinding(blob: RandomBlocksProtocol) :
    StrictProtocolBinding<RandomBlocksController>("/ipfs/blob-echo/1.0.0", blob)

class RandomBlocksTimeoutException : Libp2pException()

open class RandomBlocksProtocol : ProtocolHandler<RandomBlocksController>(Long.MAX_VALUE, Long.MAX_VALUE) {
    var timeoutScheduler by lazyVar { Executors.newSingleThreadScheduledExecutor() }
    var random = Random()

    override fun onStartInitiator(stream: Stream): CompletableFuture<RandomBlocksController> {
        val handler = RandomBlocksInitiator()
        stream.pushHandler(BlobCodec())
        stream.pushHandler(handler)
        stream.pushHandler(BlobCodec())
        return handler.activeFuture
    }

    override fun onStartResponder(stream: Stream): CompletableFuture<RandomBlocksController> {
        val handler = RandomBlocksResponder()
        stream.pushHandler(BlobCodec())
        stream.pushHandler(handler)
        stream.pushHandler(BlobCodec())
        return CompletableFuture.completedFuture(handler)
    }

    open class BlobCodec : ByteToMessageCodec<ByteArray>() {
        override fun encode(ctx: ChannelHandlerContext?, msg: ByteArray, out: ByteBuf) {
            println("Codec::encode")
            out.writeInt(msg.size)
            out.writeBytes(msg)
        }

        override fun decode(ctx: ChannelHandlerContext?, msg: ByteBuf, out: MutableList<Any>) {
            println("Codec::decode " + msg.readableBytes())
            val readerIndex = msg.readerIndex()
            if (msg.readableBytes() < 4) {
                return
            }
            val len = msg.readInt()
            if (msg.readableBytes() < len) {
                // not enough data to read the full array
                // will wait for more ...
                msg.readerIndex(readerIndex)
                return
            }
            val data = msg.readSlice(len)
            out.add(data.toByteArray())
        }
    }

    open inner class RandomBlocksResponder : ProtocolMessageHandler<ByteArray>, RandomBlocksController {
        override fun onMessage(stream: Stream, msg: ByteArray) {
            println("Responder::onMessage")
            val din = DataInputStream(ByteArrayInputStream(msg))
            val size = din.readInt()
            val count = din.readInt()
            val r = Random(28)
            val arr = ByteArray(size)
            for (i in 1..count) {
                r.nextBytes(arr)
                stream.writeAndFlush(arr)
            }
        }

        override fun requestBlocks(size: Int, count: Int): CompletableFuture<Long> {
            throw Libp2pException("This is block responder only")
        }
    }

    open inner class RandomBlocksInitiator : ProtocolMessageHandler<ByteArray>, RandomBlocksController {
        val activeFuture = CompletableFuture<RandomBlocksController>()
        var remaining = 0;
        var request: CompletableFuture<Long>? = null
        lateinit var stream: Stream
        var closed = false

        override fun onActivated(stream: Stream) {
            this.stream = stream
            activeFuture.complete(this)
        }

        override fun onMessage(stream: Stream, msg: ByteArray) {
            println("Initiator::onMessage")
            remaining -= msg.size
            if (remaining == 0)
                request?.complete(0)
        }

        override fun onClosed(stream: Stream) {
            closed = true
            request?.completeExceptionally(ConnectionClosedException())
            timeoutScheduler.shutdownNow()
            activeFuture.completeExceptionally(ConnectionClosedException())
        }

        override fun requestBlocks(size: Int, count: Int): CompletableFuture<Long> {
            request = CompletableFuture<Long>()
            remaining = size * count

            if (closed) return completedExceptionally(ConnectionClosedException())

            println("Sender requesting " + count + " blocks of size " + size)
            val bout = ByteArrayOutputStream()
            val dout = DataOutputStream(bout)
            dout.writeInt(size)
            dout.writeInt(count)
            stream.writeAndFlush(bout.toByteArray())
            return request as CompletableFuture<Long>
        }
    }
}
