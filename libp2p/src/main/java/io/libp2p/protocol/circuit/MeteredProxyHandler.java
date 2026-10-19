package io.libp2p.protocol.circuit;

import io.netty.buffer.ByteBuf;
import io.netty.channel.ChannelHandlerContext;
import io.netty.channel.ChannelInboundHandlerAdapter;
import io.netty.util.ReferenceCountUtil;
import java.util.ArrayDeque;
import java.util.concurrent.TimeUnit;
import java.util.function.Consumer;
import java.util.function.LongUnaryOperator;

/**
 * Forwards one direction of a relayed circuit, charging each chunk to the reserved target and
 * pausing as long as the charge says before forwarding more. A stream can't stop its sender by not
 * reading, so chunks arriving meanwhile are queued: the two endpoints' own flow control bounds how
 * much is in flight, and a circuit that queues more than the limit anyway is closed.
 */
class MeteredProxyHandler extends ChannelInboundHandlerAdapter {
  private final Consumer<ByteBuf> forward;
  private final Runnable closeOther;
  private final LongUnaryOperator charge;
  private final long maxQueued;
  private final ArrayDeque<ByteBuf> queue = new ArrayDeque<>();
  private long queued;
  private boolean paused;

  /**
   * @param charge given the bytes forwarded, the milliseconds to wait before forwarding more
   */
  MeteredProxyHandler(
      Consumer<ByteBuf> forward, Runnable closeOther, LongUnaryOperator charge, long maxQueued) {
    this.forward = forward;
    this.closeOther = closeOther;
    this.charge = charge;
    this.maxQueued = maxQueued;
  }

  @Override
  public void channelRead(ChannelHandlerContext ctx, Object msg) {
    if (!(msg instanceof ByteBuf)) {
      ReferenceCountUtil.release(msg);
      return;
    }
    ByteBuf buf = (ByteBuf) msg;
    if (!paused && queue.isEmpty()) {
      send(ctx, buf);
      return;
    }
    queued += buf.readableBytes();
    queue.add(buf);
    if (queued > maxQueued) {
      releaseQueued();
      ctx.close();
      closeOther.run();
    }
  }

  private void send(ChannelHandlerContext ctx, ByteBuf buf) {
    long delay = charge.applyAsLong(buf.readableBytes());
    forward.accept(buf);
    if (delay > 0) {
      paused = true;
      ctx.executor().schedule(() -> resume(ctx), delay, TimeUnit.MILLISECONDS);
    }
  }

  private void resume(ChannelHandlerContext ctx) {
    paused = false;
    while (!paused && !queue.isEmpty()) {
      ByteBuf next = queue.poll();
      queued -= next.readableBytes();
      if (!ctx.channel().isActive()) {
        next.release();
        continue;
      }
      send(ctx, next);
    }
  }

  private void releaseQueued() {
    for (ByteBuf b : queue) b.release();
    queue.clear();
    queued = 0;
  }

  @Override
  public void channelInactive(ChannelHandlerContext ctx) throws Exception {
    releaseQueued();
    super.channelInactive(ctx);
  }
}
