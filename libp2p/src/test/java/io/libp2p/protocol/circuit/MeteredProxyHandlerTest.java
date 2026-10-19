package io.libp2p.protocol.circuit;

import static org.junit.jupiter.api.Assertions.*;

import io.netty.buffer.ByteBuf;
import io.netty.buffer.Unpooled;
import io.netty.channel.embedded.EmbeddedChannel;
import java.util.ArrayList;
import java.util.List;
import java.util.concurrent.TimeUnit;
import java.util.concurrent.atomic.AtomicBoolean;
import org.junit.jupiter.api.Test;

public class MeteredProxyHandlerTest {

  private static ByteBuf bytes(int n) {
    return Unpooled.buffer(n).writeZero(n);
  }

  @Test
  public void forwardsAtOnceUntilChargedThenWaits() {
    List<ByteBuf> forwarded = new ArrayList<>();
    List<Long> charged = new ArrayList<>();
    EmbeddedChannel ch =
        new EmbeddedChannel(
            new MeteredProxyHandler(
                forwarded::add,
                () -> {},
                n -> {
                  charged.add(n);
                  return charged.size() >= 2 ? 100 : 0;
                },
                1 << 20));
    ch.writeInbound(bytes(10));
    ch.writeInbound(bytes(20));
    ch.writeInbound(bytes(30));
    assertEquals(2, forwarded.size(), "the second chunk is over budget, so the third waits");

    ch.advanceTimeBy(50, TimeUnit.MILLISECONDS);
    ch.runScheduledPendingTasks();
    assertEquals(2, forwarded.size());
    ch.advanceTimeBy(60, TimeUnit.MILLISECONDS);
    ch.runScheduledPendingTasks();
    assertEquals(3, forwarded.size());
    assertEquals(List.of(10L, 20L, 30L), charged);
    forwarded.forEach(ByteBuf::release);
    ch.finishAndReleaseAll();
  }

  @Test
  public void aCircuitQueueingTooMuchIsClosed() {
    List<ByteBuf> forwarded = new ArrayList<>();
    AtomicBoolean otherClosed = new AtomicBoolean();
    EmbeddedChannel ch =
        new EmbeddedChannel(
            new MeteredProxyHandler(forwarded::add, () -> otherClosed.set(true), n -> 1_000, 100));
    ch.writeInbound(bytes(10));
    ByteBuf queued = bytes(60), over = bytes(60);
    ch.writeInbound(queued);
    assertTrue(ch.isActive());
    ch.writeInbound(over);
    assertFalse(ch.isActive());
    assertTrue(otherClosed.get());
    assertEquals(0, queued.refCnt(), "what was queued is released");
    assertEquals(0, over.refCnt());
    forwarded.forEach(ByteBuf::release);
  }
}
