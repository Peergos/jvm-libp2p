package io.libp2p.transport.quic;

import io.libp2p.core.Connection;
import io.libp2p.core.Host;
import io.libp2p.core.crypto.KeyType;
import io.libp2p.core.dsl.HostBuilder;
import io.libp2p.core.multiformats.Multiaddr;
import io.libp2p.core.mux.StreamMuxerProtocol;
import io.libp2p.protocol.Ping;
import io.libp2p.protocol.PingController;
import io.libp2p.security.tls.TlsSecureChannel;
import io.libp2p.transport.tcp.TcpTransport;
import java.util.Random;
import java.util.concurrent.TimeUnit;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.Test;

/** Prototype check: a QUIC dial from a listening host originates from the listen port (SO_REUSEPORT). */
public class QuicReusePortTestJava {
  private static int getPort() {
    return new Random().nextInt(20_000) + 10_000;
  }

  private static Host quicHost(int port) {
    return new HostBuilder()
        .keyType(KeyType.ED25519)
        .secureTransport(QuicTransport::ECDSA)
        .transport(TcpTransport::new)
        .secureChannel(TlsSecureChannel::ECDSA)
        .muxer(StreamMuxerProtocol::getYamux)
        .protocol(new Ping())
        .listen("/ip4/127.0.0.1/udp/" + port + "/quic-v1")
        .build();
  }

  @Test
  void dialReusesTheListenPort() throws Exception {
    int portA = getPort();
    int portB = getPort();
    Host clientHost = quicHost(portA);
    Host serverHost = quicHost(portB);
    clientHost.start().get(5, TimeUnit.SECONDS);
    serverHost.start().get(5, TimeUnit.SECONDS);
    try {
      Connection conn =
          clientHost
              .getNetwork()
              .connect(serverHost.getPeerId(), new Multiaddr("/ip4/127.0.0.1/udp/" + portB + "/quic-v1"))
              .get(10, TimeUnit.SECONDS);
      System.out.println("dial local address = " + conn.localAddress());
      Assertions.assertTrue(
          conn.localAddress().toString().contains("/udp/" + portA + "/"),
          "dial should originate from our QUIC listen port " + portA + " but was " + conn.localAddress());

      // confirm the handshake completed and streams route correctly over the reused port
      PingController ping =
          conn.muxerSession().createStream(new Ping()).getController().get(5, TimeUnit.SECONDS);
      long latency = ping.ping().get(5, TimeUnit.SECONDS);
      System.out.println("ping over reuse-port dial = " + latency + "ms");
    } finally {
      clientHost.stop().get(5, TimeUnit.SECONDS);
      serverHost.stop().get(5, TimeUnit.SECONDS);
    }
  }
}
