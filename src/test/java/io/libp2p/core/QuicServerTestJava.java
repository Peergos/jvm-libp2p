package io.libp2p.core;

import io.libp2p.core.crypto.*;
import io.libp2p.core.dsl.*;
import io.libp2p.core.multiformats.*;
import io.libp2p.protocol.*;
import io.libp2p.transport.quic.*;
import kotlin.*;
import org.junit.jupiter.api.*;

import java.util.concurrent.*;

public class QuicServerTestJava {
    @Test
    @Disabled
    void ping() throws Exception {
        String localListenAddress = "/ip4/127.0.0.1/udp/40002/quic";

        Host clientHost = new HostBuilder()
                .secureTransport(QuicTransport::Ed25519)
                .build();

        Host serverHost = new HostBuilder()
                .secureTransport(QuicTransport::Ed25519)
                .protocol(new Ping())
                .listen(localListenAddress)
                .build();

        CompletableFuture<Void> clientStarted = clientHost.start();
        CompletableFuture<Void> serverStarted = serverHost.start();
        clientStarted.get(5, TimeUnit.SECONDS);
        System.out.println("Client started");
        serverStarted.get(5, TimeUnit.SECONDS);
        System.out.println("Server started");

        Assertions.assertEquals(0, clientHost.listenAddresses().size());
        Assertions.assertEquals(1, serverHost.listenAddresses().size());
        Assertions.assertEquals(
                localListenAddress + "/p2p/" + serverHost.getPeerId(),
                serverHost.listenAddresses().get(0).toString()
        );

        StreamPromise<PingController> ping =
                clientHost.getNetwork().connect(
                        serverHost.getPeerId(),
                        new Multiaddr(localListenAddress)
                ).thenApply(
                        it -> it.muxerSession().createStream(new Ping())
                )
                .get(5, TimeUnit.SECONDS);

        Stream pingStream = ping.getStream().get(5, TimeUnit.SECONDS);
        System.out.println("Ping stream created");
        PingController pingCtr = ping.getController().get(5, TimeUnit.SECONDS);
        System.out.println("Ping controller created");

        for (int i = 0; i < 10; i++) {
            long latency = pingCtr.ping().get(1, TimeUnit.SECONDS);
            System.out.println("Ping is " + latency);
        }
        pingStream.close().get(5, TimeUnit.SECONDS);
        System.out.println("Ping stream closed");

        Assertions.assertThrows(ExecutionException.class, () ->
                pingCtr.ping().get(5, TimeUnit.SECONDS));

        clientHost.stop().get(5, TimeUnit.SECONDS);
        System.out.println("Client stopped");
        serverHost.stop().get(5, TimeUnit.SECONDS);
        System.out.println("Server stopped");
    }

    @Test
    void keyPairGeneration() {
        Pair<PrivKey, PubKey> pair = KeyKt.generateKeyPair(KEY_TYPE.SECP256K1);
        PeerId peerId = PeerId.fromPubKey(pair.component2());
        System.out.println("PeerId: " + peerId.toHex());
    }
}
