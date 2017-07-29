/*
 * Copyright 2017 The Netty Project
 *
 * The Netty Project licenses this file to you under the Apache License,
 * version 2.0 (the "License"); you may not use this file except in compliance
 * with the License. You may obtain a copy of the License at:
 *
 *   http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS, WITHOUT
 * WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied. See the
 * License for the specific language governing permissions and limitations
 * under the License.
 */
package io.netty.handler.ssl;

import static io.netty.handler.ssl.SslUtils.toSSLHandshakeException;
import static java.lang.Math.min;

import javax.net.ssl.SSLEngine;
import javax.net.ssl.SSLEngineResult;
import javax.net.ssl.SSLException;
import java.lang.reflect.Method;
import java.nio.ByteBuffer;
import java.util.Collections;
import java.util.List;

import org.conscrypt.Conscrypt;
import org.conscrypt.HandshakeListener;

import io.netty.handler.ssl.JdkApplicationProtocolNegotiator.EngineConfigurator;
import io.netty.util.internal.PlatformDependent;

/**
 * A {@link JdkSslEngine} that uses the Conscrypt provider or SSL with ALPN.
 */
final class ConscryptAlpnSslEngine extends JdkSslEngine {
    private static final Class<?> ENGINES_CLASS = getEnginesClass();

    /**
     * Indicates whether or not conscrypt is available on the current system.
     */
    static boolean isAvailable() {
        return ENGINES_CLASS != null && PlatformDependent.javaVersion() >= 8;
    }

    static boolean isEngineSupported(SSLEngine engine) {
        return isAvailable() && isConscryptEngine(engine, ENGINES_CLASS);
    }

    static ConscryptAlpnSslEngine newClientEngine(SSLEngine engine,
            JdkApplicationProtocolNegotiator applicationNegotiator) {
        final ConscryptAlpnSslEngine clientEngine = new ConscryptAlpnSslEngine(engine, applicationNegotiator);
        final EngineConfigurator engineConfigurator = applicationNegotiator.newEngineConfigurator(clientEngine);

        // Register for completion of the handshake.
        Conscrypt.Engines.setHandshakeListener(engine, new HandshakeListener() {
            @Override
            public void onHandshakeFinished() throws SSLException {
                String protocol = Conscrypt.Engines.getAlpnSelectedProtocol(clientEngine.getWrappedEngine());
                try {
                    engineConfigurator.selected(protocol);
                } catch (Throwable e) {
                    throw toSSLHandshakeException(e);
                }
            }
        });

        return clientEngine;
    }

    static ConscryptAlpnSslEngine newServerEngine(SSLEngine engine,
            JdkApplicationProtocolNegotiator applicationNegotiator) {
        final ConscryptAlpnSslEngine serverEngine = new ConscryptAlpnSslEngine(engine, applicationNegotiator);
        final EngineConfigurator engineConfigurator = applicationNegotiator.newEngineConfigurator(serverEngine);

        // Register for completion of the handshake.
        Conscrypt.Engines.setHandshakeListener(engine, new HandshakeListener() {
            @Override
            public void onHandshakeFinished() throws SSLException {
                try {
                    String protocol = Conscrypt.Engines.getAlpnSelectedProtocol(serverEngine.getWrappedEngine());
                    engineConfigurator.select(protocol != null ? Collections.singletonList(protocol)
                            : Collections.<String>emptyList());
                } catch (Throwable e) {
                    throw toSSLHandshakeException(e);
                }
            }
        });

        return serverEngine;
    }

    private ConscryptAlpnSslEngine(SSLEngine engine, ApplicationProtocolNegotiator applicationNegotiator) {
        super(engine);

        // Set the list of supported ALPN protocols on the engine.
        List<String> protocols = applicationNegotiator.protocols();
        Conscrypt.Engines.setAlpnProtocols(engine, protocols.toArray(new String[protocols.size()]));
    }

    /**
     * Calculates the maximum size of the encrypted output buffer required to wrap the given plaintext bytes. Assumes
     * as a worst case that there is one TLS record per buffer.
     *
     * @param plaintextBytes the number of plaintext bytes to be wrapped.
     * @param numBuffers the number of buffers that the plaintext bytes are spread across.
     * @return the maximum size of the encrypted output buffer required for the wrap operation.
     */
    int calculateOutNetBufSize(int plaintextBytes, int numBuffers) {
        // Assuming a max of one frame per component in a composite buffer.
        long maxOverhead = (long) Conscrypt.Engines.maxSealOverhead(getWrappedEngine()) * numBuffers;
        // TODO(nmittler): update this to use MAX_ENCRYPTED_PACKET_LENGTH instead of Integer.MAX_VALUE
        return (int) min(Integer.MAX_VALUE, plaintextBytes + maxOverhead);
    }

    SSLEngineResult unwrap(ByteBuffer[] srcs, ByteBuffer[] dests) throws SSLException {
        return Conscrypt.Engines.unwrap(getWrappedEngine(), srcs, dests);
    }

    private static Class<?> getEnginesClass() {
        try {
            // Always use bootstrap class loader.
            Class<?> engineClass = Class.forName("org.conscrypt.Conscrypt$Engines", true,
                    ConscryptAlpnSslEngine.class.getClassLoader());
            // Ensure that it also has the isConscrypt method.
            getIsConscryptMethod(engineClass);
            return engineClass;
        } catch (Throwable ignore) {
            // Conscrypt was not loaded.
            return null;
        }
    }

    private static boolean isConscryptEngine(SSLEngine engine, Class<?> enginesClass) {
        try {
            Method method = getIsConscryptMethod(enginesClass);
            return (Boolean) method.invoke(null, engine);
        } catch (Throwable ignore) {
            return false;
        }
    }

    private static Method getIsConscryptMethod(Class<?> enginesClass) throws NoSuchMethodException {
        return enginesClass.getMethod("isConscrypt", SSLEngine.class);
    }
}
