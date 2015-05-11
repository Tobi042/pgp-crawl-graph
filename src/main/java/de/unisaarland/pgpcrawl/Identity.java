package de.unisaarland.pgpcrawl;

import java.util.concurrent.ConcurrentHashMap;

/**
 * Created by tobias on 5/7/15.
 */
public class Identity {

    public final String keyId;
    public final ConcurrentHashMap<Identity, Signature> incomingSignatures = new ConcurrentHashMap<>();
    public final ConcurrentHashMap<Identity, Signature> outgoingSignatures = new ConcurrentHashMap<>();

    public Identity(String keyId) {
        this.keyId = keyId;
    }
}
