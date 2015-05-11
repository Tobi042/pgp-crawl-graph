package de.unisaarland.pgpcrawl;

/**
 * Created by tobias on 5/7/15.
 */
public class Signature {

    public final long creationTimestamp;
    public final Identity signer;
    public final Identity signee;

    public Signature(long creationTimestamp, Identity signer, Identity signee) {
        this.creationTimestamp = creationTimestamp;
        this.signer = signer;
        this.signee = signee;
    }
}
