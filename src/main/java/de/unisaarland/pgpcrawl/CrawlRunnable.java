package de.unisaarland.pgpcrawl;

import org.apache.commons.io.IOUtils;
import org.json.JSONArray;
import org.json.JSONObject;

import java.io.IOException;
import java.net.HttpURLConnection;
import java.net.SocketTimeoutException;
import java.net.URL;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.*;

/**
 * Created by tobias on 5/7/15.
 */
public class CrawlRunnable implements Callable<Identity> {

    private final String keyId;
    private final int currentDepth;
    private final ConcurrentHashMap<String, Identity> idMap;
    private final ExecutorService threadPool;
    private final Set<CrawlRunnable> activeCrawlers;

    private static final Semaphore httpSemaphore = new Semaphore(50);

    public CrawlRunnable(String keyId, int currentDepth, ConcurrentHashMap<String, Identity> idMap, ExecutorService threadPool, Set<CrawlRunnable> activeCrawlers) {
        this.keyId = keyId;
        this.currentDepth = currentDepth;
        this.idMap = idMap;
        this.threadPool = threadPool;
        this.activeCrawlers = activeCrawlers;
    }

    @Override
    public Identity call() throws Exception {
        // Check if ignored.
        if (Main.ignoredKeys.contains(keyId)) {
            activeCrawlers.remove(this);
            throw new Exception("Was thread for ignored key");
        }

        // return existing id if possible
        Identity newId = new Identity(keyId);
        Identity oldId = idMap.putIfAbsent(keyId, newId);
        if (oldId != null) {
            activeCrawlers.remove(this);
            return oldId;
        }

        // So we have a new identity. Fetch key first.
        String jsonString;
        try {
//            jsonString = IOUtils.toString(URI.create(Main.searchUrlStart + keyId), Charsets.UTF_8);
            httpSemaphore.acquire();
            URL url = new URL(Main.searchUrlStart + keyId);
            HttpURLConnection huc;
            byte failCounter = -1;
            do {
                huc = (HttpURLConnection) url.openConnection();
                huc.setConnectTimeout(10000);
                huc.setReadTimeout(20000);
                huc.connect();

                failCounter++;
                if (failCounter > 5) {
                    System.out.println("\nGiving up trying to get identity for " + keyId + " due to too many errors.");
                    activeCrawlers.remove(this);
                    return newId;
                }
            } while (huc.getResponseCode() != 200);

            jsonString = IOUtils.toString(huc.getInputStream());
        } catch (SocketTimeoutException e) {
            System.out.println("\nSocket read timed out for keyId " + keyId);
            activeCrawlers.remove(this);
            return newId;
        } catch (IOException e) {
            e.printStackTrace();
            activeCrawlers.remove(this);
            return newId;
        } finally {
            httpSemaphore.release();
        }
        JSONObject jsonObject = jsonObject = new JSONObject(jsonString);

        // Check if there were any hits.
        jsonObject = jsonObject.getJSONObject("hits");
        if (jsonObject.getInt("total") < 1) {
            activeCrawlers.remove(this);
            throw new Exception("No hits.");
        }

        if (jsonObject.getInt("total") > 1) {
            System.out.println("\nMultiple hits for identity " + keyId + "! Using first one");
        }

        JSONObject completeKey = jsonObject.getJSONArray("hits").getJSONObject(0).getJSONObject("_source");
        JSONArray packets = completeKey.getJSONArray("packets");

        HashMap<String, JSONObject> keySigMap = new HashMap<>(packets.length());

        for (int i = 0; i < packets.length(); i++) {
            JSONObject packet = packets.getJSONObject(i);
            if (!packet.has("tag_id") || packet.getInt("tag_id") != 2) {
                // skip non-signature packet
                continue;
            }

            // Look for issuer sub-packet (they are usually at the end)
            if (!packet.has("subpackets")) {
                // Strange signature packet without subpackets, skip
                continue;
            }

            JSONArray subpackets = packet.getJSONArray("subpackets");
            for (int j = subpackets.length() - 1; j > 0; j--) {
                JSONObject subpacket = subpackets.getJSONObject(j);
                if (subpacket.getInt("type_id") != 16) {
                    // Skip non-issuer subpackets here
                    continue;
                }
                // if issuer found, put in keySigMap
                String issuer = subpacket.getString("key_id");
                if (!keySigMap.containsKey(issuer) && !issuer.equals(keyId)) {
                    keySigMap.put(issuer, packet);
                }
                break;
            }
        }

//        System.out.println("Key: " + keyId + ", signatures: " + keySigMap.size());

        // if no signatures are found, we are in a dead end and do not need to recurse further
        if (keySigMap.size() == 0) {
            activeCrawlers.remove(this);
            return newId;
        }

        // Now start identity creation / retrieval
        HashMap<Identity, JSONObject> idSigMap = new HashMap<>(keySigMap.size());
        HashMap<Future<Identity>, JSONObject> futureIdSigMap = new HashMap<>(keySigMap.size());
        for (Map.Entry<String, JSONObject> entry : keySigMap.entrySet()) {
            // Try to look up existing id first
            Identity id = idMap.get(entry.getKey());
            if (id != null) {
                idSigMap.put(id, entry.getValue());
            } else {
                // Do not add additional nodes when max depth has been reached
                if (currentDepth >= 0) {
                    // if none exists yet, create a new thread that creates it. (This is breadth-first search)
                    CrawlRunnable idCrawler = new CrawlRunnable(entry.getKey(), currentDepth - 1, idMap, threadPool, activeCrawlers);
                    activeCrawlers.add(idCrawler);
                    Future<Identity> identityFuture = threadPool.submit(idCrawler);
                    futureIdSigMap.put(identityFuture, entry.getValue());
                }
            }
        }

        // Now that all creation threads were started, we wait for them to complete.
        for (Map.Entry<Future<Identity>, JSONObject> entry : futureIdSigMap.entrySet()) {
            try {
                Identity identity = entry.getKey().get();
                if (identity != null)
                    idSigMap.put(identity, entry.getValue());
            } catch (InterruptedException | ExecutionException e) {
                // Waiting too long / no result possible
            }
        }

        // Now we actually parse all signatures and create Signature objects
        for (Map.Entry<Identity, JSONObject> entry : idSigMap.entrySet()) {
            Identity signer = entry.getKey();
            JSONObject signaturePacket = entry.getValue();

            // Find signature creation time subpacket (usually first)
            JSONArray subpackets = signaturePacket.getJSONArray("subpackets");
            for (int j = 0; j < subpackets.length(); j++) {
                JSONObject subpacket = subpackets.getJSONObject(j);
                if (subpacket.getInt("type_id") != 2) {
                    // Skip non-creation-time subpackets here
                    continue;
                }
                // if creation time found, create signature object
                long creationTime = subpacket.getLong("creation_time");
                Signature sig = new Signature(creationTime, signer, newId);
                newId.incomingSignatures.put(signer, sig);
                signer.outgoingSignatures.put(newId, sig);
                break;
            }
        }

//        System.out.println("Finished creation of identity for key " + keyId);
        activeCrawlers.remove(this);
        return newId;
    }
}
