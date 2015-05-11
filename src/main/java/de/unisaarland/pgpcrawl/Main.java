package de.unisaarland.pgpcrawl;

import org.apache.commons.io.IOUtils;
import org.elasticsearch.client.Client;
import org.elasticsearch.client.transport.TransportClient;
import org.elasticsearch.common.transport.InetSocketTransportAddress;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.util.*;
import java.util.concurrent.*;

/**
 * Main class of pgp-crawler.
 * Created by tobias on 5/7/15.
 */
public class Main {
    public static final String searchUrlStart = "https://keyserver-elasticsearch.daylightpirates.org/keyserver/_search?q=key_id:";
//    public static final String searchUrlStart = "http://127.0.0.1:9200/keyserver1/_search?q=key_id:";

    public static final String initialKeyId = "373002372679ae34";
    public static final int depth = 4;
    public static final boolean useNames = true;

    public static final List<String> ignoredKeys = Collections.synchronizedList(new ArrayList<String>());

    static {
        ignoredKeys.add("d2bb0d0165d0fd58"); // CACert
    }

    public static void main(String[] args) {
//        Client client = new TransportClient()
//                .addTransportAddress(new InetSocketTransportAddress("keyserver-elasticsearch.daylightpirates.org", 9300));
//
//        try {
//            client.prepareCount("keyserver").execute().get();
//        } catch (InterruptedException e) {
//            e.printStackTrace();
//        } catch (ExecutionException e) {
//            e.printStackTrace();
//        }
//        System.exit(0);

        ConcurrentHashMap<String, Identity> idMap = new ConcurrentHashMap<>();
        ExecutorService threadPool = Executors.newCachedThreadPool();
        Set<CrawlRunnable> activeCrawlers = Collections.newSetFromMap(new ConcurrentHashMap<CrawlRunnable, Boolean>());

        CrawlRunnable rootIdCrawler = new CrawlRunnable(initialKeyId, depth - 1, idMap, threadPool, activeCrawlers);
        activeCrawlers.add(rootIdCrawler);
        Future<Identity> future = threadPool.submit(rootIdCrawler);

//        try {
//            future.get(30, TimeUnit.SECONDS);
//        } catch (TimeoutException e) {
//            future.cancel(true);
//        } catch (InterruptedException e) {
//            e.printStackTrace();
//        } catch (ExecutionException e) {
//            e.printStackTrace();
//        }

        boolean finished = false;
        int lastActiveSize = 0, secondsSinceLastChange = 0, activeSeconds = 0;
        while (!finished) {
            try {
                // Status output
                secondsSinceLastChange++;
                activeSeconds++;
                if (lastActiveSize != activeCrawlers.size()) {
                    secondsSinceLastChange = 0;
                    lastActiveSize = activeCrawlers.size();
                }
                if (secondsSinceLastChange > 60) {
                    System.out.println("\nStopping thread pool because the remaining threads seem to hang");
                    threadPool.shutdownNow();
                    break;
                }
                System.out.print("\r                                                                            \r");
                System.out.print("Active: " + activeSeconds + " sec, still waiting: " + activeCrawlers.size() +
                        " / " + (idMap.size() + activeCrawlers.size()) + (secondsSinceLastChange > 30 ?
                        ", potentially hanging, killing in " + (60 - secondsSinceLastChange) + " sec" : ""));

                // Actually useful stuff.
                finished = threadPool.awaitTermination(1, TimeUnit.SECONDS);
                if (!finished && activeCrawlers.size() == 0) {
                    System.out.println("\nStopping thread pool because there are no more active threads");
                    threadPool.shutdownNow();
                    break;
                }
            } catch (InterruptedException e) {
                e.printStackTrace();
                finished = false;
            }
        }

        System.out.println("Done crawling, creating graph files.");

        List<String> names;
        if (useNames) {
            try {
                names = IOUtils.readLines(new FileInputStream("names.txt"));
                Collections.shuffle(names);
            } catch (IOException e) {
                e.printStackTrace();
                names = Collections.emptyList();
            }
        } else names = Collections.emptyList();

        Iterator<String> nameIt = names.iterator();
        Map<String, String> nameMap = new HashMap<>();
        for (String id : idMap.keySet()) {
            if (nameIt.hasNext()) {
                nameMap.put(id, nameIt.next());
            } else {
                nameMap.put(id, id);
            }
        }

        // Count signatures for file headers
        int signatures = 0;
        for (Identity id : idMap.values()) {
            for (Signature sig : id.incomingSignatures.values()) {
                signatures++;
            }
        }

        // Build dot and iwot graph
        StringBuilder dotGraph = new StringBuilder(), iwotGraph = new StringBuilder();
        String header = "// Graph created on " + new Date().toString() + " by pgp-crawl in " + activeSeconds +
                " seconds, start node: " + (useNames ? nameMap.get(initialKeyId) : initialKeyId) + ", depth: " + depth +
                ", keys: " + idMap.size() + ", signatures: " + signatures + "\n";
        dotGraph.append(header);
        iwotGraph.append(header);
        dotGraph.append("digraph pgp {\n");
        for (Identity id : idMap.values()) {
            for (Signature sig : id.incomingSignatures.values()) {
                String signerName = nameMap.get(sig.signer.keyId), signeeName = nameMap.get(sig.signee.keyId);
                dotGraph.append("\t\"");
                dotGraph.append(signerName);
                iwotGraph.append(signerName);
                dotGraph.append("\" -> \"");
                dotGraph.append(signeeName);
                dotGraph.append('\"');
                if (sig.creationTimestamp < 1401580800l) { // 06/01/2014 @ 12:00am (UTC)
                    dotGraph.append("[color=red,penwidth=1.5]");
                    iwotGraph.append(" => ");
                } else {
                    iwotGraph.append(" -> ");
                }
                iwotGraph.append(signeeName);
                dotGraph.append(";");
                dotGraph.append('\n');
                iwotGraph.append(", ");
            }
            iwotGraph.append('\n');
        }
        dotGraph.append("}");

        System.out.println("Created keys: " + idMap.size() + ", created signatures: " + signatures +
                (useNames ? ", starting key name: " + nameMap.get(initialKeyId) : ""));

        String baseFileName = "graph_depth-" + depth + "_start-" + (useNames ? nameMap.get(initialKeyId) : initialKeyId)
                + "_" + new Date().getTime();

        File dotFile = new File(baseFileName + ".dot");
        try {
            IOUtils.write(dotGraph.toString(), new FileOutputStream(dotFile));
        } catch (IOException e) {
            e.printStackTrace();
        }

        File iwotFile = new File(baseFileName + ".iwot");
        try {
            IOUtils.write(iwotGraph.toString(), new FileOutputStream(iwotFile));
        } catch (IOException e) {
            e.printStackTrace();
        }

    }


}
