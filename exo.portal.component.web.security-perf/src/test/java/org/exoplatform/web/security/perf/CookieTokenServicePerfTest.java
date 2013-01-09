package org.exoplatform.web.security.perf;

import java.io.File;
import java.net.URL;
import java.text.NumberFormat;
import java.util.HashMap;
import java.util.HashSet;
import java.util.Locale;
import java.util.Map;
import java.util.Map.Entry;
import java.util.Set;
import java.util.TreeMap;

import org.exoplatform.commons.utils.PropertyManager;
import org.exoplatform.component.test.AbstractKernelTest;
import org.exoplatform.component.test.ConfigurationUnit;
import org.exoplatform.component.test.ConfiguredBy;
import org.exoplatform.component.test.ContainerScope;
import org.exoplatform.container.PortalContainer;
import org.exoplatform.web.security.security.CookieTokenService;
import org.gatein.wci.security.Credentials;
import org.junit.Test;

@ConfiguredBy({ @ConfigurationUnit(scope = ContainerScope.PORTAL, path = "conf/tokenservice-configuration.xml"),
    @ConfigurationUnit(scope = ContainerScope.PORTAL, path = "conf/exo.portal.component.test.jcr-configuration.xml"),
    @ConfigurationUnit(scope = ContainerScope.PORTAL, path = "conf/jcr-configuration.xml") })
public class CookieTokenServicePerfTest extends AbstractKernelTest {

    private static final String PASSWORD = "********";
    private static final int MAX_CLIENTS_PER_USER = 5;
    public static final NumberFormat NINE_FRACTION_DIGITS = NumberFormat.getNumberInstance(Locale.ENGLISH);

    static {
        NINE_FRACTION_DIGITS.setMaximumFractionDigits(9);
        NINE_FRACTION_DIGITS.setMinimumFractionDigits(9);
    }


    private CookieTokenService service;
    protected void setUp() throws Exception {
        PortalContainer container = getContainer();
        service = (CookieTokenService) container.getComponentInstance("org.exoplatform.web.security.security.PerfCookieTokenService");
        Thread.sleep(1000); // give him enough time to initialize the database
    }

    protected void beforeRunBare() {
        String foundGateInConfDir = PropertyManager.getProperty("gatein.conf.dir");
        if (foundGateInConfDir == null || foundGateInConfDir.length() == 0) {
            /* A way to get the conf directory path */
            URL tokenserviceConfUrl = Thread.currentThread().getContextClassLoader()
                    .getResource("conf/tokenservice-configuration.xml");
            File confDir = new File(tokenserviceConfUrl.getPath()).getParentFile();
            PropertyManager.setProperty("gatein.conf.dir", confDir.getAbsolutePath());
        }
        super.beforeRunBare();
    }

    public void test() {
        //First dry run
        run(10, 1);
        run(500, 3);
        run(1000, 3);
        run(1500, 3);
    }

    public static double seconds(long nanoseconds) {
        return nanoseconds / 1000000000.0d;
    }

    public static long stop(long startTime) {
        return System.nanoTime() - startTime;
    }


    public void run(int userCount, int iterationCount) {
        //System.out.println("users\t"+ userCount + "x"+ iterationCount);
        Map<Integer, Map<String, Number>> metrics = new HashMap<Integer, Map<String,Number>>(iterationCount + iterationCount/2);
        for (int i = 0; i < iterationCount; i++) {
            Map<String, Number> resultSet = new TreeMap<String, Number>();
            metrics.put(i, resultSet);

            /* create */
            long startCreate = System.nanoTime();
            Set<String> tokens = createTokens(userCount);
            resultSet.put("createAvg", new Double(seconds(stop(startCreate)) / tokens.size()));
            resultSet.put("tokenCount", tokens.size());

            /* retrieve */
            long startRetrieveAll = System.nanoTime();
            long retrieveBest = Long.MAX_VALUE;
            long retrieveWorst = 0;
            for (String token : tokens) {
                long startRetrieve = System.nanoTime();
                service.getToken(token);
                long retrievalTime = stop(startRetrieve);
                if (retrieveBest > retrievalTime) {
                    retrieveBest = retrievalTime;
                }
                if (retrieveWorst < retrievalTime) {
                    retrieveWorst = retrievalTime;
                }
            }
            resultSet.put("retrieveAvg", new Double(seconds(stop(startRetrieveAll)) / tokens.size()));
            resultSet.put("retrieveBest", new Double(seconds(retrieveBest)));
            resultSet.put("retrieveWorst", new Double(seconds(retrieveWorst)));

            /* clean */
            service.deleteAll();

        }
        printAvg(iterationCount, metrics);
    }

    /**
     * @param userCount
     * @return
     */
    private Set<String> createTokens(int userCount) {
        Set<String> tokens = new HashSet<String>(userCount + userCount/2);

        for (int userIndex = 0; userIndex < userCount; userIndex++) {
            int clientCount = clientCount(userIndex);

            String username = "perfuser"+ userIndex;

            for (int clientIndex = 0; clientIndex < clientCount; clientIndex++) {
                String token;
                try {
                    token = service.createToken(new Credentials(username, PASSWORD));
                    tokens.add(token);
                } catch (NullPointerException e) {
                    e.printStackTrace();
                }
            }
        }
        return tokens;
    }

    /**
     * @param iterationCount
     * @param metrics
     */
    private void printAvg(int iterationCount, Map<Integer, Map<String, Number>> metrics) {
        Map<String, Number> avgs = new TreeMap<String, Number>();
        for (Entry<Integer, Map<String, Number>> en : metrics.entrySet()) {
            Map<String, Number> results = en.getValue();
            for (Entry<String, Number> resultSet : results.entrySet()) {
                String key = resultSet.getKey();
                Number avg = avgs.get(key);
                if (avg == null) {
                    avgs.put(key, resultSet.getValue());
                }
                else if ("tokenCount".equals(key)) {
                    /* do nothing - no need to compute avg for tokenCount */
                }
                else {
                    avgs.put(key, avg.doubleValue() + resultSet.getValue().doubleValue());
                }
            }
        }

        for (Entry<String, Number> avg : avgs.entrySet()) {
            if ("tokenCount".equals(avg.getKey())) {
                //System.out.println(avg.getKey() + "\t"+ avg.getValue().intValue());
            }
            else {
                //System.out.println(avg.getKey() + "\t"+ NINE_FRACTION_DIGITS.format(avg.getValue().doubleValue() / iterationCount));
                System.out.println(NINE_FRACTION_DIGITS.format(avg.getValue().doubleValue() / iterationCount));
            }
        }
    }

    private static int clientCount(int userIndex) {
        int result = 1;
        while (userIndex % 2 != 0) {
            userIndex /= 2;
            result++;
            if (result > MAX_CLIENTS_PER_USER) {
                return 1;
            }
        }
        return result;
    }

}
