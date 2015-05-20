import com.sun.jndi.ldap.LdapCtxFactory;

import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.*;
import java.io.*;
import java.net.InetAddress;
import java.util.*;

public class LdapChecker {

    private static final String INITIAL_CONTEXT_FACTORY_IMPLEMENTATION = "com.sun.jndi.dns.DnsContextFactory";
    private static final String DNS = "dns:";
    private static final String LDAP_TAP_PREFIX = "_ldap._tcp.";
    private static final String SRV = "SRV";
    private static final String LDAP = "ldap://";
    private static final String SLASH = "/";
    private static final int REACHABLE_TIMEOUT = 5000;
    private static final String SPECIAL_CHARACTER_AT = "@";
    private static final String RESULTS_TXT = "results.txt";
    private static final String UTF_8 = "UTF-8";
    private static final String CONFIGURATION_FILE_NAME = "common.properties";
    private static final String EQUALS = "=";
    private static final String LDAP_USER_BASE = "ldap.user.base";
    private static final String LDAP_USER_QUERY = "ldap.user.query";
    private static final String LDAP_USER_ATTRIBUTES = "ldap.user.attributes";
    private static final String COMMA = ",";
    private static final String LDAP_GLOBAL_URL_ATTRIBUTE = "ldap.global.url";

    private String LDAP_BASE;
    private String LDAP_QUERY;
    private String[] LDAP_SEARCH_ATTRIBUTES;
    private String LDAP_GLOBAL_URL;
    private PrintWriter fileWriter;

    public static void main (String[] args) {
        List<String> servers;
        String login = "";
        String password = "";
        String domain = "";

        try {
            BufferedReader bread = new BufferedReader(new InputStreamReader(System.in));
            System.out.println("Enter login:");
            login = bread.readLine();
            System.out.println("Enter password:");
            Console console = System.console();
            char[] passString = console.readPassword();
            password = new String(passString);
            System.out.println("Enter domain");
            domain = bread.readLine();
            bread.close();
            System.out.println("--------------------------");

            LdapChecker main = new LdapChecker();
            main.fileWriter = new PrintWriter(new OutputStreamWriter(new FileOutputStream(new File(RESULTS_TXT), true), UTF_8));

            System.out.println("Reading ldap parameters from the properties file...");
            main.readLdapParameters();
            System.out.println("Successfully read");
            main.fileWriter.println("-------Init Ldap check for user '" + login + "' with domain '" + domain + "'-------");

            if (main.useGlobalUrl()) {
                System.out.println("Check direct Ldap Global Url...");
                main.fileWriter.println("Direct Ldap server is specified: " + main.LDAP_GLOBAL_URL);
                servers = new ArrayList<String>();
                servers.add(main.LDAP_GLOBAL_URL);
            } else {
                System.out.println("Getting top servers...");
                servers = main.selectTopServers(domain);
                if (servers == null || servers.isEmpty()) {
                    System.out.println("No servers found");
                    return;
                }
                System.out.println("Servers received success");
            }

            System.out.println("Getting ldap attributes...");
            for (String ldapUrl : servers) {
                Map<String, List<String>> userAttributes = main.getUserAttributes(login, password, domain, ldapUrl);
                if (userAttributes != null) {
                    main.fileWriter.println("From ldap '" + ldapUrl + "' next attributes were received:\n\t" + userAttributes);
                }
            }
            System.out.println("Finish receiving ldap attributes");
            main.fileWriter.close();
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }


    private List<String> getADServers(String domain) {
        List<String> serverList = null;
        DirContext ctx = null;
        try {
            Hashtable<String, String> env = new Hashtable<String, String>();
            env.put(Context.INITIAL_CONTEXT_FACTORY, INITIAL_CONTEXT_FACTORY_IMPLEMENTATION);
            env.put(Context.PROVIDER_URL, DNS);
            ctx = new InitialDirContext(env);

            Attributes attributes = ctx.getAttributes(LDAP_TAP_PREFIX + domain, new String[]{SRV});
            Attribute a = attributes.get(SRV);

            serverList = new ArrayList<String>();
            for (NamingEnumeration n = a.getAll(); n.hasMore(); ) {
                String serverString = (String) n.next();
                fileWriter.println("Receive for domain '" + domain + "' server string '" + serverString + "'");
                String[] tokens = serverString.split("\\s+");
                String server = tokens[3];
                if (server.endsWith(".")) {
                    server = server.substring(0, server.length() - 1);
                }
                serverList.add(server);
            }
        } catch (NamingException e) {
            return null;
        } finally {
            try {
                if (ctx != null) {
                    ctx.close();
                }
            } catch (NamingException e) {
                //  Who cares?
            }
        }
        return serverList;
    }

    public List<String> selectTopServers(String domain) {
        List<String> serverList = getADServers(domain);
        List<String> retList = new ArrayList<String>(serverList.size());
        for (String serverListItem : serverList) {
            long start = System.currentTimeMillis();
            try {
                if (InetAddress.getByName(serverListItem).isReachable(REACHABLE_TIMEOUT)) {
                    long duration = System.currentTimeMillis() - start;
                    fileWriter.println("Server '" + serverListItem + "' in domain '" + domain + "' ping=" + duration);
                    retList.add(LDAP + serverListItem + SLASH);
                }
            } catch (IOException e) {
                fileWriter.println("Server '" + serverListItem + "' in domain '" + domain + "' was not able to ping in " + REACHABLE_TIMEOUT);
            }
        }

        return retList;
    }

    public Map<String, List<String>> getUserAttributes(String login, String password, String domain, String ldapUrl) {

        Properties authorizationProperties = prepareAuthorizationProperties(login, domain, password);
        Map<String, List<String>> attrMap = getUserAttributesFromLdap(login, ldapUrl, authorizationProperties);
        return attrMap;
    }

    private Map<String, List<String>> getUserAttributesFromLdap(String username, String ldapUrl, Properties authorizationProperties) {
        String searchFilter = String.format(LDAP_QUERY, username);

        SearchControls searchControls = new SearchControls();
        searchControls.setReturningAttributes(LDAP_SEARCH_ATTRIBUTES);
        searchControls.setSearchScope(SearchControls.SUBTREE_SCOPE);

        DirContext context = null;
        NamingEnumeration answer = null;
        try {
            context = LdapCtxFactory.getLdapCtxInstance(ldapUrl, authorizationProperties);
            answer = context.search(LDAP_BASE, searchFilter, searchControls);
            if (answer.hasMore()) {
                SearchResult sr = (SearchResult) answer.next();
                Attributes attributes = sr.getAttributes();
                Map<String, List<String>> attrMap = new HashMap<String, List<String>>();
                for (NamingEnumeration n = attributes.getAll(); n.hasMore(); ) {
                    Attribute a = (Attribute) n.next();
                    if (a.size() == 1) {
                        List<String> lst = new ArrayList<String>();
                        Collections.addAll(lst, a.get().toString());
                        attrMap.put(a.getID(), lst);
                    } else {
                        ArrayList<String> resultAttributeValues = new ArrayList<String>();
                        NamingEnumeration<?> attributeValues = a.getAll();
                        while (attributeValues.hasMore()) {
                            resultAttributeValues.add(attributeValues.next().toString());
                        }
                        attrMap.put(a.getID(), resultAttributeValues);
                    }
                }

                return attrMap;
            } else {
                return null;
            }
        } catch (NamingException e) {
            System.out.println("Error getting user attributes. Read result file for details.");
            fileWriter.println("Error getting user attributes from ldap '" + ldapUrl + "':" + e.toString());
            return null;
        } finally {
            try {
                if (answer != null) {
                    answer.close();
                }
                if (context != null) {
                    context.close();
                }
            } catch (NamingException e) {
                //  Forget it
            }
        }
    }

    private Properties prepareAuthorizationProperties(String username, String domain, String password) {
        String principalName = username + SPECIAL_CHARACTER_AT + domain;

        Properties authorizationProperties = new Properties();
        authorizationProperties.setProperty(Context.SECURITY_PRINCIPAL, principalName);
        authorizationProperties.setProperty(Context.SECURITY_CREDENTIALS, password);

        return authorizationProperties;
    }

    private void readLdapParameters() throws IOException {
        BufferedReader bread = new BufferedReader(new FileReader(CONFIGURATION_FILE_NAME));

        Map<String, String> parameters = new HashMap<String, String>();
        String line = bread.readLine();
        while (line != null) {
            int splitIndex = line.indexOf(EQUALS);
            if (splitIndex != -1) {
                parameters.put(line.substring(0, splitIndex), line.substring(splitIndex + 1));
            }
            line = bread.readLine();
        }
        this.LDAP_BASE = parameters.get(LDAP_USER_BASE);
        this.LDAP_QUERY = parameters.get(LDAP_USER_QUERY);
        this.LDAP_SEARCH_ATTRIBUTES = parameters.get(LDAP_USER_ATTRIBUTES).split(COMMA);
        this.LDAP_GLOBAL_URL = parameters.get(LDAP_GLOBAL_URL_ATTRIBUTE);
    }

    private boolean useGlobalUrl() {
        return LDAP_GLOBAL_URL != null && LDAP_GLOBAL_URL.length() > 0;
    }
}