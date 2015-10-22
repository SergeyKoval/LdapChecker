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
    private static final String LDAP_AUTODISCOVER_BASE = "ldap.autodiscover.base";
    private static final String LDAP_USER_QUERY = "ldap.user.query";
    private static final String LDAP_USER_ATTRIBUTES = "ldap.user.attributes";
    private static final String COMMA = ",";
    private static final String LDAP_GLOBAL_URL_ATTRIBUTE = "ldap.global.url";
    private static final String LDAP_AUTODISCOVER_FILTER = "(&(objectClass=serviceConnectionPoint)(|(keywords=67661d7F-8FC4-4fa7-BFAC-E1D7794C1F68)(keywords=77378F46-2C66-4aa9-A6A6-3E7A48B19596)))";
    private static final String LDAP_AUTODISCOVER_ATTRIBUTE = "ldap.autodiscover.attribute";

    private String LDAP_BASE;
    private String LDAP_QUERY;
    private String[] LDAP_SEARCH_ATTRIBUTES;
    private String LDAP_GLOBAL_URL;
    private String[] LDAP_AUTODISCOVER_ATTRIBUTE_VALUE;
    private PrintWriter fileWriter;
    private String AUTODISCOVER_BASE;

    public static void main (String[] args) {
        String login;
        String password;
        String domain;

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

            main.checkLdap(domain, login, password);
        } catch (FileNotFoundException e) {
            e.printStackTrace();
        } catch (UnsupportedEncodingException e) {
            e.printStackTrace();
        } catch (IOException e) {
            e.printStackTrace();
        }
    }

    private void checkLdap(String domain, String login, String password) {
        List<String> servers;
        if (LDAP_BASE == null || LDAP_BASE.length() == 0) {
            System.out.println("Parse ldap.base from domain...");
            String[] domainItems = domain.split("\\.");
            StringBuilder ldapBaseBuilder = new StringBuilder();
            for (String domainItem : domainItems) {
                ldapBaseBuilder.append("dc=");
                ldapBaseBuilder.append(domainItem);
                ldapBaseBuilder.append(",");
            }
            if (ldapBaseBuilder.length() > 0) {
                ldapBaseBuilder.deleteCharAt(ldapBaseBuilder.length() - 1);
            }
            LDAP_BASE = ldapBaseBuilder.toString();
            addMessage("ldap.base=" + LDAP_BASE);
        }
        addMessage("-------Init Ldap check for user '" + login + "' with domain '" + domain + "'-------");

        if (useGlobalUrl()) {
            System.out.println("Check direct Ldap Global Url...");
            addMessage("Direct Ldap server is specified: " + LDAP_GLOBAL_URL);

            servers = new ArrayList<String>();
            servers.add(LDAP_GLOBAL_URL);
        } else {
            System.out.println("Getting top servers...");
            servers = selectTopServers(domain);
            if (servers == null || servers.isEmpty()) {
                System.out.println("No servers found");
                return;
            }
            System.out.println("Servers received success");
        }

        System.out.println("Getting ldap attributes...");
        Properties authorizationProperties = prepareAuthorizationProperties(login, domain, password);
        for (String ldapUrl : servers) {
            addMessage("----Getting root DSE attributes--------");
            Map<String, List<String>> rootDSEAttributes = getRootDSEAttributes(ldapUrl, authorizationProperties);
            addMessageAttributes(rootDSEAttributes, ldapUrl);

            if (LDAP_SEARCH_ATTRIBUTES != null) {
                addMessage("----Getting autodiscover URL--------");
                if (AUTODISCOVER_BASE != null) {
                    addMessage("Use ldap.autodiscover.base from the configuration file: " + AUTODISCOVER_BASE);
                } else {
                    AUTODISCOVER_BASE = rootDSEAttributes.get("configurationNamingContext").get(0);
                    addMessage("Use ldap.autodiscover.base from the LDAP root DSE: " + AUTODISCOVER_BASE);
                }

                Map<String, List<String>> autodiscoverAttributes = getUserAttributesFromLdap(LDAP_AUTODISCOVER_FILTER, ldapUrl, authorizationProperties, LDAP_AUTODISCOVER_ATTRIBUTE_VALUE, AUTODISCOVER_BASE);
                addMessageAttributes(autodiscoverAttributes, ldapUrl);
            }

            addMessage("----Getting user attributes--------");
            String searchFilter = String.format(LDAP_QUERY, login);
            Map<String, List<String>> userAttributes = getUserAttributesFromLdap(searchFilter, ldapUrl, authorizationProperties, LDAP_SEARCH_ATTRIBUTES, LDAP_BASE);
            addMessageAttributes(userAttributes, ldapUrl);
        }
        addMessage("Finish receiving ldap attributes");
        fileWriter.close();
    }

    private void addMessageAttributes(Map<String, List<String>> attributes, String ldapUrl) {
        if (attributes != null && !attributes.isEmpty()) {
            StringBuilder result = new StringBuilder();
            result.append("From ldap '");
            result.append(ldapUrl);
            result.append("' next attributes were received:");
            for (String attribute : attributes.keySet()) {
                result.append("\n\t");
                result.append(attribute);
                result.append("=");
                for (String element : attributes.get(attribute)) {
                    result.append("\n\t\t");
                    result.append(element);
                }
            }

            addMessage(result.toString());
        }
    }

    private List<String> getADServers(String domain) {
        List<String> serverList = new ArrayList<String>();
        DirContext ctx = null;
        try {
            Hashtable<String, String> env = new Hashtable<String, String>();
            env.put(Context.INITIAL_CONTEXT_FACTORY, INITIAL_CONTEXT_FACTORY_IMPLEMENTATION);
            env.put(Context.PROVIDER_URL, DNS);
            ctx = new InitialDirContext(env);

            Attributes attributes = ctx.getAttributes(LDAP_TAP_PREFIX + domain, new String[]{SRV});
            Attribute a = attributes.get(SRV);

            for (NamingEnumeration n = a.getAll(); n.hasMore(); ) {
                String serverString = (String) n.next();
                addMessage("Receive for domain '" + domain + "' server string '" + serverString + "'");

                String[] tokens = serverString.split("\\s+");
                String server = tokens[3];
                if (server.endsWith(".")) {
                    server = server.substring(0, server.length() - 1);
                }
                serverList.add(server);
            }
        } catch (NamingException e) {
            addMessage("Error on working with ADServers. " + e.getMessage());
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
                    addMessage("Server '" + serverListItem + "' in domain '" + domain + "' ping=" + duration);
                    retList.add(LDAP + serverListItem + SLASH);
                }
            } catch (IOException e) {
                addMessage("Server '" + serverListItem + "' in domain '" + domain + "' was not able to ping in " + REACHABLE_TIMEOUT);
            }
        }

        return retList;
    }

    private Map<String, List<String>> getRootDSEAttributes(String ldapUrl, Properties authorizationProperties) {
        Map<String, List<String>> attrMap = new HashMap<String, List<String>>();
        try {
            DirContext context = LdapCtxFactory.getLdapCtxInstance(ldapUrl, authorizationProperties);
            SearchControls controls = new SearchControls();
            controls.setSearchScope(SearchControls.OBJECT_SCOPE);
            NamingEnumeration answer = context.search("", "(objectclass=*)", controls);
            if (answer.hasMore()) {
                SearchResult sr = (SearchResult) answer.next();
                Attributes attributes = sr.getAttributes();
                addMessage("Root DSE has " + attributes.size() + " attributes in LDAP");

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
            }
        } catch (NamingException e) {
            addMessage("Error while getting Root DSE: " + e.toString());
        } finally {
            return attrMap;
        }
    }

    private Map<String, List<String>> getUserAttributesFromLdap(String searchFilter, String ldapUrl, Properties authorizationProperties, String[] returningAttributes, String ldapBase) {
        Map<String, List<String>> attrMap = new HashMap<String, List<String>>();
        SearchControls searchControls = new SearchControls();
        searchControls.setReturningAttributes(returningAttributes);
        searchControls.setSearchScope(SearchControls.SUBTREE_SCOPE);

        DirContext context = null;
        NamingEnumeration answer = null;
        try {
            context = LdapCtxFactory.getLdapCtxInstance(ldapUrl, authorizationProperties);
            answer = context.search(ldapBase, searchFilter, searchControls);
            if (answer.hasMore()) {
                SearchResult sr = (SearchResult) answer.next();
                Attributes attributes = sr.getAttributes();
                addMessage("Get " + attributes.size() + " attributes from LDAP");

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
            StringBuilder attributesBuilder = new StringBuilder();
            for(String returningAttribute : returningAttributes) {
                attributesBuilder.append(returningAttribute);
                attributesBuilder.append(",");
            }
            String attributes = attributesBuilder.toString();
            addMessage("Error getting user attributes:" + attributes + " from ldap '" + ldapUrl + "':" + e.toString());
            return attrMap;
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

        String autodiscoverAttribute = parameters.get(LDAP_AUTODISCOVER_ATTRIBUTE);
        if (autodiscoverAttribute != null && autodiscoverAttribute.length() > 0) {
            this.AUTODISCOVER_BASE = parameters.get(LDAP_AUTODISCOVER_BASE);
            this.LDAP_AUTODISCOVER_ATTRIBUTE_VALUE = new String[]{autodiscoverAttribute};
        } else {
            this.LDAP_AUTODISCOVER_ATTRIBUTE_VALUE = null;
        }
    }

    private boolean useGlobalUrl() {
        return LDAP_GLOBAL_URL != null && LDAP_GLOBAL_URL.length() > 0;
    }

    private void addMessage(String message) {
        System.out.println(message);
        fileWriter.println(message);
    }
}