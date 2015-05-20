package com.exadel.controller;


import com.sun.jndi.ldap.LdapCtxFactory;

import javax.naming.Context;
import javax.naming.NamingEnumeration;
import javax.naming.NamingException;
import javax.naming.directory.*;
import java.io.*;
import java.net.InetAddress;
import java.util.*;

public class MainController {

    private static final String INITIAL_CONTEXT_FACTORY_IMPLEMENTATION = "com.sun.jndi.dns.DnsContextFactory";
    private static final String DNS = "dns:";
    private static final String LDAP_TAP_PREFIX = "_ldap._tcp.";
    private static final String SRV = "SRV";
    private static final String LDAP = "ldap://";
    private static final String SLASH = "/";
    private static final String SORT_PATTERN = "%04d/%s";
    private static final int REACHABLE_TIMEOUT = 200;
    private static final String SPECIAL_CHARACTER_AT = "@";

    private String LDAP_BASE;
    private String LDAP_QUERY;
    private String[] LDAP_SEARCH_ATTRIBUTES;
    private boolean doNotUsePing;

    public static void main (String[] args) {
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

            MainController main = new MainController();
            main.readLdapParameters();

            List<String> servers = main.selectTopServers(domain);
            if (servers == null || servers.isEmpty()) {
                System.out.println("No data");
                return;
            }

            PrintWriter writer = new PrintWriter(new OutputStreamWriter(new FileOutputStream(new File("results.txt"), true), "UTF-8"));
            for (String ldapUrl : servers) {
                Map<String, List<String>> userAttributes = main.getUserAttributes(login, password, domain, ldapUrl);
                String attributesForServer = "For " + ldapUrl + " attributes are:\n\t" + userAttributes;
                writer.println(attributesForServer);
            }
            writer.close();
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
        if (serverList.isEmpty()) {
            return null;
        }

        if (serverList.size() == 1 || doNotUsePing) {
            for (String serverListItem : serverList) {
                retList.add(LDAP + serverListItem + SLASH);
            }
            return retList;
        }

        List<String> sortList = new ArrayList<String>(serverList.size());
        for (String serverListItem : serverList) {
            Formatter f = new Formatter();
            long start = System.currentTimeMillis();
            try {
                if (InetAddress.getByName(serverListItem).isReachable(REACHABLE_TIMEOUT)) {
                    long duration = System.currentTimeMillis() - start;
                    sortList.add(f.format(SORT_PATTERN, duration, serverListItem).toString());
                }
            } catch (IOException e) {
                //Ignore
            }
        }

        if (sortList.isEmpty()) {
            doNotUsePing = true;
            for (String serverListItem : serverList) {
                retList.add(LDAP + serverListItem + SLASH);
            }
            return retList;
        }

        Collections.sort(sortList);
        for (String sortedListItem : sortList) {
            String shortLdapUrl = substringAfter(sortedListItem, "/");
            retList.add(LDAP + shortLdapUrl + SLASH);
        }
        return retList;
    }

    private String substringAfter(String str, String separator) {
        if (str.isEmpty()) {
            return str;
        }
        if (separator == null) {
            return "";
        }
        int pos = str.indexOf(separator);
        if (pos == -1) {
            return "";
        }
        return str.substring(pos + separator.length());
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
        BufferedReader bread = new BufferedReader(new FileReader("common.properties"));

        Map<String, String> parameters = new HashMap<String, String>();
        String line = bread.readLine();
        while (line != null) {
            int splitIndex = line.indexOf('=');
            if (splitIndex != -1) {
                parameters.put(line.substring(0, splitIndex), line.substring(splitIndex + 1));
            }
            line = bread.readLine();
        }
        this.LDAP_BASE = parameters.get("ldap.user.base");
        this.LDAP_QUERY = parameters.get("ldap.user.query");
        this.LDAP_SEARCH_ATTRIBUTES = parameters.get("ldap.user.attributes").split(",");
    }
}
