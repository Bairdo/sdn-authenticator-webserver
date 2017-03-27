/**
 * Created by bairdmich on 11/01/17.
 */

import com.mashape.unirest.http.HttpResponse;
import com.mashape.unirest.http.Unirest;
import com.mashape.unirest.http.exceptions.UnirestException;

import net.jradius.client.RadiusClient;
import net.jradius.client.auth.*;
import net.jradius.dictionary.*;
import net.jradius.exception.RadiusException;
import net.jradius.packet.AccessAccept;
import net.jradius.packet.AccessRequest;
import net.jradius.packet.RadiusRequest;
import net.jradius.packet.RadiusResponse;
import net.jradius.packet.attribute.AttributeFactory;
import net.jradius.packet.attribute.AttributeList;

import org.apache.logging.log4j.LogManager;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import org.json.JSONObject;
import spark.ModelAndView;
import spark.template.velocity.VelocityTemplateEngine;

import java.io.BufferedReader;
import java.io.FileNotFoundException;
import java.io.FileReader;
import java.io.IOException;

import java.net.InetAddress;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.util.HashMap;
import java.util.Map;
import java.util.Scanner;

import static spark.Spark.get;
import static spark.Spark.head;
import static spark.Spark.post;
import static spark.SparkBase.port;


public class Main {

    static final org.apache.logging.log4j.Logger logger = LogManager.getFormatterLogger(Main.class);

    public static void main(String[] args) {

        Config config;
        try {
            config = Config.BuildFromFile(args[0]);
        } catch (IllegalArgumentException e) {
            // should of already printed the error, so just quit.
            return;
        } catch (IOException e) {
            logger.error(e);
            logger.error("Unable to read config file %s", args[0]);
            return;
        }

        Security.addProvider(new BouncyCastleProvider());

        port(config.getWebserverHTTPPort());

        post("/auth", (req, res) -> {
            String username = req.queryParams("username");
            String password = req.queryParams("password"); 

            String redirect = req.queryParams("redirect");

            if (doRadius(config, username, password) == 1) {
                if (sendAuthToController(config, req.ip(), username)){
                    return "Authenticated. " + "Redirecting to <a href=" + redirect + ">"
                            + redirect + "in 10 seconds." + "<meta http-equiv='refresh' content='10;" + redirect + "'>";
                }
                res.redirect("/login?redirect=" + redirect + "&message=Internal%20Server%20Error%20Unable%20to%20Login");
                res.status(500);
		return null;
            }

            res.redirect("/login?redirect=" + redirect + "&message=Incorrect%20Username%20or%20Password");
            res.status(400);
            return null;
        });

        get("/login", (req, res) -> {

            Map<String, Object> model = new HashMap<>();
            model.put("redirect", req.queryParams("redirect"));
            if (req.queryParams("message") != null) {
                model.put("message", req.queryParams("message"));
            } else {
                model.put("message", "");
            }

            return new ModelAndView(model, "login.vm");

        }, new VelocityTemplateEngine());

        get("/logout", (req, res) -> {
            return getLogoutHTML();
        });

        get("/logoff", (req, res) -> {
            return getLogoutHTML();
        });

        get("/loggedout", (req, res) -> {
            BufferedReader br = new BufferedReader(new FileReader("goodbye.html"));
            StringBuffer sb = new StringBuffer();
            br.lines().forEach(sb::append);
            sendDeauthToController(config, req.ip());
            return sb.toString();
        });

        post("/loggedout", (req, res) -> {
            BufferedReader br = new BufferedReader(new FileReader("goodbye.html"));
            StringBuffer sb = new StringBuffer();
            br.lines().forEach(sb::append);
            sendDeauthToController(config, req.ip());
            return sb.toString();
        });

        get("/*", (req, res) -> {
            StringBuilder target = new StringBuilder().append("redirect=")
                    .append(req.host())
                    .append(req.pathInfo());
            if (req.queryString() != null) {
                target.append("?")
                        .append(req.queryString());
            }

            res.redirect("/login?" + target.toString());

            return null;
        });
    }

    private static Object getLogoutHTML() throws FileNotFoundException {
        BufferedReader br = new BufferedReader(new FileReader("logout.html"));
        StringBuffer sb = new StringBuffer();
        br.lines().forEach(sb::append);
        return sb.toString();
    }

    private static String getMacFromIP(String arp_iface, String ip){
	logger.debug("getMacFrom IP, %d", System.currentTimeMillis());
	ArpHelper arpHelper = new ArpHelper();
        try{
            String arpTable = arpHelper.getARPTable(arp_iface);
            logger.debug("got arp table %d", System.currentTimeMillis());
            logger.debug("arptable %s", arpTable);
            for(String line : arpTable.split("\\n")){
                logger.debug("line", line);
                String[] tokens = line.split("\\s+");
                logger.debug("tokens: %s, %s, %s, %s", tokens[0], tokens[1], tokens[2], tokens[3]);
                if (ip.equals(tokens[0])){
                    logger.debug("Found arp entry ip: %s. mac %s", ip, tokens[2]);
                    logger.debug("found arp %d", System.currentTimeMillis());
                    return tokens[2];
                }
            }
        } catch (IOException e ){
            logger.warn("Exception while getting info from arp. msg: %s", e.getMessage());
        }
        logger.debug("find arp %d", System.currentTimeMillis());
        logger.warn("unable to find corresponding arp entry for ip: %s", ip);
        return null;
    }

    /**
    * @return true when successfully sent message to controller. false otherwise (so probably a good idea to let client know they are not authenticated).
    */
    private static boolean sendAuthToController(Config config, String ip, String username) {
        String mac = getMacFromIP(config.getArpIFace(), ip);
        if (mac == null){
            return false;
	}
        try {
            Map<String, String> map = new HashMap<>();
            map.put("ip", ip);
            map.put("user", username);
            map.put("mac", mac);

            HttpResponse<String> response = Unirest.post("http://{ip}:{port}/v1.1/authenticate/auth")
                    .routeParam("ip", config.getControllerIP())
                    .routeParam("port", String.valueOf(config.getControllerHTTPPort()))
                    //.header("Content-Type", "application/x-www-form-urlencoded")
                    //.routeParam("userip", ip)
                    //.routeParam("user", "NULL")
                    .header("Content-Type", "application/json")
                    .body(new JSONObject(map))
                    .asString();

            if (response.getStatus() != 200) {
                logger.warn("Http response auth request for ip='%s' user='%s': res.status='%d', body='%s'", ip, username, response.getStatus(), response.getBody());
                return false;
            }
        } catch (UnirestException e) {
            e.printStackTrace();
            return false;
        }
        return true;
    }

    private static void sendDeauthToController(Config config, String ip) {

        String mac = getMacFromIP(config.getArpIFace(), ip);
        try {

            Map<String, String> map = new HashMap<>();
            map.put("ip", ip);
            map.put("user", null);
            map.put("mac", mac);

            HttpResponse<String> response = Unirest.delete("http://{ip}:{port}/v1.1/authenticate/auth")
                    .routeParam("ip", config.getControllerIP())
                    .routeParam("port", String.valueOf(config.getControllerHTTPPort()))
                    //.header("Content-Type", "application/x-www-form-urlencoded")
                    //.routeParam("userip", ip)
                    //.routeParam("user", "NULL")
                    .header("Content-Type", "application/json")
                    .body(new JSONObject(map))
                    .asString();

            if (response.getStatus() != 200) {
                logger.warn("Http response deauth request for ip='%s' user='%s': res.status='%d', body='%s'", ip, "NULL", response.getStatus(), response.getBody());
            }
        } catch (UnirestException e) {
            e.printStackTrace();
        }
    }


    private static int doRadius(Config config, String username, String password) {
        try {

            AttributeFactory.loadAttributeDictionary("net.jradius.dictionary.AttributeDictionaryImpl");

            InetAddress host = InetAddress.getByName(config.getRadiusIP());
            RadiusClient rc = new RadiusClient(host, config.getRadiusSecret(), config.getRadiusPort(), config.getRadiusAcctPort(), 1000);

            AttributeList attrs = new AttributeList();
            attrs.add(new Attr_UserName(username));
            attrs.add(new Attr_NASPortType(Attr_NASPortType.Wireless80211));
            attrs.add(new Attr_NASPort(new Long(1)));

            RadiusRequest request = new AccessRequest(rc, attrs);
            request.addAttribute(new Attr_UserPassword(password));

            logger.debug("Sending: %s", request.toString());
            logger.debug("to:\n", rc.toString());

            RadiusAuthenticator authenticator;

            if (config.getRadiusAuthentication().equals(Config.AuthenticationTypes.CHAP)) {
                authenticator = new CHAPAuthenticator();
            } else if (config.getRadiusAuthentication().equals(Config.AuthenticationTypes.EAPMD5)) {
                authenticator = new EAPMD5Authenticator();
            } else if (config.getRadiusAuthentication().equals(Config.AuthenticationTypes.EAPMSCHAPv2)) {
                authenticator = new EAPMSCHAPv2Authenticator();
            } else if (config.getRadiusAuthentication().equals(Config.AuthenticationTypes.MSCHAPv1)) {
                authenticator = new MSCHAPv1Authenticator();
            } else if (config.getRadiusAuthentication().equals(Config.AuthenticationTypes.MSCHAPv2)) {
                authenticator = new MSCHAPv2Authenticator();
            } else if (config.getRadiusAuthentication().equals(Config.AuthenticationTypes.PAP)) {
                authenticator = new PAPAuthenticator();
            }
            // jradius-extended methods
            else if (config.getRadiusAuthentication().equals(Config.AuthenticationTypes.EAPTLS)) {
                authenticator = new EAPTLSAuthenticator();
            } else if (config.getRadiusAuthentication().equals(Config.AuthenticationTypes.EAPTTLS)) {
                authenticator = new EAPTTLSAuthenticator();
            } else if (config.getRadiusAuthentication().equals(Config.AuthenticationTypes.PEAP)) {
                authenticator = new PEAPAuthenticator();
            } else {
                // this should never ever happen, as it should be caught by the config file reader
                logger.error("Configuration file did not specify an authentication type to use, and has been detected when attempting to do RADIUS. and should have been caught in Config.java but looks like it has an error.");
                System.exit(1);
                // This return is needed so the compiler doesn't whinge about 'authenticator' not being initialized,
                // even though the return statement and also the rc.authenticate call will never be hit.
                return -1;
            }

            RadiusResponse reply = rc.authenticate((AccessRequest) request, authenticator, 5);

            logger.debug("Recieved:\n" + reply.toString());

            boolean isAuthenticated = (reply instanceof AccessAccept);

            String replyMessage = (String) reply.getAttributeValue(Attr_ReplyMessage.TYPE);

            if (replyMessage != null) {
                logger.debug("Reply Message: " + replyMessage);
            }

            if (!isAuthenticated) return 0;

            return 1;
        } catch (IOException | NoSuchAlgorithmException | RadiusException e) {
            logger.error(e);
        }
        return -1;
    }

}
