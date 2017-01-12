/**
 * Created by bairdmich on 11/01/17.
 */

import com.mashape.unirest.http.HttpResponse;
import com.mashape.unirest.http.Unirest;
import com.mashape.unirest.http.exceptions.UnirestException;
import net.jradius.client.RadiusClient;
import net.jradius.client.auth.*;
import net.jradius.exception.RadiusException;
import net.jradius.exception.UnknownAttributeException;
import net.jradius.packet.AccessAccept;
import net.jradius.packet.AccessRequest;
import net.jradius.packet.RadiusRequest;
import net.jradius.packet.RadiusResponse;
import net.jradius.packet.attribute.AttributeFactory;
import net.jradius.dictionary.Attr_NASPort;
import net.jradius.dictionary.Attr_NASPortType;
import net.jradius.dictionary.Attr_ReplyMessage;
import net.jradius.dictionary.Attr_UserName;
import net.jradius.dictionary.Attr_UserPassword;

import net.jradius.packet.attribute.AttributeList;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import spark.ModelAndView;
import spark.template.velocity.VelocityTemplateEngine;

import static spark.Spark.*;
import static spark.SparkBase.staticFileLocation;

import java.io.*;

import java.net.InetAddress;
import java.net.UnknownHostException;
import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.util.HashMap;
import java.util.Map;


public class Main {

    public static void main(String[] args) {
        Config config;
        try {
            config = Config.BuildFromFile(args[0]);
        }catch (IllegalArgumentException e){
            e.printStackTrace();
            return;
        } catch (IOException e) {
            System.err.printf("Unable to read config file %s", args[0]);
            return;
        }

        Security.addProvider(new BouncyCastleProvider());
        staticFileLocation("/public");

        post("/auth", (req, res) -> {
            String username = "host110user";//req.queryParams("username");
            String password = "host110pass"; //req.queryParams("password");



            String redirect = req.queryParams("redirect");

            if (doRadius(config, username, password) == 1) {
                sendAuthToController(config, req.ip(), username);
                return "Authenticated. " + "Redirecting to <a href=" + redirect + ">"
                        + redirect + "in 10 seconds." + "<meta http-equiv='refresh' content='10;" + redirect + "'>";
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

        get("/logout", (req, res)->{
            return getLogoutHTML();
        });

        get("/logoff", (req, res) -> {
            return getLogoutHTML();
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


    private static void sendAuthToController(Config config, String ip, String username) {
        try {
            HttpResponse<String> response = Unirest.post("http://{ip}:{port}/v1.0/authenticate/ip={userip}&user={user}")
                    .routeParam("ip", config.getControllerIP())
                    .routeParam("port", String.valueOf(config.getControllerHTTPPort()))
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .routeParam("userip", ip)
                    .routeParam("user", username)
                    .asString();

            if (response.getStatus() != 200) {
                System.err.printf("Http response: %d, body: %s", response.getStatus(), response.getBody());
            }
        } catch (UnirestException e) {
            e.printStackTrace();
        }
    }

    private static void sendDeauthToController(Config config, String ip) {
        try {
            HttpResponse<String> response = Unirest.delete("http://{ip}:{port}/v1.0/authenticate/ip={userip}&user={user}")
                    .routeParam("ip", config.getControllerIP())
                    .routeParam("port", String.valueOf(config.getControllerHTTPPort()))
                    .header("Content-Type", "application/x-www-form-urlencoded")
                    .routeParam("userip", ip)
                    .routeParam("user", "NULL")
                    .asString();

            if (response.getStatus() != 200) {
                System.err.printf("Http response: %d, body: %s", response.getStatus(), response.getBody());
            }
        } catch (UnirestException e) {
            e.printStackTrace();
        }
    }


    private static int doRadius(Config config, String username, String password){
       try{

           AttributeFactory.loadAttributeDictionary("net.jradius.dictionary.AttributeDictionaryImpl");

           InetAddress host = InetAddress.getByName(config.getRadiusIP());
           RadiusClient rc = new RadiusClient(host, config.getRadiusSecret(), config.getRadiusPort(), config.getRadiusAcctPort(), 1000);

           AttributeList attrs = new AttributeList();
           attrs.add(new Attr_UserName(username));
           attrs.add(new Attr_NASPortType(Attr_NASPortType.Wireless80211));
           attrs.add(new Attr_NASPort(new Long(1)));

           RadiusRequest request = new AccessRequest(rc, attrs);
           request.addAttribute(new Attr_UserPassword(password));

           System.out.println("Sending:\n" + request.toString());
           System.out.println("to:\n" + rc.toString());

           RadiusAuthenticator authenticator;

           if (config.getRadiusAuthentication().equals(Config.AuthenticationTypes.CHAP)){
               authenticator = new CHAPAuthenticator();
           } else if (config.getRadiusAuthentication().equals(Config.AuthenticationTypes.EAPMD5)){
               authenticator = new EAPMD5Authenticator();
           } else if (config.getRadiusAuthentication().equals(Config.AuthenticationTypes.EAPMSCHAPv2)){
               authenticator = new EAPMSCHAPv2Authenticator();
           } else if (config.getRadiusAuthentication().equals(Config.AuthenticationTypes.MSCHAPv1)){
               authenticator = new MSCHAPv1Authenticator();
           } else if (config.getRadiusAuthentication().equals(Config.AuthenticationTypes.MSCHAPv2)){
               authenticator = new MSCHAPv2Authenticator();
           } else if (config.getRadiusAuthentication().equals(Config.AuthenticationTypes.PAP)){
               authenticator = new PAPAuthenticator();
           }
           // jradius-extended methods
           else if (config.getRadiusAuthentication().equals(Config.AuthenticationTypes.EAPTLS)){
               authenticator = new MSCHAPv1Authenticator();
           } else if (config.getRadiusAuthentication().equals(Config.AuthenticationTypes.EAPTTLS)){
               authenticator = new MSCHAPv2Authenticator();
           } else if (config.getRadiusAuthentication().equals(Config.AuthenticationTypes.PEAP)){
               authenticator = new PAPAuthenticator();
           } else {
               // this should never ever happen, as it should be caught by the config file reader
               System.err.println("Configuration file did not specify an authentication type to use," +
                       " and has been detected when doing RADIUS. Config.java probably has an error.");
               System.exit(1);
               // This return is needed so the compiler doesn't whinge about 'authenticator' not being initialized,
               // even though the return statement and also the rc.authenticate call will never be hit.
               return -1;
           }

           RadiusResponse reply = rc.authenticate((AccessRequest) request, authenticator, 5);

           System.out.println("Recieved:\n" + reply.toString());

           boolean isAuthenticated = (reply instanceof AccessAccept);

           String replyMessage = (String)reply.getAttributeValue(Attr_ReplyMessage.TYPE);

           if (replyMessage != null){
               System.out.println("Reply Message: " + replyMessage);
           }

           if (!isAuthenticated) return 0;

           return 1;
       } catch (UnknownHostException e) {
           e.printStackTrace();
       } catch (IOException e) {
           e.printStackTrace();
       } catch (NoSuchAlgorithmException e) {
           e.printStackTrace();
       } catch (UnknownAttributeException e) {
           e.printStackTrace();
       } catch (RadiusException e) {
           e.printStackTrace();
       }
        return -1;
    }

}