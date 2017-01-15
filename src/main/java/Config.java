import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;

import lombok.Getter;
import lombok.ToString;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import java.io.File;
import java.io.IOException;
import java.net.InetAddress;
import java.net.UnknownHostException;


/**
 * Created by bairdmich on 12/01/17.
 */
public @Getter @ToString(exclude ="logger")
class Config {


    static final Logger logger = LogManager.getFormatterLogger(Config.class);
static  {

}
    private static final int MIN_PORT_NUMBER = 0;
    private static final int MAX_PORT_NUMBER = 0xffff;

    public class AuthenticationTypes {
        public static final String MSCHAPv2 = "MSHCAPv2";
        public static final String MSCHAPv1 = "MSCHAPv1";
        public static final String CHAP = "CHAP";
        public static final String EAPMD5 = "EAPMD5";
        public static final String EAPMSCHAPv2 = "EAPMSCHAPv2";
        public static final String PAP = "PAP";
        // jradius-extended authentication methods
        public static final String EAPTLS = "EAPTLS";
        public static final String EAPTTLS = "EAPTTLS";
        public static final String PEAP = "PEAP";
    }

    private String controllerIP;
    private int controllerHTTPPort = 8080;

    private String radiusIP;
    private int radiusPort = 1812;
    private int radiusAcctPort = 1813;
    private String radiusSecret;
    private String radiusAuthentication;

    private int webserverHTTPPort;

    private static boolean isValidIPAddress(String ip){
        try {
            InetAddress.getByName(ip);
            return true;
        } catch (UnknownHostException e) {
            // bad boy.
        }
        return false;
    }

    public static Config BuildFromFile(String filename) throws IOException, IllegalArgumentException {

        ObjectMapper mapper = new ObjectMapper(new YAMLFactory());
        Config config = mapper.readValue(new File(filename), Config.class);

        if (config.controllerIP == null || !isValidIPAddress(config.controllerIP)) {
            // TODO verify if it is a valid IP address or hostname.
            logger.error("Field: %s must specify an IP address or hostname. was: %s", "controllerIP", config.controllerIP);
            throw new IllegalArgumentException("must specify valid controllerIP field");
        }
        if (config.controllerHTTPPort < MIN_PORT_NUMBER || config.controllerHTTPPort > MAX_PORT_NUMBER ){
            logger.error("Field: %s -> %d must be a valid TCP port number %d - %d", "controllerHTTPPort", config.controllerHTTPPort, MIN_PORT_NUMBER, MAX_PORT_NUMBER);
            throw new IllegalArgumentException("controllerHTTPPort field out of range: " + config.controllerHTTPPort);
        }

        if (config.radiusIP == null || !isValidIPAddress(config.radiusIP)){
            logger.error("Field: %s must specify an IP address or hostname. was: %s", "radiusIP", config.radiusIP);
            throw new IllegalArgumentException("must specify radiusIP field");
        }
        if (config.radiusAcctPort < MIN_PORT_NUMBER || config.radiusAcctPort > MAX_PORT_NUMBER ){
            logger.error("Field: %s must be a valid TCP port number %d - %d. was %d", "radiusAcctPort", MIN_PORT_NUMBER, MAX_PORT_NUMBER, config.radiusAcctPort);
            throw new IllegalArgumentException("radiusAcctPort field out of range: " + config.controllerHTTPPort);
        }
        if (config.radiusPort < MIN_PORT_NUMBER || config.radiusPort > MAX_PORT_NUMBER){
            logger.error("Field: %s must be a valid TCP port number %d - %d. was: %d", "radiusPort", MIN_PORT_NUMBER, MAX_PORT_NUMBER, config.radiusPort);
            throw new IllegalArgumentException("radiusPort field out of range: " + config.controllerHTTPPort);
        }
        if (config.radiusSecret == null){
            // can we check this is a potentially valid secret (only legit characters, ...)?
            logger.error("Field: %s must not be null", "radiusSecret");
            throw new IllegalArgumentException("must specify radiusSecret field");
        }
        if (!(AuthenticationTypes.CHAP.equals(config.radiusAuthentication)
                || AuthenticationTypes.EAPMD5.equals(config.radiusAuthentication)
                || AuthenticationTypes.EAPMSCHAPv2.equals(config.radiusAuthentication)
                || AuthenticationTypes.MSCHAPv1.equals(config.radiusAuthentication)
                || AuthenticationTypes.MSCHAPv2.equals(config.radiusAuthentication)
                || AuthenticationTypes.PAP.equals(config.radiusAuthentication)
                // jradius-extended
                || AuthenticationTypes.EAPTLS.equals(config.radiusAuthentication)
                || AuthenticationTypes.EAPTTLS.equals(config.radiusAuthentication)
                || AuthenticationTypes.PEAP.equals(config.radiusAuthentication)
        )){

            String message = String.format("'radiusAuthentication' must be one of '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s', '%s'\n"
                    + "And not: '%s'",
                    AuthenticationTypes.CHAP, AuthenticationTypes.EAPMD5, AuthenticationTypes.EAPMSCHAPv2,
                    AuthenticationTypes.MSCHAPv1, AuthenticationTypes.MSCHAPv2, AuthenticationTypes.PAP,
                    AuthenticationTypes.EAPTLS, AuthenticationTypes.EAPTTLS, AuthenticationTypes.PEAP,
                    config.radiusAuthentication);
            logger.error(message);
            throw new IllegalArgumentException(message);
        }
        if (config.webserverHTTPPort < MIN_PORT_NUMBER || config.webserverHTTPPort > MAX_PORT_NUMBER){
            logger.error("Field: %s must be a valid TCP port number %d - %d. was: %d", "webserverHTTPPort", MIN_PORT_NUMBER, MAX_PORT_NUMBER, config.webserverHTTPPort);
            throw new IllegalArgumentException("webserverHTTPPort field out of range: " + config.controllerHTTPPort);
        }
        System.out.println(config.toString());
        return config;
    }
}