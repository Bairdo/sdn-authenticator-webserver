import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import com.sun.corba.se.spi.activation.TCPPortHelper;
import sun.rmi.transport.tcp.TCPChannel;

import java.io.File;
import java.io.IOException;
import java.net.Socket;

/**
 * Created by bairdmich on 12/01/17.
 */
public class Config {

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

    public String getRadiusAuthentication() {
        return radiusAuthentication;
    }

    public void setRadiusAuthentication(String radiusAuthentication) {
        this.radiusAuthentication = radiusAuthentication;
    }

    private String radiusAuthentication;

    public void setControllerIP(String controllerIP) {
        this.controllerIP = controllerIP;
    }

    public void setControllerHTTPPort(int controllerHTTPPort) {
        this.controllerHTTPPort = controllerHTTPPort;
    }

    public void setRadiusIP(String radiusIP) {
        this.radiusIP = radiusIP;
    }

    public void setRadiusPort(int radiusPort) {
        this.radiusPort = radiusPort;
    }

    public void setRadiusAcctPort(int radiusAcctPort) {
        this.radiusAcctPort = radiusAcctPort;
    }

    public void setRadiusSecret(String radiusSecret) {
        this.radiusSecret = radiusSecret;
    }

    public String getControllerIP() {
        return controllerIP;
    }

    public int getControllerHTTPPort() {
        return controllerHTTPPort;
    }

    public String getRadiusIP() {
        return radiusIP;
    }

    public int getRadiusPort() {
        return radiusPort;
    }

    public int getRadiusAcctPort() {
        return radiusAcctPort;
    }

    public String getRadiusSecret() {
        return radiusSecret;
    }

    public Config(){

    }

    public static Config BuildFromFile(String filename) throws IOException, IllegalArgumentException {

        ObjectMapper mapper = new ObjectMapper(new YAMLFactory());
        Config config = mapper.readValue(new File(filename), Config.class);

        try {
            if (config.controllerIP == null) {
                // TODO verify if it is a valid IP address or hostname.
                throw new IllegalArgumentException("must specify " + Config.class.getField("controllerIP").getName() + "field");
            }
            if (config.controllerHTTPPort < MIN_PORT_NUMBER || config.controllerHTTPPort > MAX_PORT_NUMBER ){
                throw new IllegalArgumentException(Config.class.getField("controllerHTTPPort").getName() + "field out of range: " + config.controllerHTTPPort);
            }
            if (config.radiusIP == null){
                throw new IllegalArgumentException("must specify " + Config.class.getField("radiusIP").getName() + "field");
            }
            if (config.radiusAcctPort < MIN_PORT_NUMBER || config.radiusAcctPort > MAX_PORT_NUMBER ){
                throw new IllegalArgumentException(Config.class.getField("radiusAcctPort").getName() + "field out of range: " + config.controllerHTTPPort);
            }
            if (config.radiusPort < MIN_PORT_NUMBER || config.radiusPort > MAX_PORT_NUMBER){
                throw new IllegalArgumentException(Config.class.getField("radiusPort").getName() + "field out of range: " + config.controllerHTTPPort);
            }
            if (config.radiusSecret == null){
                throw new IllegalArgumentException("must specify " + Config.class.getField("radiusSecret").getName() + "field");
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
                throw new IllegalArgumentException(message);
            }
        } catch (NoSuchFieldException nsfe){
            System.err.println(nsfe);
        }

        return config;
    }

}