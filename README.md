
Captive Portal webserver for the https://github.com/Bairdo/sdn-authenticator project.

This replaces https://github.com/Bairdo/CapFlow-webserver.

#Configuration
[config.yaml](https://github.com/Bairdo/sdn-authenticator-webserver/blob/v0.2.0/config.yaml) contains an example configuration file
The following fields are usable (where the field has a value, it is optional, otherwise it must be defined in the configuration file).

Field | Default Value | Range
--------- | ------------- | ----------
controllerIP | | valid IP address or hostname
controllerHTTPPort | 8080 | Valid TCP port
radiusIP | | valid IP address or hostname
radiusPort | 1812 | Valid TCP/UDP port
radiusAcctPort | 1813 | Valid TCP/UDP port
radiusSecret | |
radiusAuthentication | | one of: CHAP, EAPMD5, EAPMSCHAPv2, EAPTLS, EAPTTLS, MSHCAPv1, MSCHAPv2, PAP, PEAP
webserverHTTPPort | | Valid TCP port

webserverHTTPPort is the TCP port for the server to listen on.

Ensure your RADIUS server is configured for the correct authentication method.


RADIUS Authentications methods MSHCAPv2, MSCHAPv1, CHAP, EAPMD5, EAPMSCHAPv2, PAP, EAPTLS, EAPTTLS, PEAP can be used thanks to jradius.

#Run:

jre8 is required

Download [jar](https://github.com/Bairdo/sdn-authenticator-webserver/releases/download/v0.2.0/uber-captive-portal-webserver-1.0-SNAPSHOT.jar)

Create the configuration file.



##usage:
'''
java -cp <JAR_FILE.jar> Main <CONFIGURATION.yaml>
'''
##therefore:
'''
java -cp uber-captive-portal-webserver-1.0-SNAPSHOT.jar Main config.yaml'''




#Build:
This project uses Maven and jdk8.

Using the Maven Shade plugin all dependencies are packages into a single jar.

The following should be enough to build the project
Clone the repo
'''
mvn package
'''
which should download all required jar files and create the jar

sometimes a:
'''
mvn clean package
'''
is required to update all files in the created jar.

Thanks to the following libraries:
- [jradius](https://github.com/coova/jradius/) (RADIUS)
- [jackson](http://wiki.fasterxml.com/JacksonHome) (json & yaml)
- [spark web framework](http://sparkjava.com/)
- [velocity](http://velocity.apache.org/) (template engine for webpage)
- [unirest](http://unirest.io/java.html) (http client)
- [bouncy castle](https://www.bouncycastle.org/) (crypto library)
- [lombok](https://projectlombok.org/) (generates getters with annotations)
- [Apache log4j](https://logging.apache.org/log4j/2.x/)