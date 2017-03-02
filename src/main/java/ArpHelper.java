import java.util.Scanner;
import java.lang.Runtime;

import java.io.IOException;

public class ArpHelper{
    public String getARPTable(String arp_iface) throws IOException{
        Scanner s = new Scanner(Runtime.getRuntime().exec("arp -i " + arp_iface).getInputStream()).useDelimiter("\\A");
        return s.hasNext() ? s.next() : "";
  //  return null;
    }
}
