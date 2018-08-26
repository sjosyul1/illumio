package com.firewall.filter;


import java.io.File;
import java.net.InetAddress;
import java.util.Scanner;

/*
 * author @sai srinath josyula
 * Coding quiz
 */

public class Firewall {
	
static String filepath = "";
    
	public Firewall(String filepath)
	{
		Firewall.filepath = filepath;
	}
	
	public static long ipToLong(InetAddress ip) {
        byte[] octets = ip.getAddress();
        long result = 0;
        for (byte octet : octets) {
            result <<= 8;
            result |= octet & 0xff;
        }
        return result;
    }
	
	public static boolean accept_packet(String direction, String protocol, int port, String ip_address)
	{	
		try{
			 File file = new File(filepath);
			 Scanner sc = new Scanner(file);
			 String rule_line = "";
			 String[] rule_array;
			 String[] port_range;
			 int lower_port;
			 int upper_port;			 
			 String[] ips;
			 			 
			 while (sc.hasNextLine())
			 {
				 rule_line = sc.nextLine();
				 rule_array = rule_line.split(",");

				 if (direction.equals(rule_array[0]) && protocol.equals(rule_array[1]))
				 {
					 System.out.println("direction and protocol matched");
					 //protocol and direction matches
					if (rule_array[2].contains("-"))
					{
						System.out.println("Ranged port : "+ rule_array[2]);
						//ranged port
						port_range =  rule_array[2].split("-");
						lower_port = Integer.parseInt(port_range[0]);
						upper_port = Integer.parseInt(port_range[1]);
						if (port >= lower_port && port <= upper_port)
						{
							System.out.println("ranged port matched");
							//ranged ip
							if(rule_array[3].contains("-"))
							{
							   System.out.println("Ranged ip addresses : "+ rule_array[3]);
							   ips = rule_array[3].split("-");
							   
							    long ipLo = ipToLong(InetAddress.getByName(ips[0]));
						        long ipHi = ipToLong(InetAddress.getByName(ips[1]));
						        long ipToTest = ipToLong(InetAddress.getByName(ip_address));
						        
						        if (ipToTest >= ipLo && ipToTest <= ipHi)
						        {
									System.out.println("Ranged ip matched");
									return true;
						        }
							}
							else
							{
								System.out.println("Single ip address : "+ rule_array[3]);
								long singleip = ipToLong(InetAddress.getByName(rule_array[3]));
								long ipToTest = ipToLong(InetAddress.getByName(ip_address));
								
								if(singleip == ipToTest)
								{
									   System.out.println("Single ip matched");
									   return true;
								}
							}
						}
					}
					//single port
					else  
					{
						System.out.println("Single port: " +rule_array[2]);
						if(Integer.parseInt(rule_array[2]) == port)
						{
							System.out.println("single port matched");
							System.out.println("Ranged ip : "+rule_array[3]);
							//ranged ip
							if(rule_array[3].contains("-"))
							{
							   ips = rule_array[3].split("-");
							    long ipLo = ipToLong(InetAddress.getByName(ips[0]));
						        long ipHi = ipToLong(InetAddress.getByName(ips[1]));
						        long ipToTest = ipToLong(InetAddress.getByName(ip_address));
						        
						        if (ipToTest >= ipLo && ipToTest <= ipHi)
						        {
									System.out.println("Ranged ip matched");
									return true;
						        }
							}
							else
							{
								System.out.println("Single ip : "+rule_array[3]);
								//single ip
								long singleip = ipToLong(InetAddress.getByName(rule_array[3]));
								long ipToTest = ipToLong(InetAddress.getByName(ip_address));
								
								if(singleip == ipToTest)
								{
									   System.out.println("Single ip matched");
									   return true;
								}
							}
						}
					}
				 }
			 }
			 sc.close();
		}
		catch(Exception e)
		{
			System.out.println("Exception occured " + e);
			return false;
		}
		return false;
	}
	
	public static void main(String args[])
	{
		/*
		 *  inbound,tcp,80,192.168.1.2
			outbound,tcp,10000-20000,192.168.10.11
			inbound,udp,53,192.168.1.1-192.168.2.5
			outbound,udp,1000-2000,52.12.48.92
		 */
		
		boolean firewall_output;
		Firewall f = new Firewall("/C:/Logtesting/input.csv");
		
		System.out.println("1st test");
		firewall_output = accept_packet("inbound", "tcp", 80, "192.168.1.2");
		System.out.println(firewall_output + "\n");
		
		System.out.println("2nd test");
		firewall_output = accept_packet("outbound", "tcp", 10100, "192.168.10.11");
		System.out.println(firewall_output+ "\n");
		
		System.out.println("3rd test");
		firewall_output = accept_packet("inbound", "udp", 53, "192.168.1.10");
		System.out.println(firewall_output+ "\n");
		
		System.out.println("4th test");
		firewall_output = accept_packet("outbound", "udp", 1010, "52.12.48.92");
		System.out.println(firewall_output+ "\n");		
	}

}
