import dpkt
import sys
import socket

# taken from source code for examples.print_http_requests
def inet_to_str(inet):
    """Convert inet object to a string

        Args:
            inet (inet struct): inet network address
        Returns:
            str: Printable/readable IP address
    """
    # First try ipv4 and then ipv6
    try:
        return socket.inet_ntop(socket.AF_INET, inet)
    except ValueError:
        return socket.inet_ntop(socket.AF_INET6, inet)


# input is a pcap file and outputs set of IP addresses (one per line) of victims of an ACK flood attack
def getIPAddresses(pcap, SYNACKDict, ACKDict, threshold):

    # For each packet in the pcap process the contents
    for num, (timestamp, buf) in enumerate(pcap):
        # Check if packet uses Ethernet
        try:
            eth = dpkt.ethernet.Ethernet(buf)
        except:
            continue

        # Make sure the Ethernet data contains an IP packet
        if not isinstance(eth.data, dpkt.ip.IP):
            #print('Non IP Packet type not supported %s\n' % eth.data.__class__.__name__)
            continue
        
        ip = eth.data

        # Check if packet uses TCP
        if isinstance(ip.data, dpkt.tcp.TCP):
            tcp = ip.data
            # Print the packet number
            # print("Packet #%d"%(num+1))

            # Check if received a SYN + ACK packet
            if((tcp.flags & dpkt.tcp.TH_SYN) and (tcp.flags & dpkt.tcp.TH_ACK)):
                #increment number of SYN + ACK packets sent in dictionary
                if (inet_to_str(ip.src)) in SYNACKDict:
                    SYNACKDict[inet_to_str(ip.src)] += 1
                # add IP address into dictionary
                else:
                    SYNACKDict[inet_to_str(ip.src)] = 1
            # Check if sent a SYN packet
            elif (tcp.flags & dpkt.tcp.TH_ACK):
                # increment number of SYN packets sent in dictionary
                if (inet_to_str(ip.dst)) in ACKDict:
                    ACKDict[inet_to_str(ip.dst)] += 1
                # add IP address into dictionary
                else:
                    ACKDict[inet_to_str(ip.dst)] = 1

    # Array holding victim IP addresses
    victims = []

    # Iterate through dictionary of IP addresses that received ACK Packets
    for packet in ACKDict:
        # Check if IP address also sent SYN + ACK packets
        if packet in SYNACKDict:
            # Check if received 3x more ACK packets than sent SYN + ACK packets
            # If true, append address to result
            if(ACKDict.get(packet) > threshold * SYNACKDict.get(packet)):
                victims.append(packet)
        # If only received ACK packets, append address to result
        else:
            victims.append(packet)
    
    # Return array of IP addresses, SYNACK dictionary, and ACK dictionary
    return {
        'addresses': victims,
        'SYNACKDict': SYNACKDict,
        'ACKDict': ACKDict,
    }


def main():
    # Open command line argument file
    with open(sys.argv[1], 'rb') as f:
        pcap = dpkt.pcap.Reader(f)
        # call main function to get list of IP address
        SYNACKDict = {}
        ACKDict = {}
        threshold = 3
        ans = getIPAddresses(pcap, SYNACKDict, ACKDict, threshold)
        # Iterate through result and output each IP addresses line-by-line
        if (len(ans["addresses"]) == 0):
            print("------------------------------------\nNo ACK Flood detected\n------------------------------------")
        else:
            print("------------------------------------\nACK Flood detected\n------------------------------------\nVictim IP Addresses:\n")
            ans["addresses"].sort()
            for x in ans["addresses"]:
                print(x+"\n")
            print("Number of victims: " + str(len(ans["addresses"])))
            print("------------------------------------")
        # Return array of IP addresses
        return ans["addresses"]

# call main function
if __name__ == '__main__':
    main()