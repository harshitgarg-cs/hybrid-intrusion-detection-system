from scapy.all import sniff, IP, TCP
from collections import defaultdict
import threading
import queue

class PacketCapture:
    def __init__(self):
        '''
        The init method initialized the class by creating a
        queue.Queue to store captured packets and a threading
        event to control when the packet capture should stop.
        '''
        self.packet_capture = queue.Queue()
        self.stop_capture = threading.Event()

    def packet_callback(self, packet):
        '''
        THe packet_callback method acts as a handler for each captured
        packet and checks if the packet contains both IP and TCP layers.
        If so, it adds it to the queue for further processing.
        '''
        if IP in packet and TCP in packet:
            self.packet_queue.put(packet)
        
    def start_capture(self, interface="eth0"):
        '''
        The start_capture method begins capturing packets on a specified
        interface (defaulting to etho0 to capture packets from the Ethernet interface).
        Run ifconfig to understand the available interfaces and select the appropriate interface from the list.
        '''
        def capture_thread():
            sniff(iface=interface,
                  prn=self.packet_callback,
                  store = 0,
                  stop_filter = lambda _: self.stop_capture.is_set())
        
        self.capture_thread = threading.Thread(target=capture_thread)
        self.capture_thread.start()
    
    def stop(self):
        self.stop_capture.set()
        self.capture_thread.join()

'''Tracking connection flows and calculate statistics for packets in real time.
'''
class TrafficAnalyzer:
    
    '''__init__ method initializes two attributes: connections, which stores lists of related packets for each flow,
    and flow_stats, which stores aggregated statistics for each flow, such as packet count, byte count, start time,
    and the time of the most recent packet.
    '''
    def __init__(self):
        '''Using the defaultdict data structure in Python to 
        manage connections and flow statistics by organizing data by unique flows.
        '''
        self.connections = defaultdict(list)
        self.flow_stats = defaultdict(lambda: {
            'packet_count':0,
            'byte_count' : 0,
            'start_time' : None,
            'last_time' : None
        })

    def analyze_packet(self, packet):
        '''
        This class processes each packet. If the packet contains IP and TCP layers,
        it extracts the source and destination IPs and ports, forming an unique,
        flow_key to identify the flow. It updates the statistics for the flow by incrementing
        the packet count, adding the packet's size to the byte count, and setting or updating the start
        and last time of the flow. Eventually, it calls extract_features to calculate and return additional metrics.
        '''
        if IP in packet and TCP in packet:
            ip_src = packet[IP].src
            ip_dst = packet[IP].src
            port_src = packet[TCP].sport
            port_dst = packet[TCP].dport

            flow_key = (ip_src, ip_dst, port_src, port_dst)

            #Update flow statistics
            stats = self.flow_stats[flow_key]
            stats['packet_count'] += 1
            stats['byte_count'] += len(packet)
            current_time = packet.time

            if not stats['start_time']:
                stats['start_time'] = current_time
            stats['last_time'] = current_time

            return self.extract_features(packet, stats)
        
    def extract_features(self, packet, stats):
        '''
        This class computes detailed characteristics of the flow and the current packet.
        These include the packet size, flow duration, packet rate, byte rate, TCP flags,
        and the TCP window size. These metrics are quite useful to identify patterns, anomalies, or potential threats in network traffic.
        '''
        return{
            'packet_size' : len(packet),
            'flow_duration' : stats['last_time'] - stats['start_time'],
            'packet_rate' : stats['packet_count'] / (stats['last_time']-stats['start_time']),
            'byte_rate' : stats['byte_count'] / (stats['last_time']-stats['start_time']),
            'tcp_flags' : packet[TCP].flags,
            'window_size' : packet[TCP].window
        }
    