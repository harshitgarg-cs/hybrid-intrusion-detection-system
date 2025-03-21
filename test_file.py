from scapy.all import IP, TCP
from ids import IntrusionDetectionSystem


def test_ids():
    # Create test packets to simulate various scenarios
    test_packets = [
        # Normal traffic
        IP(src="192.168.1.1", dst="192.168.1.2") / TCP(sport=1234, dport=80, flags="A"),
        IP(src="192.168.1.3", dst="192.168.1.4") / TCP(sport=1235, dport=443, flags="P"),

        # SYN flood simulation
        IP(src="10.0.0.1", dst="192.168.1.2") / TCP(sport=5678, dport=80, flags="S"),
        IP(src="10.0.0.2", dst="192.168.1.2") / TCP(sport=5679, dport=80, flags="S"),
        IP(src="10.0.0.3", dst="192.168.1.2") / TCP(sport=5680, dport=80, flags="S"),

        # Port scan simulation
        IP(src="192.168.1.100", dst="192.168.1.2") / TCP(sport=4321, dport=22, flags="S"),
        IP(src="192.168.1.100", dst="192.168.1.2") / TCP(sport=4321, dport=23, flags="S"),
        IP(src="192.168.1.100", dst="192.168.1.2") / TCP(sport=4321, dport=25, flags="S"),
    ]

    ids = IntrusionDetectionSystem()

    # Simulate packet processing and threat detection
    print("Starting IDS Test...")
    for i, packet in enumerate(test_packets, 1):
        print(f"\nProcessing packet {i}: {packet.summary()}")

        # Analyze the packet
        features = ids.traffic_analyzer.analyze_packet(packet)

        if features:
            # Log the flow statistics
            flow_key = (packet[IP].src, packet[IP].dst, packet[TCP].sport, packet[TCP].dport)
            stats = ids.traffic_analyzer.flow_stats.get(flow_key, None)

            if stats:
                print(f"Flow {flow_key} - Start Time: {stats['start_time']} | Last Time: {stats['last_time']}")
            
            # Detect threats based on features
            threats = ids.detection_engine.detect_threats(features)

            for threat in threats:
                        packet_info = {
                            'source_ip' : packet[IP].src,
                            'destination_ip' : packet[IP].dst,
                            'source_port' : packet[TCP].sport,
                            'destination_port' : packet[TCP].dport
                        }
                        ids.alert_system.generate_alert(threat, packet_info)

            else:
                print("No threats detected.")
        else:
            print("Packet does not contain IP/TCP layers or is ignored.")

    print("\nIDS Test Completed.")


if __name__ == "__main__":
    test_ids()
