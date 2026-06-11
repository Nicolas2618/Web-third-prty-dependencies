import socket
import struct
import dns.resolver

# Sends DNS query to DNS server using raw sockets

def create_dns_query(domain):
    """Create a DNS query packet for a domain."""
    transaction_id = 0x1234
    flags = 0x0100
    questions = 1
    answers = 0
    authorities = 0
    additionals = 0

    header = struct.pack('>HHHHHH', transaction_id, flags, questions, answers, authorities, additionals)

    parts = domain.split('.')
    question = b''
    for part in parts:
        question += struct.pack('B', len(part)) + part.encode()
    question += b'\x00'
    question += struct.pack('>HH', 1, 1)

    return header + question

def parse_dns_response(response):
    """Parse DNS response and extract IP address."""
    offset = 12

    while response[offset] != 0:
        offset += response[offset] + 1
    offset += 5

    while offset < len(response):
        if response[offset] >= 192:
            offset += 2
        else:
            while response[offset] != 0:
                offset += response[offset] + 1
            offset += 1

        if offset + 10 > len(response):
            break

        query_type, query_class, ttl, data_len = struct.unpack('>HHIH', response[offset:offset+10])
        offset += 10

        if query_type == 1:
            ip_bytes = response[offset:offset+4]
            return '.'.join(map(str, ip_bytes))

        offset += data_len

    return None

def dns_query(domain, dns_server='8.8.8.8'):
    """Perform DNS query using raw socket."""
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(5)

    try:
        query = create_dns_query(domain)
        sock.sendto(query, (dns_server, 53))
        response, _ = sock.recvfrom(512)
        return parse_dns_response(response)
    except socket.timeout:
        return None
    finally:
        sock.close()

def get_ns(domain: str) -> list[str]:
    """Get the nameservers for a domain."""
    try:
        answers = dns.resolver.resolve(domain, 'NS')
        return [str(rdata) for rdata in answers]
    except dns.resolver.NoAnswer:
        return []
    except dns.resolver.NXDOMAIN:
        return []

# Main execution
if __name__ == '__main__':
    domain = "example.com"

    ip_address = dns_query(domain)
    if ip_address:
        print(f"IP address for {domain}: {ip_address}")
    else:
        print(f"Could not resolve {domain}")

    nameservers = get_ns("netflix.com")
    for ns in nameservers:
        print(f"NS record: {ns}")

