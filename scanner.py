import socket
import ssl

# Get the URL from user input
url = input("Enter the URL: ")

# Get the IP address of the URL
ip_address = socket.gethostbyname(url)

# Create a socket and connect to the IP address using SSL
context = ssl.create_default_context()
with socket.create_connection((ip_address, 443)) as sock:
    with context.wrap_socket(sock, server_hostname=url) as sslsock:
        # Get the TLS certificate from the server
        cert = sslsock.getpeercert()

        # Extract the TLS version
        tls_version = sslsock.version()

        # Extract the cipher suite
        cipher_suite = sslsock.cipher()

        # Extract the certificate subject
        if 'subject' in cert:
            cert_subject = dict(x[0] for x in cert['subject'])
        else:
            cert_subject = {}

        # Extract the certificate issuer
        if 'issuer' in cert:
            cert_issuer = dict(x[0] for x in cert['issuer'])
        else:
            cert_issuer = {}

        # Extract the certificate expiration date
        if 'notAfter' in cert:
            cert_not_after = cert['notAfter']
        else:
            cert_not_after = "N/A"

        # Extract the certificate start date
        if 'notBefore' in cert:
            cert_not_before = cert['notBefore']
        else:
            cert_not_before = "N/A"

        # Extract the certificate serial number
        if 'serialNumber' in cert:
            cert_serial_number = cert['serialNumber']
        else:
            cert_serial_number = "N/A"

        # Extract the certificate public key
        if 'subjectPublicKeyInfo' in cert:
            cert_public_key = cert['subjectPublicKeyInfo']
        else:
            cert_public_key = "N/A"

        # Extract the ALPN protocol
        alpn_protocol = sslsock.selected_alpn_protocol()

# Print the TLS information
print("TLS version:", tls_version)
print("Cipher suite:", cipher_suite)
print("Certificate subject:", cert_subject)
print("Certificate issuer:", cert_issuer)
print("Certificate expiration date:", cert_not_after)
print("Certificate start date:", cert_not_before)
print("Certificate serial number:", cert_serial_number)
print("Certificate public key:", cert_public_key)
print("ALPN protocol:", alpn_protocol)
