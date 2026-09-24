"""Internal PKI of the lab: one SocForge CA and the TLS certificates of the services
that other tools call over HTTPS, so that clients verify both the chain and the name
instead of turning verification off.

Usage:  python pki/make_certs.py
Writes the public CA certificate to pki/socforge-lab-ca.crt (versioned) and every
private key and issued certificate to secrets/pki/ (gitignored). An existing CA is
reused, so re-running only (re)issues the server certificates.
"""
import datetime as dt, ipaddress, pathlib
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import ec
from cryptography.x509.oid import ExtendedKeyUsageOID, NameOID

ROOT = pathlib.Path(__file__).resolve().parent.parent
PUB = ROOT / "pki"
SEC = ROOT / "secrets" / "pki"

# name -> (DNS names, IP addresses)
SERVERS = {
    "misp": (["misp.socforge.lab"], ["10.10.10.22"]),
    "opnsense": (["opnsense.socforge.lab"], ["10.10.10.1"]),
}

NOW = dt.datetime.now(dt.timezone.utc)


def name(cn):
    return x509.Name([x509.NameAttribute(NameOID.ORGANIZATION_NAME, "SocForge Lab"),
                      x509.NameAttribute(NameOID.COMMON_NAME, cn)])


def pem_key(key):
    return key.private_bytes(serialization.Encoding.PEM, serialization.PrivateFormat.PKCS8,
                             serialization.NoEncryption())


def pem_cert(cert):
    return cert.public_bytes(serialization.Encoding.PEM)


def load_or_create_ca():
    key_file, crt_file = SEC / "socforge-lab-ca.key", PUB / "socforge-lab-ca.crt"
    if key_file.exists() and crt_file.exists():
        return (serialization.load_pem_private_key(key_file.read_bytes(), None),
                x509.load_pem_x509_certificate(crt_file.read_bytes()))
    key = ec.generate_private_key(ec.SECP384R1())
    subject = name("SocForge Lab CA")
    ski = x509.SubjectKeyIdentifier.from_public_key(key.public_key())
    cert = (x509.CertificateBuilder()
            .subject_name(subject).issuer_name(subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(NOW - dt.timedelta(minutes=5))
            .not_valid_after(NOW + dt.timedelta(days=3650))
            .add_extension(x509.BasicConstraints(ca=True, path_length=0), critical=True)
            .add_extension(x509.KeyUsage(digital_signature=True, key_cert_sign=True, crl_sign=True,
                                         content_commitment=False, key_encipherment=False,
                                         data_encipherment=False, key_agreement=False,
                                         encipher_only=False, decipher_only=False), critical=True)
            .add_extension(ski, critical=False)
            .sign(key, hashes.SHA384()))
    key_file.write_bytes(pem_key(key))
    crt_file.write_bytes(pem_cert(cert))
    return key, cert


def issue(ca_key, ca_cert, cn, dns, ips):
    key = ec.generate_private_key(ec.SECP256R1())
    san = [x509.DNSName(d) for d in dns] + [x509.IPAddress(ipaddress.ip_address(i)) for i in ips]
    cert = (x509.CertificateBuilder()
            .subject_name(name(dns[0])).issuer_name(ca_cert.subject)
            .public_key(key.public_key())
            .serial_number(x509.random_serial_number())
            .not_valid_before(NOW - dt.timedelta(minutes=5))
            .not_valid_after(NOW + dt.timedelta(days=825))
            .add_extension(x509.BasicConstraints(ca=False, path_length=None), critical=True)
            .add_extension(x509.KeyUsage(digital_signature=True, key_encipherment=False,
                                         content_commitment=False, data_encipherment=False,
                                         key_agreement=True, key_cert_sign=False, crl_sign=False,
                                         encipher_only=False, decipher_only=False), critical=True)
            .add_extension(x509.ExtendedKeyUsage([ExtendedKeyUsageOID.SERVER_AUTH]), critical=False)
            .add_extension(x509.SubjectAlternativeName(san), critical=False)
            .add_extension(x509.AuthorityKeyIdentifier.from_issuer_public_key(ca_key.public_key()),
                           critical=False)
            .sign(ca_key, hashes.SHA384()))
    (SEC / f"{cn}.key").write_bytes(pem_key(key))
    # full chain: server certificate first, then the CA
    (SEC / f"{cn}.crt").write_bytes(pem_cert(cert) + pem_cert(ca_cert))
    print(f"{cn}: {', '.join(dns + ips)}  (valid until {cert.not_valid_after_utc:%Y-%m-%d})")


if __name__ == "__main__":
    SEC.mkdir(parents=True, exist_ok=True)
    ca_key, ca_cert = load_or_create_ca()
    print("CA:", ca_cert.subject.rfc4514_string())
    for cn, (dns, ips) in SERVERS.items():
        issue(ca_key, ca_cert, cn, dns, ips)
