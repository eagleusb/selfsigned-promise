const forge = require('node-forge');
const utility = require('./utility');

const DEFAULT_ATTRS = [{
  name: 'commonName',
  value: 'example.org',
}, {
  name: 'countryName',
  value: 'US',
}, {
  shortName: 'ST',
  value: 'Virginia',
}, {
  name: 'localityName',
  value: 'Blacksburg',
}, {
  name: 'organizationName',
  value: 'Test',
}, {
  shortName: 'OU',
  value: 'Test',
}];
const DEFAULT_EXT = [{
  name: 'basicConstraints',
  cA: true,
}, {
  name: 'keyUsage',
  keyCertSign: true,
  digitalSignature: true,
  nonRepudiation: true,
  keyEncipherment: true,
  dataEncipherment: true,
}, {
  name: 'subjectAltName',
  altNames: [{
    type: 6, // URI
    value: 'http://example.org/webid#me',
  }],
}];

function generate(certAttributes = DEFAULT_ATTRS, options = {}) {
  const {
    keySize, days, extensions, algorithm, pkcs7, clientCertificate,
  } = options;

  function generatePem(keyPair) {
    const cert = forge.pki.createCertificate();
    const { publicKey, privateKey } = keyPair;

    cert.serialNumber = utility.toPositiveHex(forge.util.bytesToHex(forge.random.getBytesSync(9)));
    cert.validity.notBefore = new Date();
    cert.validity.notAfter = new Date();
    cert.validity.notAfter.setDate(cert.validity.notBefore.getDate() + (days || 365));
    cert.setSubject(certAttributes);
    cert.setIssuer(certAttributes);
    cert.publicKey = publicKey;
    cert.setExtensions(extensions || DEFAULT_EXT);
    cert.sign(privateKey, utility.getAlgorithm(algorithm));

    const fingerprint = forge.md.sha1
      .create()
      .update(forge.asn1.toDer(forge.pki.certificateToAsn1(cert)).getBytes())
      .digest()
      .toHex()
      .match(/.{2}/g)
      .join(':');

    const pem = {
      private: forge.pki.privateKeyToPem(privateKey),
      public: forge.pki.publicKeyToPem(publicKey),
      cert: forge.pki.certificateToPem(cert),
      fingerprint,
    };

    if (pkcs7) {
      const p7 = forge.pkcs7.createSignedData();
      p7.addCertificate(cert);
      pem.pkcs7 = forge.pkcs7.messageToPem(p7);
    }

    if (clientCertificate) {
      const clientkeys = forge.pki.rsa.generateKeyPair(1024);
      const clientcert = forge.pki.createCertificate();
      clientcert.serialNumber = utility.toPositiveHex(forge.util.bytesToHex(forge.random.getBytesSync(9)));
      clientcert.validity.notBefore = new Date();
      clientcert.validity.notAfter = new Date();
      clientcert.validity.notAfter.setFullYear(clientcert.validity.notBefore.getFullYear() + 1);

      const clientAttrs = JSON.parse(JSON.stringify(certAttributes));
      for (let i = 0; i < clientAttrs.length; i++) {
        if (clientAttrs[i].name === 'commonName') {
          if (options.clientCertificateCN) { clientAttrs[i] = { name: 'commonName', value: options.clientCertificateCN }; } else { clientAttrs[i] = { name: 'commonName', value: 'John Doe jdoe123' }; }
        }
      }

      clientcert.setSubject(clientAttrs);
      clientcert.setIssuer(certAttributes);
      clientcert.publicKey = clientkeys.publicKey;
      clientcert.sign(privateKey);

      pem.clientprivate = forge.pki.privateKeyToPem(clientkeys.privateKey);
      pem.clientpublic = forge.pki.publicKeyToPem(clientkeys.publicKey);
      pem.clientcert = forge.pki.certificateToPem(clientcert);

      if (pkcs7) {
        const clientp7 = forge.pkcs7.createSignedData();
        clientp7.addCertificate(clientcert);
        pem.clientpkcs7 = forge.pkcs7.messageToPem(clientp7);
      }
    }

    const caStore = forge.pki.createCaStore();
    caStore.addCertificate(cert);

    try {
      forge.pki.verifyCertificateChain(
        caStore, [cert],
        (vfd, depth, chain) => {
          if (vfd !== true) {
            throw new Error('Certificate could not be verified.');
          }
          return true;
        },
      );
    } catch (ex) {
      throw new Error(ex);
    }

    return pem;
  }


  const keyPair = options.keyPair ? {
    privateKey: forge.pki.privateKeyFromPem(options.keyPair.privateKey),
    publicKey: forge.pki.publicKeyFromPem(options.keyPair.publicKey),
  } : forge.pki.rsa.generateKeyPair(keySize);

  return generatePem(keyPair);
}

module.exports = { generate };
