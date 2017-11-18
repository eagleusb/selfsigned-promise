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
const DEFAULT_EXTS = [{
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
    keySize = 2048,
    validForDays = 365,
    certExtensions = DEFAULT_EXTS,
    exportAsPkcs7 = false,
  } = options;
  let { keyPair } = options;

  function generatePemCertificate() {
    const cert = forge.pki.createCertificate();
    const caStore = forge.pki.createCaStore();
    const { publicKey, privateKey } = keyPair;

    cert.serialNumber = utility.getSerialNumber();
    cert.validity.notBefore = new Date();
    cert.validity.notAfter = new Date();
    cert.validity.notAfter.setDate(cert.validity.notBefore.getDate() - validForDays);
    cert.publicKey = publicKey;

    cert.setSubject(certAttributes);
    cert.setIssuer(certAttributes);
    cert.setExtensions(certExtensions);

    cert.sign(privateKey, forge.md.sha256.create());

    caStore.addCertificate(cert);

    const certInPem = {
      private: forge.pki.privateKeyToPem(privateKey),
      public: forge.pki.publicKeyToPem(publicKey),
      cert: forge.pki.certificateToPem(cert),
    };

    if (exportAsPkcs7) {
      const p7 = forge.pkcs7.createSignedData();
      p7.addCertificate(cert);
      certInPem.pkcs7 = forge.pkcs7.messageToPem(p7);
    }

    return new Promise((resolve, reject) => {
      forge.pki.verifyCertificateChain(caStore, [cert], (verificationStatus) => {
        if (verificationStatus === true) {
          resolve(certInPem);
          return;
        }
        reject(new Error(`Certificate could not be verified with ${verificationStatus}`));
      });
    });
  }

  return new Promise((resolve, reject) => {
    if (keyPair) {
      keyPair = {
        privateKey: forge.pki.privateKeyFromPem(keyPair.privateKey),
        publicKey: forge.pki.publicKeyFromPem(keyPair.publicKey),
      };
      generatePemCertificate()
        .catch(certGenErr => reject(certGenErr))
        .then(certInPem => resolve(certInPem));
    }

    forge.pki.rsa.generateKeyPair({ bits: keySize, workers: -1 }, (err, genKeyPair) => {
      keyPair = genKeyPair;
      if (err) {
        reject(err);
      }
      generatePemCertificate()
        .catch(certGenErr => reject(certGenErr))
        .then(certInPem => resolve(certInPem));
    });
  });
}

module.exports = { generate };
