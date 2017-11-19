const forge = require('node-forge');
const utility = require('./utility');
const { DEFAULT_ATTRS, DEFAULT_EXTS } = require('./conf');

function generate(certAttributes = DEFAULT_ATTRS, options = {}) {
  const {
    keyPair,
    keySize = 2048,
    validForDays = 365,
    certExtensions = DEFAULT_EXTS,
    exportAsPkcs7 = false,
  } = options;
  let publicKey;
  let privateKey;

  function generateCertificate() {
    const cert = forge.pki.createCertificate();

    cert.serialNumber = utility.getSerialNumber();
    cert.validity.notBefore = new Date();
    cert.validity.notAfter = new Date();
    cert.validity.notAfter.setDate(cert.validity.notBefore.getDate() + validForDays);
    cert.publicKey = publicKey;

    cert.setSubject(certAttributes);
    cert.setIssuer(certAttributes);
    cert.setExtensions(certExtensions);
    cert.sign(privateKey, forge.md.sha256.create());

    return cert;
  }

  function generatePkcs7(cert) {
    const p7 = forge.pkcs7.createSignedData();
    p7.addCertificate(cert);
    return forge.pkcs7.messageToPem(p7);
  }

  function verifyCertificate(cert, certInPem) {
    const caStore = forge.pki.createCaStore();
    caStore.addCertificate(cert);

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

  function generatePemCertificate() {
    const cert = generateCertificate();
    const certInPem = {
      public: forge.pki.publicKeyToPem(publicKey),
      private: forge.pki.privateKeyToPem(privateKey),
      cert: forge.pki.certificateToPem(cert),
      fingerprint: forge.pki.getPublicKeyFingerprint(publicKey, {
        md: forge.md.sha256.create(),
        encoding: 'hex',
        delimiter: ':',
      }),
      expire: validForDays,
    };

    if (exportAsPkcs7) {
      certInPem.pkcs7 = generatePkcs7(cert);
    }

    return verifyCertificate(cert, certInPem);
  }

  return new Promise((resolve, reject) => {
    if (keyPair) {
      publicKey = forge.pki.publicKeyFromPem(keyPair.publicKey);
      privateKey = forge.pki.privateKeyFromPem(keyPair.privateKey);
      generatePemCertificate()
        .catch(certGenErr => reject(certGenErr))
        .then(certInPem => resolve(certInPem));
    }

    forge.pki.rsa.generateKeyPair({ bits: keySize, workers: -1 }, (err, genKeyPair) => {
      if (err) {
        reject(err);
        return;
      }
      ({ publicKey, privateKey } = genKeyPair);
      generatePemCertificate()
        .catch(certGenErr => reject(certGenErr))
        .then(certInPem => resolve(certInPem));
    });
  });
}

module.exports = { generate };
