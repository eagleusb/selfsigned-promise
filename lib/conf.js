const DEFAULT_ATTRS = [{
  shortName: 'CN',
  value: '*.helloworld.paris',
}, {
  shortName: 'C',
  value: 'FR',
}, {
  shortName: 'ST',
  value: 'Ile-de-France',
}, {
  shortName: 'L',
  value: 'Paris Valley',
}, {
  shortName: 'O',
  value: 'France Inc',
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
  name: 'extKeyUsage',
  serverAuth: true,
  clientAuth: true,
  codeSigning: true,
  emailProtection: true,
  timeStamping: true,
}, {
  name: 'nsCertType',
  client: true,
  server: true,
  email: true,
  objsign: true,
  sslCA: true,
  emailCA: true,
  objCA: true,
}, {
  name: 'subjectAltName',
  altNames: [{
    type: 6, // URI
    value: 'https://helloworld.paris',
  }, {
    type: 7, // IP
    ip: '127.0.0.1',
  }],
}, {
  name: 'subjectKeyIdentifier',
}];

module.exports = {
  DEFAULT_ATTRS,
  DEFAULT_EXTS,
};
