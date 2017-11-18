const DEFAULT_ATTRS = [{
  shortName: 'CN',
  value: 'example.org',
}, {
  shortName: 'C',
  value: 'US',
}, {
  shortName: 'ST',
  value: 'Virginia',
}, {
  shortName: 'L',
  value: 'Blacksburg',
}, {
  shortName: 'O',
  value: 'Test',
}, {
  shortName: 'OU',
  value: 'Test',
}, {
  shortName: 'E',
  value: 'foo@bar.lan',
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
    value: 'http://example.org/webid#me',
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
