const forge = require('node-forge');

function toPositiveHex(hexString) {
  let mostSiginficativeHexAsInt = parseInt(hexString[0], 16);
  if (mostSiginficativeHexAsInt < 8) {
    return hexString;
  }

  mostSiginficativeHexAsInt -= 8;
  return mostSiginficativeHexAsInt.toString() + hexString.substring(1);
}

function getAlgorithm(key) {
  switch (key) {
    case 'sha256':
      return forge.md.sha256.create();
    default:
      return forge.md.sha1.create();
  }
}

module.exports = {
  toPositiveHex,
  getAlgorithm,
};
