const crypto = require('crypto');

module.exports.encodeDes = function(textToEncode, keyString) {
    var key = Buffer.from(keyString, 'utf8');
    var cipher = crypto.createCipheriv('DES-ECB', key, '');
    return cipher.update(textToEncode, 'utf8');
}

module.exports.hashMD4 = function (textToHash) {
    var hash = crypto.createHash('md4');
    hash.update(textToHash);
    return hash.digest();
}

module.exports.LMHash = function (rawPassword) {
    let password = Buffer.alloc(14, 'ascii');
    password.write(rawPassword.toUpperCase(), 0, rawPassword.length);
    const startString = 'KGS!@#$%';
    
    return Buffer.concat([
        this.encodeDes(startString, this.expandkey(password.slice(0, 7))),
        this.encodeDes(startString, this.expandkey(password.slice(7))),
        Buffer.alloc(5)
    ]);
}

module.exports.NTHash = function (rawPassword) {
    return Buffer.concat([this.hashMD4(Buffer.from(rawPassword, 'ucs2')), Buffer.alloc(5)]);
}

module.exports.resolveChallenge = function (challenge, keys) {
    return Buffer.concat([
        this.encodeDes(challenge, keys[0]),
        this.encodeDes(challenge, keys[1]),
        this.encodeDes(challenge, keys[2])
    ]);
}

module.exports.expandkey = function (key56)
{
    var key64 = Buffer.alloc(8);
    
    key64[0] = key56[0] & 0xFE;
    key64[1] = ((key56[0] << 7) & 0xFF) | (key56[1] >> 1);
    key64[2] = ((key56[1] << 6) & 0xFF) | (key56[2] >> 2);
    key64[3] = ((key56[2] << 5) & 0xFF) | (key56[3] >> 3);
    key64[4] = ((key56[3] << 4) & 0xFF) | (key56[4] >> 4);
    key64[5] = ((key56[4] << 3) & 0xFF) | (key56[5] >> 5);
    key64[6] = ((key56[5] << 2) & 0xFF) | (key56[6] >> 6);
    key64[7] =  (key56[6] << 1) & 0xFF;
    
    return key64;
}
