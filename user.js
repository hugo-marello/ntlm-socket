const util = require('./utils');
const os = require('os');

module.exports = {
    createUserWithCredentials: (domain, username, password) => {
        let lmh = util.LMHash(password);
        let nth = util.NTHash(password);
        
        return {
            user: username,
            domain: domain,
            hostname: os.hostname(),
            LTKeys: [
                util.expandkey(lmh.slice(0, 7)),
                util.expandkey(lmh.slice(7, 14)),
                util.expandkey(lmh.slice(14))
            ],
            NTKeys: [
                util.expandkey(nth.slice(0, 7)),
                util.expandkey(nth.slice(7, 14)),
                util.expandkey(nth.slice(14))
            ]
        }
    },
    createUserWithHashs: (domain, username, LMHash, NTHash) => {
        return {
            user: username,
            domain: domain,
            hostname: os.hostname(),
            LTKeys: [
                util.expandkey(LMHash.slice(0, 7)),
                util.expandkey(LMHash.slice(7, 14)),
                util.expandkey(LMHash.slice(14))
            ],
            NTKeys: [
                util.expandkey(NTHash.slice(0, 7)),
                util.expandkey(NTHash.slice(7, 14)),
                util.expandkey(NTHash.slice(14))
            ]
        }
    },
    getHash: (password) => {
        return {
            LMHash: util.LMHash(password).toString('hex'),
            NTHash: util.NTHash(password).toString('hex')
        };
    }
};