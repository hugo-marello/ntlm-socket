const Socket = require('net').Socket;
const { Duplex } = require('stream');
const util = require('./utils');

module.exports = class NtlmSocket extends Duplex {
    _negotiationStarted = false;
    _socket = new Socket();
    _optionalHeaders = '';
    _firstPayload = '';
    customEvents = ['ntlm-error', 'ntlm-data', 'ntlm-authorized', 'ntlm-authenticate', 'ntlm-challenge', 'ntlm-negotiate'];
    socketEvents = ['close', 'connect', 'data', 'drain', 'end', 'error', 'lookup', 'ready', 'timeout'];

    constructor(user, options) {
        super();
        this._user = user;
        this._options = options;

        //prepare future optional headers
        for(let header of this._options.headers){
            this._optionalHeaders += header + '\r\n';
        }

        //re-throw all socket events
        for(let event of this.socketEvents){
            this._socket.on(event, (...args) => this.emit(event, ...args));
        }

        this._socket.once('data', (data) => this._parseChallenge(data));
        this.on('ntlm-data', (data) => {
            console.log(typeof data);
            this.push(data);
        });
    }
    
    connect(port, host, cb) {
        this._socket.connect(port, host, cb);
    }

    _parseChallenge(data) {
        let headers = data.toString().split('\r\n');
        if(headers.length < 2) {
            return this.emit('ntlm-error', 'Received an invalid response from proxy.\n'+data);
        }
        let httpMethod = headers.shift();
        let statusCode = httpMethod.match(/HTTP\/\d\.\d (.*) /);
        if(!statusCode || (statusCode[1] != '407' && statusCode[1] != '401')) {
            return this.emit('ntlm-error', 'Proxy challenge answer mismatch 407(Authentication Required).\n'+data);
        }

        headers.filter(header => header.startsWith('Proxy-Authenticate: NTLM ')).forEach(value => this.challenge = value.slice(25));

        if(!this.challenge) {
            return this.emit('ntlm-error', 'No ntlm challenge received.\n'+data.toString());
        }
        let buf = Buffer.from(this.challenge, 'base64');
        let pos = 8;
        let signature = buf.slice(0, pos);
        
        if(signature.toString() !== 'NTLMSSP\0') {
            return this.emit('ntlm-error', `Proxy didn't send a signature in the challenge.\n`+this.challenge);
        }

        let messageType = buf.readUInt32LE(pos);
        pos += 4;

        if(messageType !== 0x02) {
            return this.emit('ntlm-error', `Proxy didn't send a valid message type in the challenge.\n`+this.challenge);
        }

        pos += 8; //ignoring the TargetName as suggested on the documentation
        
        this._receivedFlags = buf.readUInt32LE(pos);
        pos += 4;
        
        this._challengeNonce = buf.slice(pos, pos+8);
        pos += 16; // also ignoring other 8 reserved bytes
        
        this.emit('ntlm-challenge', this.challenge);

        this._socket.once('data', (arg) => this._parseAuthorized(arg));
        this._writeAuthenticate();
    }

    _parseAuthorized(data) {
        if(data.toString().match(/^HTTP\/\d\.\d 2\d\d .*/)) {
            this._socket.on('data', (chunk) => this.emit('ntlm-data', chunk));
            this.emit('ntlm-authorized');
        } else {
            return this.emit('ntlm-error', 'Proxy response was different than authorized.\n'+data.toString());
        }
    }

    write(chunk, encoding, cb) {
        let _cb = cb;

        if(typeof encoding == 'function' && !cb){
            _cb = encoding;
        }

        if(this._negotiationStarted){
            this._socket.write(chunk, (...args)=> _cb(args));
        } else {
            this._writeNegotiate(chunk.toString(), encoding, _cb);
        }
    }

    _ntlmNegotiateMsg(){
        let domain = this._user.domain.toUpperCase();
        let user = this._user.hostname.toUpperCase();
        let userlen = Buffer.byteLength(user, 'ascii');
        let domainlen = Buffer.byteLength(domain, 'ascii');
        let buf = Buffer.alloc(32 + userlen + domainlen);
        let pos = 0;

        buf.write('NTLMSSP\0', pos, 7, 'ascii'); //Signature
        pos += 8;

        buf.writeUInt32LE(1, pos); //Message type 
        pos += 4;

        buf.writeUInt32LE(0xb207,pos);// flags
        pos += 4;

        buf.writeUInt16LE(domainlen, pos); //Domain
        pos += 2;
        buf.writeUInt16LE(domainlen, pos);
        pos += 2;

        buf.writeUInt32LE(0x20, pos); //Domain offset, from start of package
        pos += 4;

        buf.writeUInt16LE(userlen, pos); //Username
        pos += 2;
        buf.writeUInt16LE(userlen, pos);
        pos += 2;

        buf.writeUInt32LE(0x20+domainlen, pos); //Username offset, also from start of package
        pos += 4;

        //Payload
        buf.write(domain, pos, domainlen, 'ascii');
        pos += domainlen;
        buf.write(user, pos, userlen, 'ascii');
        pos += userlen;

        return buf.toString('base64');
    }

    _writeNegotiate(chunk, cb) {
        let httpEnd = chunk.indexOf('\r\n\r\n');
        if(httpEnd === -1){
            return this.emit('ntlm-error', 'Invalid first HTTP request.\n'+chunk);
        }
        
        this._firstMessage = chunk.slice(0, httpEnd+2); //also removing last terminator of http request
        this._firstCb = cb;
        if(chunk.length > httpEnd + 4) { // has payload
            this._firstPayload = chunk.slice(httpEnd+4);
        }

        let NTLM = this._ntlmNegotiateMsg();
        let request = this._firstMessage + this._optionalHeaders + 'Proxy-Authorization: NTLM '+NTLM+'\r\n\r\n'+this._firstPayload;
        
        this._negotiationStarted = true;
        this._socket.write(request, () => {
            this.emit('ntlm-negotiate', NTLM);
        });
    }

    _writeAuthenticate() {
        let NTLM = this._ntlmAuthenticateMsg();
        let request = this._firstMessage + this._optionalHeaders + 'Proxy-Authorization: NTLM '+NTLM+'\r\n\r\n'+this._firstPayload;
        this._socket.write(request, () => {            
            if(this._firstCb) {
                this._firstCb();
            }
            this.emit('ntlm-authenticate', NTLM);
        });
    }

    _ntlmAuthenticateMsg() {
        let lmr = util.resolveChallenge(this._challengeNonce, this._user.LTKeys);
        let ntr = util.resolveChallenge(this._challengeNonce, this._user.NTKeys);
        
        let hostnameLength = this._user.hostname.length*2;
        let domainLength = this._user.domain.length*2;
        let userLength = this._user.user.length*2;

        let totalLength = 64 + 
            domainLength +
            userLength +
            hostnameLength +
            lmr.length +
            ntr.length;


        let response = Buffer.allocUnsafe(totalLength);
        let pos = 0;
        let payloadOffset = 64;
        response.write('NTLMSSP\0', pos, 8, 'ascii'); //signature
        pos += 8;

        response.writeUInt32LE(0x03, pos); //message type
        pos += 4;

        // LM challenge
        response.writeUInt16LE(lmr.length, pos);
        pos += 2;
        response.writeUInt16LE(lmr.length, pos);
        pos += 2;
        response.writeUInt32LE(payloadOffset, pos);
        pos += 4;
        payloadOffset += lmr.length;

        // NTLM challenge
        response.writeUInt16LE(ntr.length, pos);
        pos += 2;
        response.writeUInt16LE(ntr.length, pos);
        pos += 2;
        response.writeUInt32LE(payloadOffset, pos);
        pos += 4;
        payloadOffset += ntr.length;

        // domain
        response.writeUInt16LE(domainLength, pos);
        pos += 2;
        response.writeUInt16LE(domainLength, pos);
        pos += 2;
        response.writeUInt32LE(payloadOffset, pos);
        pos += 4;
        payloadOffset += domainLength;

        // username
        response.writeUInt16LE(userLength, pos);
        pos += 2;
        response.writeUInt16LE(userLength, pos);
        pos += 2;
        response.writeUInt32LE(payloadOffset, pos);
        pos += 4;
        payloadOffset += userLength;

        // workstation
        response.writeUInt16LE(hostnameLength, pos);
        pos += 2;
        response.writeUInt16LE(hostnameLength, pos);
        pos += 2;
        response.writeUInt32LE(payloadOffset, pos);
        pos += 4;
        payloadOffset += hostnameLength;

        // encrypted session
        response.writeUInt16LE(0, pos);
        pos += 2;
        response.writeUInt16LE(0, pos);
        pos += 2;
        response.writeUInt32LE(payloadOffset, pos);
        pos += 4;
        payloadOffset += 0;

        // flags
        response.writeUInt32LE(this._receivedFlags, pos);
        pos += 4;

        // Payload
        lmr.copy(response, pos, 0, lmr.length);
        pos += lmr.length;
        ntr.copy(response, pos, 0, ntr.length);
        pos += ntr.length;
        response.write(this._user.domain.toUpperCase(), pos, domainLength, 'ucs2');
        pos += domainLength;
        response.write(this._user.user.toUpperCase(), pos, userLength, 'ucs2');
        pos += userLength;
        response.write(this._user.hostname.toUpperCase(), pos, hostnameLength, 'ucs2');
        pos += hostnameLength;

        return response.toString('base64');
    }

    _write(chunk, encoding, callback) {
        this.write(chunk, encoding, callback);
    }
  
    _read(size) {
    }

    _final(cb) {
        this._socket.end(cb);
      }
}
