# ntlm-socket
This project contains a implementation of a socket with builtin NTLM proxy capabilities. Any new desired functionality or bugs may be requested in the issues page. Currently only authenticates using NTLMv1 and ignore most flags;

## How the NTLM Protocol works
Whenever someone wants to have access to a proxy server (using NTLM), authentication is necessary, even for anonymous users. The protocol consists mostly of 3 messages, these messages are nothing more than common http messages but with an extra header. This header is always encoded in base64.

1. The first http message is called 'negotiate' it consists of the first http message of the client but with an extra http header, this header contains information about who is the client trying to authenticate.

2. The second message is the server response to the negotiate message, it's called 'challenge'. This message contains flags containing information about the proxy configuration and a random stream of bytes called challenge or 'nonce'.

3. The last message is the same http message from the first request, but the header of the proxy will contain a response to the challenge message, proving the user is who he says he is. This message is called 'authenticate'.

## How to use
The first step is to create a user. You can use your password in clear text, or use the hashes from it. Be warned that one flaw of the NTLM protocol is that those hashes can also be used to gain access, no password is needed. Be careful either way.

```javascript
const User = require('ntlm-socket/user');

let user1 = User.createUserWithCredentials('domAin', 'UserName', 'Passw0rd');

let hashes = User.getHash('Passw0rd');
let user2 = User.createUserWithHashs('domAin', 'user2', hashes.LMHash, hashes.NTHash);

```

Once you got the user you can use the socket as an EventEmitter or a stream, just like a normal socket.

```javascript
const User = require('ntlm-socket/user');
const NtlmSocket = require('ntlm-socket/ntlm-socket');

let user1 = User.createUserWithCredentials('domAin', 'UserName', 'Passw0rd');

let options = {
    headers: ['Proxy-Connection: keep-alive',
    'User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.100 Safari/537.36'
    ]
}

let socket = new NtlmSocket( user1, options);

socket.connect(3128, 'localhost', () => {
    console.log('Connected to proxy');
    socket.write('Hello world!!!', 'ascii', () => {
        console.log('Just wrote to the proxy');
    });
});
```
You can find a more complete example in the file [test.js](https://github.com/hugo-marello/ntlm-socket/blob/master/tests/test.js)

## Events
All common socket events are emitted so you can manipulate it yourself. They can also be listed as below.
```javascript
console.log(socket.socketEvents);
```

There are also other events, they are all prefixed with 'ntlm-'. They can also be listed.
```javascript
console.log(socket.customEvents);
```
Is recomended to listen to the 'ntlm-data' event, for the 'data' event will also be emitted before authorization.

* **ntlm-error**
contains error messages
* **ntlm-data**
contains read data after authorization
* **ntlm-authorized**
emitted after authorization
* **ntlm-authenticate**
emitted after the authenticate message is sent, contains the emitted header
* **ntlm-challenge**
emitted after the challenge is received, contains the challenge header
* **ntlm-negotiate**
emitted after the negotiate message is sent, contains the emitted header
