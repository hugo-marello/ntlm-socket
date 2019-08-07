const NtlmSocket = require('../ntlm-socket');
const User = require('../user');

let socket = new NtlmSocket( User.createUserWithCredentials('XXXX', 'XXXXX', 'XXXXX'), 
{
    headers: ['Proxy-Connection: keep-alive',
    'User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/75.0.3770.100 Safari/537.36'
    ]
}
);

socket.on('ntlm-error', (err) => {
    console.log('NtlmError: '+err);
});
socket.on('error', (err) => {
    console.log('Error: '+err);
});
socket.on('data', (data) => {
    console.log('received data on socket: '+data.length);
});

socket.on('ntlm-data', (data)=>{
    console.log('received data post-authorization: '+data.length);    
});

socket.on('ntlm-authorized', (arg)=>{
    console.log('ntlm-authorized');    
});
socket.on('ntlm-authenticate', (arg)=>{
    console.log('ntlm-authenticate');    
});
socket.on('ntlm-challenge', (arg)=>{
    console.log('ntlm-challenge');    
});
socket.on('ntlm-negotiate', (arg)=>{
    console.log('ntlm-negotiate');    
});


socket.connect(3128, 'proxy.rede.tst', () => {
    console.log('Connected to proxy');
});

var Readable = require('stream').Readable;
var rs = Readable({autoclose: false});

var sent = false;
rs._read = function () {   
    if(!sent){
        sent = true;
        rs.push(Buffer.from('GET http://pudim.com.br HTTP/1.1\r\nHost: pudim.com.br\r\n\r\n'));
    }
};

rs.pipe(socket).pipe(process.stdout);

