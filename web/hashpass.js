'use strict';
const scrypt = require('scrypt-async');

const text_encoder = new TextEncoder()

function to_bytes(string) {
    return text_encoder.encode(string.normalize('NFKC'))
}

function hashpass_derive(master_password, domain, user, counter, length, charset, callback) {
    if (counter < 0 || counter > 255) throw new RangeError('Counter must be in range [0, 255]');
    master_password = to_bytes(master_password)
    domain = to_bytes(domain)
    user = to_bytes(user)
    var salt = new Uint8Array(domain.length + user.length + 3)
    salt.set(domain, 0)
    salt.set(user, domain.length + 1)
    salt[salt.length - 1] = counter

    scrypt(master_password, salt, { N: 16384, r: 8, p: 1, dkLen: 16, encoding: 'binary' },
        function (result) {
            console.log(result);
        });
}

hashpass_derive("f", "google", "rsy", 1, 9, '0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ!"#$%&\'()*+,-./:;<=>?@[\\]^_`{|}~ \t\n\r\x0b\x0c');
