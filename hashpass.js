'use strict';
const text_encoder = new TextEncoder()

function to_bytes(string) {
    return text_encoder.encode(string.normalize('NFKC'))
}

function large_divmod(large_dividend, divisor) {
    divisor = divisor | 0;
    let remainder = 0;
    for (let i = 0; i < large_dividend.length; ++i) {
        let x = (remainder << 8) | large_dividend[i];
        large_dividend[i] = x / divisor;
        remainder = x % divisor;
    }
    return remainder;
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

    scrypt(master_password, salt, { N: 65536, r: 8, p: 1, dkLen: 16, encoding: 'binary' },
        function (hashed) {
            let buffer = new Array(length);
            for (let i = 0; i < length; ++i) {
                buffer[i] = charset[large_divmod(hashed, charset.length)];
            }
            callback(buffer.join(''));
        });
}
