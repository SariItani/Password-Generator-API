// app.js (Express server)

const express = require('express');
const crypto = require('crypto');
const app = express();

app.use(express.json());

const KEY = "PqA3s^";

function rotator(keyLength, keyBitNumber, iterations) {
    const gears = [];
    const rand = crypto.createHash('sha256').update(String(keyLength)).digest('hex');
    for (let i = 0; i < iterations; i++) {
        gears.push((parseInt(rand[i], 16) % (2 * keyBitNumber + 1)) - keyBitNumber);
    }
    return gears;
}

function getShift(array, index) {
    if (index < 0) index += array.length;
    return array[index];
}

function decodeString(passBits) {
    let bytes = [];
    for (let i = 0; i < passBits.length; i += 8) {
        let byte = 0;
        for (let j = 0; j < 8; j++) {
            byte |= (passBits[i + j] << (7 - j));
        }
        bytes.push(byte);
    }
    return Buffer.from(bytes).toString();
}

function encodeString(password) {
    const bytes = Buffer.from(password);
    const bits = [];
    for (let i = 0; i < bytes.length; i++) {
        for (let j = 0; j < 8; j++) {
            bits.push((bytes[i] >> (7 - j)) & 1);
        }
    }
    return bits;
}

function not(bit) {
    return bit === 0 ? 1 : 0;
}

function getMultiple(keyLength, passLength) {
    let n = 1;
    while (n * keyLength < passLength) {
        n++;
    }
    return n;
}

function encrypt(password) {
    const pass = encodeString(password);
    const key = encodeString(KEY);
    const iterations = getMultiple(key.length, pass.length);
    const newKey = new Array(key.length * iterations).fill(0);
    const newPass = new Array(pass.length).fill(0);

    const myGears = rotator(KEY.length, key.length, iterations);

    let round = 0;
    for (let i = 0; i < iterations; i++) {
        const index = getShift(key, myGears[i]);
        key[index] = not(key[index]);
        for (let j = 0; j < key.length; j++) {
            newKey[j + round] = key[j];
            if ((j + round) % 8 === 0 && (j + round) <= pass.length - 1) {
                const msb = newKey[j + round] ^ pass[j + round];
                if (msb === 1) {
                    newKey[j + round] = not(newKey[j + round]);
                }
            }
        }
        round += key.length;
    }

    for (let i = 0; i < pass.length; i++) {
        newPass[i] = pass[i] ^ newKey[i];
    }

    return decodeString(newPass);
}

app.post('/generate-password', (req, res) => {
    const { password } = req.body;
    const inputPassword = password || crypto.randomBytes(8).toString('hex');
    const encryptedPassword = encrypt(inputPassword);
    res.json({ encryptedPassword });
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log(`Server running on port ${PORT}`));
