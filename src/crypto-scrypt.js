/*
* Copyright (c) 2010-2011 Intalio Pte, All Rights Reserved
* 
* Permission is hereby granted, free of charge, to any person obtaining a copy
* of this software and associated documentation files (the "Software"), to deal
* in the Software without restriction, including without limitation the rights
* to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
* copies of the Software, and to permit persons to whom the Software is
* furnished to do so, subject to the following conditions:
* 
* The above copyright notice and this permission notice shall be included in
* all copies or substantial portions of the Software.
* 
* THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
* IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
* FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
* AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
* LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
* OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
* THE SOFTWARE.
*/
// https://github.com/cheongwy/node-scrypt-js
(function () {

	var MAX_VALUE = 2147483647;
	var workerUrl = null;

	//function scrypt(byte[] passwd, byte[] salt, int N, int r, int p, int dkLen)
	/*
	* N = Cpu cost
	* r = Memory cost
	* p = parallelization cost
	* 
	*/
	window.Crypto_scrypt = function (passwd, salt, N, r, p, dkLen, callback) {
		if (N == 0 || (N & (N - 1)) != 0) throw Error("N must be > 0 and a power of 2");

		if (N > MAX_VALUE / 128 / r) throw Error("Parameter N is too large");
		if (r > MAX_VALUE / 128 / p) throw Error("Parameter r is too large");

		var PBKDF2_opts = { iterations: 1, hasher: Crypto.SHA256, asBytes: true };

		var B = Crypto.PBKDF2(passwd, salt, p * 128 * r, PBKDF2_opts);
		console.log(B);
		var B32 = convert_to_i32a(B);
		console.log(B32);
		scryptCore();
		console.log(B32);
		console.log(B);
		convert_from_i32a(B32, B);
		console.log(B);
		callback(Crypto.PBKDF2(passwd, B, dkLen, PBKDF2_opts));

		// Do a little-endian conversion from the given Uint8Array.
		function convert_to_i32a(ui8a) {
			var inl = ui8a.length;
			var outl = Math.ceil(inl/4);
			var out = new Int32Array(outl);

			var o = 0;
			for (var i = 0; i < inl; ) {
				var tmp = 0;
				var shift = 0;
				while (i < inl && shift < 32) {
					tmp |= (ui8a[i++] << shift);
					shift += 8;
				}
				out[o++] = tmp;
			}
			return out;
		}

		// Do a little-endian conversion back out to Int32Array.
		function convert_from_i32a(i32a, ui8a) {
			var shift = 0;
			var j = 0;
			for (var i = 0; i < ui8a.length; i++) {
				ui8a[i] = (i32a[j] >> shift) & 0xff;
				shift += 8;
				if (shift == 32) {
					shift = 0;
					j++;	
				}
			}
		}

		// using this function to enclose everything needed to create a worker (but also invokable directly for synchronous use)
		function scryptCore() {
			var XY = new Int32Array(64*r);
			var V = new Int32Array(32*r*N);
			for (var i = 0; i < p; i++) {
				smix(B32, i * 32 * r, r, N, V, XY);
			}

			function smix(B, Bi, r, N, V, XY) {
				var Xi = 0;
				var Yi = 32 * r;
				var i;

				arraycopy32(B, Bi, XY, Xi, Yi);

				for (i = 0; i < N; i++) {
					if (i % 1024 == 0) {
					console.log("C" + i);
					}
					arraycopy32(XY, Xi, V, i * Yi, Yi);
					blockmix_salsa8(XY, Xi, Yi, r);
				}
				console.log("D");

				for (i = 0; i < N; i++) {
					if (i % 1024 == 0) {
					console.log("D" + i);
					}
					var j = integerify(XY, Xi, r) & (N - 1);
					blockxor(V, j * Yi, XY, Xi, Yi);
					blockmix_salsa8(XY, Xi, Yi, r);
				}
				console.log("E");

				arraycopy32(XY, Xi, B, Bi, Yi);
			}

			function blockmix_salsa8(BY, Bi, Yi, r) {
				var X = [];
				var i;

				arraycopy32(BY, Bi + (2 * r - 1) * 16, X, 0, 16);

				for (i = 0; i < 2 * r; i++) {
					blockxor(BY, i * 16, X, 0, 16);
					salsa20_8(X);
					arraycopy32(X, 0, BY, Yi + (i * 16), 16);
				}

				for (i = 0; i < r; i++) {
					arraycopy32(BY, Yi + (i * 2) * 16, BY, Bi + (i * 16), 16);
				}

				for (i = 0; i < r; i++) {
					arraycopy32(BY, Yi + (i * 2 + 1) * 16, BY, Bi + (i + r) * 16, 16);
				}
			}

			function salsa20_8(B32) {
				var x = new Int32Array(16);
				var i;
				var u;
				var x0, x1, x2, x3, x4, x5, x6, x7, x8, x9, x10, x11, x12, x13, x14, x15;

				x0  = B32[0]  | 0 ;
				x1  = B32[1]  | 0 ;
				x2  = B32[2]  | 0 ;
				x3  = B32[3]  | 0 ;
				x4  = B32[4]  | 0 ;
				x5  = B32[5]  | 0 ;
				x6  = B32[6]  | 0 ;
				x7  = B32[7]  | 0 ;
				x8  = B32[8]  | 0 ;
				x9  = B32[9]  | 0 ;
				x10 = B32[10] | 0 ;
				x11 = B32[11] | 0 ;
				x12 = B32[12] | 0 ;
				x13 = B32[13] | 0 ;
				x14 = B32[14] | 0 ;
				x15 = B32[15] | 0 ;

				for (i = 8; i > 0; i -= 2) {
					 u = (x0  + x12) | 0 ;   x4  ^= (u<<7)  | (u>>>25)
				     u = (x4  + x0 ) | 0 ;   x8  ^= (u<<9)  | (u>>>23)
				     u = (x8  + x4 ) | 0 ;   x12 ^= (u<<13) | (u>>>19)
				     u = (x12 + x8 ) | 0 ;   x0  ^= (u<<18) | (u>>>14)
				     u = (x5  + x1 ) | 0 ;   x9  ^= (u<<7)  | (u>>>25)
				     u = (x9  + x5 ) | 0 ;   x13 ^= (u<<9)  | (u>>>23)
				     u = (x13 + x9 ) | 0 ;   x1  ^= (u<<13) | (u>>>19)
				     u = (x1  + x13) | 0 ;   x5  ^= (u<<18) | (u>>>14)
				     u = (x10 + x6 ) | 0 ;   x14 ^= (u<<7)  | (u>>>25)
				     u = (x14 + x10) | 0 ;   x2  ^= (u<<9)  | (u>>>23)
				     u = (x2  + x14) | 0 ;   x6  ^= (u<<13) | (u>>>19)
				     u = (x6  + x2 ) | 0 ;   x10 ^= (u<<18) | (u>>>14)
				     u = (x15 + x11) | 0 ;   x3  ^= (u<<7)  | (u>>>25)
				     u = (x3  + x15) | 0 ;   x7  ^= (u<<9)  | (u>>>23)
				     u = (x7  + x3 ) | 0 ;   x11 ^= (u<<13) | (u>>>19)
				     u = (x11 + x7 ) | 0 ;   x15 ^= (u<<18) | (u>>>14)
				     u = (x0  + x3 ) | 0 ;   x1  ^= (u<<7)  | (u>>>25)
				     u = (x1  + x0 ) | 0 ;   x2  ^= (u<<9)  | (u>>>23)
				     u = (x2  + x1 ) | 0 ;   x3  ^= (u<<13) | (u>>>19)
				     u = (x3  + x2 ) | 0 ;   x0  ^= (u<<18) | (u>>>14)
				     u = (x5  + x4 ) | 0 ;   x6  ^= (u<<7)  | (u>>>25)
				     u = (x6  + x5 ) | 0 ;   x7  ^= (u<<9)  | (u>>>23)
				     u = (x7  + x6 ) | 0 ;   x4  ^= (u<<13) | (u>>>19)
				     u = (x4  + x7 ) | 0 ;   x5  ^= (u<<18) | (u>>>14)
				     u = (x10 + x9 ) | 0 ;   x11 ^= (u<<7)  | (u>>>25)
				     u = (x11 + x10) | 0 ;   x8  ^= (u<<9)  | (u>>>23)
				     u = (x8  + x11) | 0 ;   x9  ^= (u<<13) | (u>>>19)
				     u = (x9  + x8 ) | 0 ;   x10 ^= (u<<18) | (u>>>14)
				     u = (x15 + x14) | 0 ;   x12 ^= (u<<7)  | (u>>>25)
				     u = (x12 + x15) | 0 ;   x13 ^= (u<<9)  | (u>>>23)
				     u = (x13 + x12) | 0 ;   x14 ^= (u<<13) | (u>>>19)
				     u = (x14 + x13) | 0 ;   x15 ^= (u<<18) | (u>>>14)
				}

				B32[0]  += x0;
				B32[1]  += x1;
				B32[2]  += x2;
				B32[3]  += x3;
				B32[4]  += x4;
				B32[5]  += x5;
				B32[6]  += x6;
				B32[7]  += x7;
				B32[8]  += x8;
				B32[9]  += x9;
				B32[10] += x10;
				B32[11] += x11;
				B32[12] += x12;
				B32[13] += x13;
				B32[14] += x14;
				B32[15] += x15;
			}

			function blockxor(S, Si, D, Di, len) {
				var i = len >> 4;
				while (i--) {
					D[Di++] ^= S[Si++]; D[Di++] ^= S[Si++];
					D[Di++] ^= S[Si++]; D[Di++] ^= S[Si++];
					D[Di++] ^= S[Si++]; D[Di++] ^= S[Si++];
					D[Di++] ^= S[Si++]; D[Di++] ^= S[Si++];

					D[Di++] ^= S[Si++]; D[Di++] ^= S[Si++];
					D[Di++] ^= S[Si++]; D[Di++] ^= S[Si++];
					D[Di++] ^= S[Si++]; D[Di++] ^= S[Si++];
					D[Di++] ^= S[Si++]; D[Di++] ^= S[Si++];
				}
			}

			function integerify(B, bi, r) {
				var n;
				bi += (2 * r - 1) * 16;
				n = B[bi]
				return n;
			}

			function arraycopy(src, srcPos, dest, destPos, length) {
				while (length--) {
					dest[destPos++] = src[srcPos++];
				}
			}

			function arraycopy32(src, srcPos, dest, destPos, length) {
				var i = length >> 3;
				while (i--) {
					dest[destPos++] = src[srcPos++]; dest[destPos++] = src[srcPos++];
					dest[destPos++] = src[srcPos++]; dest[destPos++] = src[srcPos++];
					dest[destPos++] = src[srcPos++]; dest[destPos++] = src[srcPos++];
					dest[destPos++] = src[srcPos++]; dest[destPos++] = src[srcPos++];
				}
			}
		} // scryptCore
	}; // window.Crypto_scrypt
})();