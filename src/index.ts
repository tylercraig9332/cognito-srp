import { Sha256 } from "@aws-crypto/sha256-js";
import { SourceData } from "@smithy/types";
import { modPow } from "./bigIntUtils";

export default class CognitoSRP {
  private readonly INIT_N =
    "FFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD1" +
    "29024E088A67CC74020BBEA63B139B22514A08798E3404DD" +
    "EF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245" +
    "E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7ED" +
    "EE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3D" +
    "C2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F" +
    "83655D23DCA3AD961C62F356208552BB9ED529077096966D" +
    "670C354E4ABC9804F1746C08CA18217C32905E462E36CE3B" +
    "E39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9" +
    "DE2BCBF6955817183995497CEA956AE515D2261898FA0510" +
    "15728E5A8AAAC42DAD33170D04507A33A85521ABDF1CBA64" +
    "ECFB850458DBEF0A8AEA71575D060C7DB3970F85A6E1E4C7" +
    "ABF5AE8CDB0933D71E8C94E04A25619DCEE3D2261AD2EE6B" +
    "F12FFA06D98A0864D87602733EC86A64521F2B18177B200C" +
    "BBE117577A615D6C770988C0BAD946E208E24FA074E5AB31" +
    "43DB5BFCE0FD108E4B82D120A93AD2CAFFFFFFFFFFFFFFFF";
  private readonly N = BigInt(`0x${this.INIT_N}`);
  private readonly g = 2n;
  private readonly k = BigInt(
    `0x${this.getHexFromBytes(
      this.createHash(this.getBytesFromHex(`${this.getPaddedHex(this.N)}${this.getPaddedHex(this.g)}`))
    )}`
  );
  private a!: bigint;
  private A!: bigint;
  private crypto!: Crypto;
  private encoder = new TextEncoder();

  public timestamp!: string;

  constructor(private userPoolName: string) {
    if (typeof window !== "undefined" && window.crypto) this.crypto = window.crypto;
    if (typeof process === "object" && process.versions && process.versions.node) {
      this.crypto = require("crypto").webcrypto;
    }
  }

  /**
   * Calculates the SRPA value is sent to the server when auth is initiated. It is used by the server to calculate the SRPB value,
   * which is returned to the client and then used to create the password claim signature.
   *
   * This function performs a modular exponentiation operation to generate an authentication value based on SRP (Secure Remote Password) protocol.
   * It checks for the legality of the computed value to ensure it does not equal zero when modulated by N.
   *
   * @returns A hexadecimal representation of the authentication value.
   * @throws {Error} If the computed value modulo N is zero or if there are other processing errors.
   */
  public calculateSRPAValue(): string {
    const buffer = new Uint8Array(16);
    this.crypto.getRandomValues(buffer);

    this.a = BigInt(`0x${this.getHexFromBytes(buffer)}`);
    this.A = modPow(this.g, this.a, this.N);

    return this.A.toString(16);
  }

  /**
   * Calculates the password claim signature for AWS Cognito's Secure Remote Password (SRP) authentication.
   *
   * @param password - The user's password.
   * @param challengeParameters - The challenge parameters from AWS Cognito.
   * @param challengeParameters.USER_ID_FOR_SRP - The user's ID for SRP.
   * @param challengeParameters.SALT - The salt value for the SRP protocol.
   * @param challengeParameters.SECRET_BLOCK - The secret block value for the SRP protocol.
   * @param challengeParameters.SRP_B - The SRP B value from the server.
   * @returns The password claim signature value.
   * @throws {Error} Throws an error if the calculation fails.
   */
  public calculatePasswordClaimSignature(
    password: string,
    challengeParameters: {
      USER_ID_FOR_SRP: string;
      SALT: string;
      SECRET_BLOCK: string;
      SRP_B: string;
    }
  ): string {
    this.timestamp = this.createTimestamp();
    const serverBValue = BigInt(`0x${challengeParameters.SRP_B}`);

    if (serverBValue % this.N === 0n) throw new Error("Invalid server public key");

    const U = this.calculateU(serverBValue);
    const serverSalt = BigInt(`0x${challengeParameters.SALT}`);
    const userPasswordHash = this.createHash(`${this.userPoolName}${challengeParameters.USER_ID_FOR_SRP}:${password}`);
    const saltedUserPassHash = this.createHash(
      this.getBytesFromHex(`${this.getPaddedHex(serverSalt)}${this.getHexFromBytes(userPasswordHash)}`)
    );
    const x = BigInt(`0x${this.getHexFromBytes(saltedUserPassHash)}`);
    const S = this.calculateS(x, serverBValue, U);

    const concatenatedArray = this.concatenateArrays(
      this.encoder.encode(this.userPoolName),
      this.encoder.encode(challengeParameters.USER_ID_FOR_SRP),
      this.urlB64ToUint8Array(challengeParameters.SECRET_BLOCK),
      this.encoder.encode(this.timestamp)
    );

    const context = this.encoder.encode("Caldera Derived Key");
    const spacer = this.encoder.encode(String.fromCharCode(1));
    const info = this.concatenateArrays(context, spacer);

    const hmacSecret = this.createHash(
      this.getBytesFromHex(this.getPaddedHex(S)),
      this.getBytesFromHex(this.getPaddedHex(U))
    );
    const awsHashHmac = this.createHash(info, hmacSecret);
    const awsHash = this.createHash(concatenatedArray, awsHashHmac.slice(0, 16));

    return btoa(Array.from(awsHash, (byte) => String.fromCodePoint(byte)).join(""));
  }

  private concatenateArrays(...arrays: Uint8Array[]): Uint8Array {
    const concatenatedArray = new Uint8Array(arrays.reduce((acc, arr) => acc + arr.byteLength, 0));
    let length = 0;

    for (const array of arrays) {
      concatenatedArray.set(array, length);
      length += array.byteLength;
    }

    return concatenatedArray;
  }

  private calculateU(B: bigint): bigint {
    const hexAB = `${this.getPaddedHex(this.A)}${this.getPaddedHex(B)}`;
    const hashHex = this.getHexFromBytes(this.createHash(this.getBytesFromHex(hexAB)));
    const U = BigInt(`0x${hashHex}`);

    if (U === 0n) throw new Error("U cannot be zero.");

    return U;
  }

  private calculateS(x: bigint, B: bigint, U: bigint): bigint {
    const t0 = modPow(this.g, x, this.N) * this.k;
    const t1 = B - t0;
    const t2 = this.a + U * x;
    return modPow(t1, t2, this.N);
  }

  private getBytesFromHex(encoded: string): Uint8Array {
    const matchArray = encoded.match(/(..)/g);

    if (!matchArray) throw new Error("Invalid Hex String.");

    return Uint8Array.from(matchArray.map((hex) => parseInt(hex, 16)));
  }

  private getHexFromBytes(bytes: Uint8Array): string {
    return Array.from(bytes)
      .map((byte) => byte.toString(16).padStart(2, "0"))
      .join("");
  }

  private createHash(data: SourceData, secret?: SourceData): Uint8Array {
    const sha256 = new Sha256(secret);
    sha256.update(data);
    return sha256.digestSync();
  }

  private getPaddedHex(bigInt: bigint): string {
    let hex: string = bigInt.toString(16);
    /* Pad hex to even length if needed */
    hex = hex.length % 2 !== 0 ? `0${hex}` : hex;
    /* Prepend "00" if the most significant bit is set */
    hex = /^[89a-f]/i.test(hex) ? `00${hex}` : hex;

    if (bigInt < 0n) {
      const invertedHex = hex
        .split("")
        .map((nibble) => (~parseInt(nibble, 16) & 0xf).toString(16).toUpperCase())
        .join("");

      hex = (BigInt(`0x${invertedHex}`) + 1n).toString(16);

      if (hex.toUpperCase().startsWith("FF8")) hex = hex.substring(2);
    }

    return hex;
  }

  private urlB64ToUint8Array(base64String: string): Uint8Array {
    const padding = "=".repeat((4 - (base64String.length % 4)) % 4);
    const base64 = `${base64String}${padding}`.replace(/-/g, "+").replace(/_/g, "/");

    const rawData = atob(base64);
    const outputArray = new Uint8Array(rawData.length);

    for (let i = 0; i < rawData.length; ++i) {
      outputArray[i] = rawData.charCodeAt(i);
    }

    return outputArray;
  }

  private createTimestamp() {
    const now = new Date();

    const weekDay = ["Sun", "Mon", "Tue", "Wed", "Thu", "Fri", "Sat"][now.getUTCDay()];
    const month = ["Jan", "Feb", "Mar", "Apr", "May", "Jun", "Jul", "Aug", "Sep", "Oct", "Nov", "Dec"][
      now.getUTCMonth()
    ];
    const date = now.getUTCDate();

    const hours = now.getUTCHours().toString().padStart(2, "0");
    const minutes = now.getUTCMinutes().toString().padStart(2, "0");
    const seconds = now.getUTCSeconds().toString().padStart(2, "0");

    const year = now.getUTCFullYear();

    return `${weekDay} ${month} ${date} ${hours}:${minutes}:${seconds} UTC ${year}`;
  }
}
