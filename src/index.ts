import { Sha256 } from "@aws-crypto/sha256-js";
import { SourceData } from "@smithy/types";
import BigInteger, { AuthBigInteger } from "./BigInteger";

export default class CognitoSRP {
  private INIT_N =
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
  private encoder = new TextEncoder();
  private N: AuthBigInteger;
  private g: AuthBigInteger;
  private a: AuthBigInteger;
  private k: AuthBigInteger;
  private A: AuthBigInteger = new BigInteger();
  private info: Uint8Array;

  public timestamp: string;

  constructor(private userPoolName: string) {
    this.N = new BigInteger(this.INIT_N, 16);
    this.g = new BigInteger("2", 16);

    const buffer = new Uint8Array(16);
    window.crypto.getRandomValues(buffer);
    const hexString = this.getHexFromBytes(buffer);

    this.a = new BigInteger(hexString, 16);
    this.k = new BigInteger(
      this.createHash(`${this.getPaddedHex(this.N)}${this.getPaddedHex(this.g)}`, { from: "hex", to: "hex" }),
      16
    );
    this.timestamp = this.createTimestamp();

    const context = this.encoder.encode("Caldera Derived Key");
    const spacer = this.encoder.encode(String.fromCharCode(1));
    this.info = this.concatenateArrays(context, spacer);
  }

  /**
   * Calculates the SRPA value is sent to the server when auth is initiated. It is used by the server to calculate the SRPB value,
   * which is returned to the client and then used to create the password claim signature.
   *
   * This function performs a modular exponentiation operation to generate an authentication value based on SRP (Secure Remote Password) protocol.
   * It checks for the legality of the computed value to ensure it does not equal zero when modulated by N.
   *
   * @returns A promise that resolves to the hexadecimal representation of the authentication value.
   * @throws {Error} If the computed value modulo N is zero or if there are other processing errors.
   */
  public async calculateSRPAValue(): Promise<string> {
    // TODO: see if i can create this value in the constructor somehow. Why is this async in the first place?
    this.A = await new Promise((resolve, reject) => {
      this.g.modPow(this.a, this.N, (err: unknown, A: AuthBigInteger) => {
        if (err) {
          reject(err);
          return;
        }

        if (A.mod(this.N).equals(BigInteger.ZERO)) {
          reject(new Error("Illegal parameter. A mod N cannot be 0."));
          return;
        }

        resolve(A);
      });
    });

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
  public async calculatePasswordClaimSignature(
    password: string,
    challengeParameters: {
      USER_ID_FOR_SRP: string;
      SALT: string;
      SECRET_BLOCK: string;
      SRP_B: string;
    }
  ): Promise<string> {
    const serverBValue = new BigInteger(challengeParameters.SRP_B, 16);

    if (serverBValue.mod(this.N).equals(BigInteger.ZERO)) throw new Error("B cannot be zero.");

    const U = this.calculateU(serverBValue);
    const serverSalt = new BigInteger(challengeParameters.SALT, 16);
    const x = new BigInteger(
      this.createHash(
        `${this.getPaddedHex(serverSalt)}${this.createHash(
          `${this.userPoolName}${challengeParameters.USER_ID_FOR_SRP}:${password}`,
          { to: "hex" }
        )}`,
        { from: "hex", to: "hex" }
      ),
      16
    );
    const S = await this.calculateS(x, serverBValue, U);

    const concatenatedArray = this.concatenateArrays(
      this.encoder.encode(this.userPoolName),
      this.encoder.encode(challengeParameters.USER_ID_FOR_SRP),
      this.urlB64ToUint8Array(challengeParameters.SECRET_BLOCK),
      this.encoder.encode(this.timestamp)
    );

    const awsHashHmac = this.createHash(this.info, {
      secret: this.createHash(this.getBytesFromHex(this.getPaddedHex(S)), {
        secret: this.getBytesFromHex(this.getPaddedHex(U)),
      }),
    });
    const awsHash = this.createHash(concatenatedArray, { secret: awsHashHmac.slice(0, 16) });

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

  private calculateU(B: AuthBigInteger): AuthBigInteger {
    const U = new BigInteger(
      this.createHash(this.getPaddedHex(this.A) + this.getPaddedHex(B), { from: "hex", to: "hex" }),
      16
    );

    if (U.equals(BigInteger.ZERO)) throw new Error("U cannot be zero.");

    return U;
  }

  private calculateS(x: AuthBigInteger, B: AuthBigInteger, U: AuthBigInteger): Promise<AuthBigInteger> {
    return new Promise((resolve, reject) => {
      this.g.modPow(x, this.N, (outerErr: unknown, outerResult: AuthBigInteger) => {
        if (outerErr) {
          reject(outerErr);

          return;
        }

        B.subtract(this.k.multiply(outerResult)).modPow(
          this.a.add(U.multiply(x)),
          this.N,
          (innerErr: unknown, innerResult: AuthBigInteger) => {
            if (innerErr) {
              reject(innerErr);

              return;
            }
            resolve(innerResult.mod(this.N));
          }
        );
      });
    });
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

  private createHash(data: string, options: { from: "hex" }): Uint8Array;
  private createHash(data: string, options: { from: "hex"; to: "hex" }): string;
  private createHash(data: SourceData, options: { to: "hex" }): string;
  private createHash(data: SourceData): Uint8Array;
  private createHash(data: SourceData, options: { secret: SourceData }): Uint8Array;
  private createHash(
    data: SourceData,
    options?: { from?: "hex"; to?: "hex"; secret?: SourceData }
  ): Uint8Array | string {
    const sha256 = new Sha256(options?.secret);
    sha256.update(options?.from === "hex" && typeof data === "string" ? this.getBytesFromHex(data) : data);
    const hashBytes = sha256.digestSync();

    return options?.to === "hex" ? this.getHexFromBytes(hashBytes) : hashBytes;
  }

  private getPaddedHex(bigInt: AuthBigInteger): string {
    if (!(bigInt instanceof BigInteger)) throw new Error("Not a BigInteger");

    /* Get a hex string for abs(bigInt) */
    let hex: string = bigInt.abs().toString(16);
    /* Pad hex to even length if needed */
    hex = hex.length % 2 !== 0 ? `0${hex}` : hex;
    /* Prepend "00" if the most significant bit is set */
    hex = /^[89a-f]/i.test(hex) ? `00${hex}` : hex;

    if (bigInt.compareTo(BigInteger.ZERO) < 0) {
      const invertedHex = hex
        .split("")
        .map((nibble) => (~parseInt(nibble, 16) & 0xf).toString(16).toUpperCase())
        .join("");

      hex = new BigInteger(invertedHex, 16).add(BigInteger.ONE).toString(16);

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
