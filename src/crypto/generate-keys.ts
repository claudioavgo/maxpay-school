import { ensureSigningKeys, newMasterKeyHex } from "./keys.js";

ensureSigningKeys();
console.log("Signing key pair ready in certs/");
console.log("MASTER_KEY_HEX=" + newMasterKeyHex());
