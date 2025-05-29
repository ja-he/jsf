# `jsf`

[JSON Signature Format (JSF)](https://cyberphone.github.io/doc/security/jsf.html) helper crate.

# API

> [!WARNING]
> this is just a draft for now

```
try_from(<jwk-str>) -> Result<<jwk>>
sign(<json-str>, <jwk>) -> Result<<json-str>>
sign(<json-obj>, <jwk>) -> Result<<json-obj>>
```

## Example

```rs
let signed_obj_str = sign(r#"{"foo":"bar"}"#, r#"{"kty":"EC",...}"#.try_into()?)?;
```

# Status

Experimental / exploratory / WIP

## Coverage of JSF Spec Test Vectors

### Signatures

| Name                                        | Parse | Verify | Spec                                                                                                 |
| ---                                         | ---   | ---    | ---                                                                                                  |
| `p256#es256@kid.json`                       | ❌    | ❌     | [link](https://cyberphone.github.io/doc/security/jsf.html#p256_es256_kid.json)                       |
| `p256#es256@imp.json`                       | ❌    | ❌     | [link](https://cyberphone.github.io/doc/security/jsf.html#p256_es256_imp.json)                       |
| `p256#es256@cer.json`                       | ❌    | ❌     | [link](https://cyberphone.github.io/doc/security/jsf.html#p256_es256_cer.json)                       |
| `p256#es256@name-jwk.json`                  | ✅    | ✅     | [link](https://cyberphone.github.io/doc/security/jsf.html#p256_es256_name-jwk.json)                  |
| `p256#es256@exts-jwk.json`                  | ✅    | ✅     | [link](https://cyberphone.github.io/doc/security/jsf.html#p256_es256_exts-jwk.json)                  |
| `p256#es256@excl-jwk.json`                  | ❌    | ❌     | [link](https://cyberphone.github.io/doc/security/jsf.html#p256_es256_excl-jwk.json)                  |
| `p384#es384@jwk.json`                       | ❌    | ❌     | [link](https://cyberphone.github.io/doc/security/jsf.html#p384_es384_jwk.json)                       |
| `p384#es384@kid.json`                       | ❌    | ❌     | [link](https://cyberphone.github.io/doc/security/jsf.html#p384_es384_kid.json)                       |
| `p384#es384@imp.json`                       | ❌    | ❌     | [link](https://cyberphone.github.io/doc/security/jsf.html#p384_es384_imp.json)                       |
| `p384#es384@cer.json`                       | ❌    | ❌     | [link](https://cyberphone.github.io/doc/security/jsf.html#p384_es384_cer.json)                       |
| `p521#es512@jwk.json`                       | ❌    | ❌     | [link](https://cyberphone.github.io/doc/security/jsf.html#p521_es512_jwk.json)                       |
| `p521#es512@kid.json`                       | ❌    | ❌     | [link](https://cyberphone.github.io/doc/security/jsf.html#p521_es512_kid.json)                       |
| `p521#es512@imp.json`                       | ❌    | ❌     | [link](https://cyberphone.github.io/doc/security/jsf.html#p521_es512_imp.json)                       |
| `p521#es512@cer.json`                       | ❌    | ❌     | [link](https://cyberphone.github.io/doc/security/jsf.html#p521_es512_cer.json)                       |
| `r2048#rs256@jwk.json`                      | ❌    | ❌     | [link](https://cyberphone.github.io/doc/security/jsf.html#r2048_rs256_jwk.json)                      |
| `r2048#ps256@jwk.json`                      | ❌    | ❌     | [link](https://cyberphone.github.io/doc/security/jsf.html#r2048_ps256_jwk.json)                      |
| `r2048#rs256@kid.json`                      | ❌    | ❌     | [link](https://cyberphone.github.io/doc/security/jsf.html#r2048_rs256_kid.json)                      |
| `r2048#rs256@imp.json`                      | ❌    | ❌     | [link](https://cyberphone.github.io/doc/security/jsf.html#r2048_rs256_imp.json)                      |
| `r2048#rs256@cer.json`                      | ❌    | ❌     | [link](https://cyberphone.github.io/doc/security/jsf.html#r2048_rs256_cer.json)                      |
| `ed25519#ed25519@jwk.json`                  | ❌    | ❌     | [link](https://cyberphone.github.io/doc/security/jsf.html#ed25519_ed25519_jwk.json)                  |
| `ed25519#ed25519@kid.json`                  | ❌    | ❌     | [link](https://cyberphone.github.io/doc/security/jsf.html#ed25519_ed25519_kid.json)                  |
| `ed25519#ed25519@imp.json`                  | ❌    | ❌     | [link](https://cyberphone.github.io/doc/security/jsf.html#ed25519_ed25519_imp.json)                  |
| `ed25519#ed25519@cer.json`                  | ❌    | ❌     | [link](https://cyberphone.github.io/doc/security/jsf.html#ed25519_ed25519_cer.json)                  |
| `ed448#ed448@jwk.json`                      | ❌    | ❌     | [link](https://cyberphone.github.io/doc/security/jsf.html#ed448_ed448_jwk.json)                      |
| `ed448#ed448@kid.json`                      | ❌    | ❌     | [link](https://cyberphone.github.io/doc/security/jsf.html#ed448_ed448_kid.json)                      |
| `ed448#ed448@imp.json`                      | ❌    | ❌     | [link](https://cyberphone.github.io/doc/security/jsf.html#ed448_ed448_imp.json)                      |
| `ed448#ed448@cer.json`                      | ❌    | ❌     | [link](https://cyberphone.github.io/doc/security/jsf.html#ed448_ed448_cer.json)                      |
| `a256#hs256@kid.json`                       | ❌    | ❌     | [link](https://cyberphone.github.io/doc/security/jsf.html#a256_hs256_kid.json)                       |
| `a384#hs384@kid.json`                       | ❌    | ❌     | [link](https://cyberphone.github.io/doc/security/jsf.html#a384_hs384_kid.json)                       |
| `a512#hs512@kid.json`                       | ❌    | ❌     | [link](https://cyberphone.github.io/doc/security/jsf.html#a512_hs512_kid.json)                       |
| `p256#es256,r2048#rs256@mult-jwk.json`      | ❌    | ❌     | [link](https://cyberphone.github.io/doc/security/jsf.html#p256_es256_r2048_rs256_mult-jwk.json)      |
| `p256#es256,r2048#rs256@mult-exts-kid.json` | ❌    | ❌     | [link](https://cyberphone.github.io/doc/security/jsf.html#p256_es256_r2048_rs256_mult-exts-kid.json) |
| `p256#es256,r2048#rs256@mult-excl-kid.json` | ❌    | ❌     | [link](https://cyberphone.github.io/doc/security/jsf.html#p256_es256_r2048_rs256_mult-excl-kid.json) |
| `p256#es256,r2048#rs256@chai-jwk.json`      | ❌    | ❌     | [link](https://cyberphone.github.io/doc/security/jsf.html#p256_es256_r2048_rs256_chai-jwk.json)      |
| `p256#es256,r2048#rs256@chai-exts-kid.json` | ❌    | ❌     | [link](https://cyberphone.github.io/doc/security/jsf.html#p256_es256_r2048_rs256_chai-exts-kid.json) |

## Private Keys

| Name                    | TODO |
| ---                     | ---  |
| `p256privatekey.jwk`    | ❌   |
| `p384privatekey.jwk`    | ❌   |
| `p521privatekey.jwk`    | ❌   |
| `r2048privatekey.jwk`   | ❌   |
| `ed25519privatekey.jwk` | ❌   |
| `ed448privatekey.jwk`   | ❌   |

# License

MIT-Licensed, see [LICENSE](./LICENSE).
