# `jsf`

[JSON Signature Format (JSF)](https://cyberphone.github.io/doc/security/jsf.html) helper crate.

# API

::: warning
this is just a draft for now
:::

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

# License

MIT-Licensed, see [LICENSE](./LICENSE).
