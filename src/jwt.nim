import future, json, strutils, tables

from private/hmac import nil

import private/claims, private/jose, private/utils

type
    InvalidToken = object of Exception

    JWT* = object
        headerB64: string
        claimsB64: string
        header*: JOSEHeader
        claims*: TableRef[string, Claim]
        signature*: string

export claims
export jose



proc splitToken(s: string): seq[string] =
    let parts = s.split(".")
    if parts.len != 3:
        raise newException(InvalidToken, "Invalid token")
    result = parts


# Load up a b64url string to JWT
proc toJWT*(s: string): JWT =
    var parts = splitToken(s)
    let
      headerB64 = parts[0]
      claimsB64 = parts[1]
      headerJson = parseJson(decodeUrlSafe(headerB64))
      claimsJson = parseJson(decodeUrlSafe(claimsB64))
      signature = decodeUrlSafe(parts[2])

    result = JWT(
        headerB64: headerB64,
        claimsB64: claimsB64,
        header: headerJson.toHeader(),
        claims: claimsJson.toClaims(),
        signature: signature
    )


proc toJWT*(node: JsonNode): JWT =
  let claims = node["claims"].toClaims
  let header = node["header"].toHeader

  JWT(
    claims: claims,
    header: header
  )


# Encodes the raw signature hex to b64url
proc signatureToB64(token: JWT): string =
  assert token.signature != nil
  result = encodeUrlSafe(token.signature)


proc loaded*(token: JWT): string =
  token.headerB64 & "." & token.claimsB64


proc parsed*(token: JWT): string =
  result = token.header.toBase64 & "." & token.claims.toBase64


# Signs a string with a secret
proc signString*(toSign: string, secret: var string): string =
  var
    signature: array[32, uint8]
    sigsize: cuint
  discard hmac.HMAC(hmac.EVP_sha256(), addr(secret[0]), 8, toSign.cstring, toSign.len.cint, cast[ptr char](addr signature), addr sigsize)
  result = join(signature.map((i: uint8) => (toHex(BiggestInt(i), 2))), "")


# Verify that the token is not tampered with
proc verifySignature*(data: string, signature: string, secret: var string): bool =
  let dataSignature = signString(data, secret)
  result = dataSignature == signature


proc sign*(token: var JWT, secret: var string) =
  assert token.signature == nil
  token.signature = signString(token.parsed, secret)


# Verify a token typically an incoming request
proc verify*(token: JWT, secret: var string): bool =
  result = verifySignature(token.loaded, token.signature, secret)


proc toString*(token: JWT): string =
  token.header.toBase64 & "." & token.claims.toBase64 & "." & token.signatureToB64


proc `$`*(token: JWT): string =
  token.toString


proc `%`*(token: JWT): JsonNode =
  let s = $token
  %s


when isMainModule:
    # Load a token from json
    let
      claimsJson = %{
        "iss": %"jane",
        "sub": %"john",
        "nbf": %1234,
        "iat": %1234,
        "exp": %1234,
        "jti": %"token-id",
        "foo": %{"bar": %1}
      }
      headerJson = %{"alg": %"HS256", "typ": %"JWT"}

    # Load it as JWT
    var
      token = JWT(
        claims: claimsJson.toClaims,
        header: headerJson.toHeader
      )
      secret = "secret"

    # Sign and verify
    token.sign(secret)

    let b64Token = $token
    token = b64Token.toJWT
    assert token.verify(secret) == true
