import future, json, strutils, tables

from private/hmac import nil

import private/claims, private/jose, private/utils

type
    InvalidToken = object of Exception

    JWT* = object
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
      headerNode = parseJson(decodeUrlSafe(parts[0]))
      payloadNode = parseJson(decodeUrlSafe(parts[1]))
      signature = decodeUrlSafe(parts[2])

    result = JWT(
        header: headerNode.toHeader(),
        claims: payloadNode.toClaims(),
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
  return encodeUrlSafe(token.signature)


# Returns the signature as a string
proc sign*(token: JWT, secret: var string): string =
  var
    signature:  array[32, uint8]
    sigsize: cuint
    toSign = token.header.toBase64 & "." & token.claims.toBase64

  discard hmac.HMAC(hmac.EVP_sha256(), addr(secret[0]), 8, toSign.cstring, toSign.len.cint, cast[ptr char](addr signature), addr sigsize)

  result = $signature.map((i: uint8) => (toHex(BiggestInt(i), 2)))


# Verify that the token is not tampered with
proc verify*(token: JWT, secret: var string): bool =
  let signature = token.sign(secret)
  result = token.signature == signature


proc toString*(token: JWT): string =
  result = token.header.toBase64 & "." & token.claims.toBase64 & "." & token.signatureToB64

proc `$`*(token: JWT): string =
  token.toString

proc `%`*(token: JWT): JsonNode =
  $token

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
        header: headerJson.toHeaders
      )
      secret = "secret"

    # Sign and verify
    token.signature = token.sign(secret)
    assert token.verify(secret) == true

    let b64Token = $token
    token = b64Token.toJWT
    assert token.verify(secret) == true
