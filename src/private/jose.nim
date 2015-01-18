import json, strutils, tables

import utils

type
    CryptoException = object of Exception
    UnsupportedAlgorithm = object of CryptoException

    SignatureAlgorithm* = enum
        NONE = "NONE"
        HS256 = "HS256"

    JOSEHeader* = object
        alg*: SignatureAlgorithm
        typ*: string


proc strToSignatureAlgorithm(s: string): SignatureAlgorithm =
    try:
        result = parseEnum[SignatureAlgorithm](s)
    except ValueError:
        raise newException(UnsupportedAlgorithm, "$# isn't supported" % s)


proc toHeaders*(j: JsonNode): JOSEHeader =
    let algStr = j["alg"].str
    let algo = strToSignatureAlgorithm(algStr)

    # Check that the keys are present so we dont blow up.
    utils.checkKeysExists(j, "alg", "typ")

    result = JOSEHeader(
        alg: algo,
        typ: j["typ"].str
    )


proc `%`*(alg: SignatureAlgorithm): JsonNode =
    let s = $alg
    return %s


proc `%`*(h: JOSEHeader): JsonNode =
    return %{
        "alg": %h.alg,
        "typ": %h.typ
    }


proc toBase64*(h: JOSEHeader): string =
    let asJson = %h
    result = encodeUrlSafe($asJson)


when isMainModule:
    let algTests = @[
        (NONE, %"NONE"),
        (HS256, %"HS256")
    ]

    for i, v in algTests:
        let sigAsJSON = %v[0]
        assert sigAsJSON == v[1]

    let i = %{"alg": %"HS256", "typ": %"JWT"}
    let header = i.toJOSEHeader
    assert (%header == i)