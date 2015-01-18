# crypto/hmac/hmac.h
# Copyright (C) 1995-1998 Eric Young (eay@cryptsoft.com)
#  All rights reserved.
#
#  This package is an SSL implementation written
#  by Eric Young (eay@cryptsoft.com).
#  The implementation was written so as to conform with Netscapes SSL.
#
#  This library is free for commercial and non-commercial use as long as
#  the following conditions are aheared to.  The following conditions
#  apply to all code found in this distribution, be it the RC4, RSA,
#  lhash, DES, etc., code; not just the SSL code.  The SSL documentation
#  included with this distribution is covered by the same copyright terms
#  except that the holder is Tim Hudson (tjh@cryptsoft.com).
#
#  Copyright remains Eric Young's, and as such any Copyright notices in
#  the code are not to be removed.
#  If this package is used in a product, Eric Young should be given attribution
#  as the author of the parts of the library used.
#  This can be in the form of a textual message at program startup or
#  in documentation (online or textual) provided with the package.
#
#  Redistribution and use in source and binary forms, with or without
#  modification, are permitted provided that the following conditions
#  are met:
#  1. Redistributions of source code must retain the copyright
#     notice, this list of conditions and the following disclaimer.
#  2. Redistributions in binary form must reproduce the above copyright
#     notice, this list of conditions and the following disclaimer in the
#     documentation and/or other materials provided with the distribution.
#  3. All advertising materials mentioning features or use of this software
#     must display the following acknowledgement:
#     "This product includes cryptographic software written by
#      Eric Young (eay@cryptsoft.com)"
#     The word 'cryptographic' can be left out if the rouines from the library
#     being used are not cryptographic related :-).
#  4. If you include any Windows specific code (or a derivative thereof) from
#     the apps directory (application code) you must include an acknowledgement:
#     "This product includes software written by Tim Hudson (tjh@cryptsoft.com)"
#
#  THIS SOFTWARE IS PROVIDED BY ERIC YOUNG ``AS IS'' AND
#  ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
#  IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE
#  ARE DISCLAIMED.  IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS BE LIABLE
#  FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
#  DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS
#  OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION)
#  HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT
#  LIABILITY, OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY
#  OUT OF THE USE OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF
#  SUCH DAMAGE.
#
#  The licence and distribution terms for any publically available version or
#  derivative of this code cannot be changed.  i.e. this code cannot simply be
#  copied and put under another distribution licence
#  [including the GNU Public Licence.]
from openssl import SslPtr
{.passC: "-lcrypto", passL: "-lcrypto".}

const
  HMAC_MAX_MD_CBLOCK* = 128

type
  EVP_MD* = SslPtr

proc EVP_md_null*(): ptr EVP_MD   {.cdecl, importc.}
proc EVP_md2*(): ptr EVP_MD       {.cdecl, importc.}
proc EVP_md4*(): ptr EVP_MD       {.cdecl, importc.}
proc EVP_md5*(): ptr EVP_MD       {.cdecl, importc.}
proc EVP_sha*(): ptr EVP_MD       {.cdecl, importc.}
proc EVP_sha1*(): ptr EVP_MD      {.cdecl, importc.}
proc EVP_dss*(): ptr EVP_MD       {.cdecl, importc.}
proc EVP_dss1*(): ptr EVP_MD      {.cdecl, importc.}
proc EVP_ecdsa*(): ptr EVP_MD     {.cdecl, importc.}
proc EVP_sha224*(): ptr EVP_MD    {.cdecl, importc.}
proc EVP_sha256*(): ptr EVP_MD    {.cdecl, importc.}
proc EVP_sha384*(): ptr EVP_MD    {.cdecl, importc.}
proc EVP_sha512*(): ptr EVP_MD    {.cdecl, importc.}
proc EVP_mdc2*(): ptr EVP_MD      {.cdecl, importc.}
proc EVP_ripemd160*(): ptr EVP_MD {.cdecl, importc.}
proc EVP_whirlpool*(): ptr EVP_MD {.cdecl, importc.}

proc HMAC*(evp_md: ptr EVP_MD; key: pointer; key_len: cint; d: cstring;
           n: csize; md: cstring; md_len: ptr cuint): cstring {.cdecl, importc.}

#proc HMAC_CTX_init*(ctx: var HMAC_CTX) {.cdecl, importc.}
#proc HMAC_Init_ex*(ctx: var HMAC_CTX, key: pointer, key_len: cint, evp_md: ptr EVP_MD, engine: ptr ENGINE): cint {.cdecl, importc.}
#proc HMAC_Update*(ctx: var HMAC_CTX, d: cstring, len: cint): cint {.cdecl, importc.}
#proc HMAC_Final*(ctx: var HMAC_CTX, md: cstring, len: ptr cuint): cint {.cdecl, importc.}

when isMainModule:
    var
        secret = "foo"
        secretPtr = secret[0].addr
        data = "I am awesome"
        #ctx = HMAC_CTX()
        evp: ptr EVP_MD = EVP_sha256()

        output1: array[32, uint8]
        outsize1: cuint

        output2: array[32, uint8]
        outsize2: cuint

    discard HMAC(EVP_sha256(), secretPtr, 8, data.cstring, data.len.cint, cast[ptr char](addr output1), addr outsize1)

    #let foo = ENGINE()
    #HMAC_ctx_init(ctx)
    #discard HMAC_Init_ex(ctx, secretPtr, 8, evp)
    #discard HMAC_Update(ctx, data.cstring, data.len.cint)
    #discard HMAC_Final(ctx, cast[ptr char](addr output2), addr outsize2)

    #assert output1 == output2
    #assert outsize1 == outsize2
