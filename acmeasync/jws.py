import josepy as jose


class Header(jose.Header):  # type: ignore
    nonce = jose.Field("nonce", omitempty=True)
    kid = jose.Field("kid", omitempty=True)
    url = jose.Field("url", omitempty=True)


class Signature(jose.Signature):  # type: ignore
    __slots__ = jose.Signature._orig_slots  # pylint: disable=no-member
    header_cls = Header
    header = jose.Field(
        "header", omitempty=True, default=header_cls(), decoder=header_cls.from_json
    )


class JWS(jose.JWS):  # type: ignore
    signature_cls = Signature
    __slots__ = jose.JWS._orig_slots

    @classmethod
    # pylint: disable=arguments-differ
    def sign(cls, payload, key, alg, nonce, url=None, kid=None):
        # Per ACME spec, jwk and kid are mutually exclusive, so only include a
        # jwk field if kid is not provided.
        include_jwk = kid is None
        return super(JWS, cls).sign(
            payload,
            key=key,
            alg=alg,
            protect=frozenset(["nonce", "url", "kid", "jwk", "alg"]),
            nonce=nonce,
            url=url,
            kid=kid,
            include_jwk=include_jwk,
        )
