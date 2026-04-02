/// `SET OF` where elements are not guaranteed to be in DER order. Some `KeyMint` builds
/// encode digest algorithm integers (e.g. `4` then `0`) in an order `asn1::SetOf` rejects.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct UnorderedSetOfU64(pub Vec<u64>);

impl<'a> asn1::Asn1Readable<'a> for UnorderedSetOfU64 {
    fn parse(parser: &mut asn1::Parser<'a>) -> asn1::ParseResult<Self> {
        let tlv = parser.read_element::<asn1::Tlv<'a>>()?;
        let set_of_tag = <asn1::SetOf<'_, u64> as asn1::SimpleAsn1Readable<'_>>::TAG;
        if tlv.tag() != set_of_tag {
            return Err(asn1::ParseError::new(asn1::ParseErrorKind::UnexpectedTag {
                actual: tlv.tag(),
            }));
        }
        asn1::parse(tlv.data(), |p| {
            let mut v = Vec::new();
            while !p.is_empty() {
                v.push(p.read_element::<u64>()?);
            }
            Ok(Self(v))
        })
    }

    fn can_parse(tag: asn1::Tag) -> bool {
        tag == <asn1::SetOf<'_, u64> as asn1::SimpleAsn1Readable<'_>>::TAG
    }
}
