use serde::Serializer;

pub fn serialize<S>(bytes: &[u8], serializer: S) -> Result<S::Ok, S::Error>
where
    S: Serializer,
{
    serializer.serialize_str(&hex::encode(bytes))
}

pub mod option {
    use serde::Serializer;

    pub fn serialize<S>(bytes: &Option<Vec<u8>>, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        match bytes {
            Some(bytes) => super::serialize(bytes.as_slice(), serializer),
            None => serializer.serialize_none(),
        }
    }
}

pub mod vec {
    use serde::ser::SerializeSeq;
    use serde::Serializer;

    pub fn serialize<S>(digests: &[Vec<u8>], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let mut seq = serializer.serialize_seq(Some(digests.len()))?;
        for digest in digests {
            seq.serialize_element(&hex::encode(digest))?;
        }
        seq.end()
    }
}
