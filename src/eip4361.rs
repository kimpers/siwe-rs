use chrono::{DateTime, Utc};
use core::{
    convert::Infallible,
    fmt::{self, Display, Formatter},
    str::FromStr,
};
use ethers_core::{types::H160, utils::to_checksum};
use http::uri::{Authority, InvalidUri};
use iri_string::types::UriString;
use serde::{Deserialize, Serialize};
use thiserror::Error;

type TimeStamp = DateTime<Utc>;

#[derive(Copy, Clone, Debug)]
pub enum Version {
    V1 = 1,
}

impl FromStr for Version {
    type Err = ParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        if s == "1" {
            Ok(Self::V1)
        } else {
            Err(ParseError::Format("Bad Version"))
        }
    }
}

impl fmt::Display for Version {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{:?}", self)
    }
}

mod version_serde {
    use super::Version;
    use serde::{de::Error, Deserialize, Deserializer, Serializer};
    use std::str::FromStr;

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Version, D::Error>
    where
        D: Deserializer<'de>,
    {
        let string = String::deserialize(deserializer)?;
        let version = Version::from_str(&string).map_err(Error::custom)?;
        Ok(version)
    }

    pub fn serialize<S>(version: &Version, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let version_str = version.to_string();
        let stripped_cersion = version_str.strip_prefix('V').unwrap_or(&version_str);
        serializer.serialize_str(stripped_cersion)
    }
}

mod authority_serde {
    use http::uri::Authority;
    use serde::{de::Error, Deserialize, Deserializer, Serializer};
    use std::str::FromStr;

    pub fn deserialize<'de, D>(deserializer: D) -> Result<Authority, D::Error>
    where
        D: Deserializer<'de>,
    {
        let string = String::deserialize(deserializer)?;
        let authority = http::uri::Authority::from_str(&string).map_err(Error::custom)?;
        Ok(authority)
    }

    pub fn serialize<S>(authority: &http::uri::Authority, serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        serializer.serialize_str(&authority.to_string())
    }
}

mod hex_serde {
    use hex::FromHex;
    use serde::{de::Error, Deserialize, Deserializer, Serializer};

    pub fn deserialize<'de, D>(deserializer: D) -> Result<[u8; 20], D::Error>
    where
        D: Deserializer<'de>,
    {
        let hex_str: &str = Deserialize::deserialize(deserializer)?;
        let stripped = hex_str.strip_prefix("0x").unwrap_or(hex_str);
        let buffer = <[u8; 20]>::from_hex(stripped).map_err(Error::custom)?;
        Ok(buffer)
    }

    pub fn serialize<S>(hex_buffer: &[u8; 20], serializer: S) -> Result<S::Ok, S::Error>
    where
        S: Serializer,
    {
        let hex_str = hex::encode(&hex_buffer);
        let prefixed_hex = format!("0x{}", hex_str);
        serializer.serialize_str(&prefixed_hex)
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Message {
    #[serde(with = "authority_serde")]
    pub domain: Authority,
    #[serde(with = "hex_serde")]
    pub address: [u8; 20],
    pub statement: String,
    pub uri: UriString,
    #[serde(with = "version_serde")]
    pub version: Version,
    pub chain_id: String,
    pub nonce: String,
    pub issued_at: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub expiration_time: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub not_before: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub request_id: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub resources: Vec<UriString>,
}

impl Display for Message {
    fn fmt(&self, f: &mut Formatter<'_>) -> Result<(), fmt::Error> {
        writeln!(f, "{}{}", &self.domain, PREAMBLE)?;
        writeln!(f, "{}", to_checksum(&H160(self.address), None))?;
        writeln!(f, "\n{}\n", &self.statement)?;
        writeln!(f, "{}{}", URI_TAG, &self.uri)?;
        writeln!(f, "{}{}", VERSION_TAG, self.version as u64)?;
        writeln!(f, "{}{}", CHAIN_TAG, &self.chain_id)?;
        writeln!(f, "{}{}", NONCE_TAG, &self.nonce)?;
        write!(f, "{}{}", IAT_TAG, &self.issued_at)?;
        if let Some(exp) = &self.expiration_time {
            write!(f, "\n{}{}", EXP_TAG, &exp)?
        };
        if let Some(nbf) = &self.not_before {
            write!(f, "\n{}{}", NBF_TAG, &nbf)?
        };
        if let Some(rid) = &self.request_id {
            write!(f, "\n{}{}", RID_TAG, rid)?
        };
        if !self.resources.is_empty() {
            write!(f, "\n{}", RES_TAG)?;
            for res in &self.resources {
                write!(f, "\n- {}", res)?;
            }
        };
        Ok(())
    }
}

#[derive(Error, Debug)]
pub enum ParseError {
    #[error("Invalid Domain: {0}")]
    Domain(#[from] InvalidUri),
    #[error("Formatting Error: {0}")]
    Format(&'static str),
    #[error("Invalid Address: {0}")]
    Address(#[from] hex::FromHexError),
    #[error("Invalid Statement: {0}")]
    Statement(&'static str),
    #[error("Invalid URI: {0}")]
    Uri(#[from] iri_string::validate::Error),
    #[error("Invalid Timestamp: {0}")]
    TimeStamp(#[from] chrono::format::ParseError),
    #[error("Invalid Nonce: {0}")]
    Nonce(&'static str),
    #[error(transparent)]
    ParseIntError(#[from] std::num::ParseIntError),
    #[error(transparent)]
    Never(#[from] Infallible),
}

fn tagged<'a>(tag: &'static str, line: Option<&'a str>) -> Result<&'a str, ParseError> {
    line.and_then(|l| l.strip_prefix(tag))
        .ok_or(ParseError::Format(tag))
}

fn parse_line<S: FromStr<Err = E>, E: Into<ParseError>>(
    tag: &'static str,
    line: Option<&str>,
) -> Result<S, ParseError> {
    tagged(tag, line).and_then(|s| S::from_str(s).map_err(|e| e.into()))
}

fn tag_optional<'a>(
    tag: &'static str,
    line: Option<&'a str>,
) -> Result<Option<&'a str>, ParseError> {
    match tagged(tag, line).map(Some) {
        Err(ParseError::Format(t)) if t == tag => Ok(None),
        r => r,
    }
}

impl FromStr for Message {
    type Err = ParseError;
    fn from_str(s: &str) -> Result<Self, Self::Err> {
        use hex::FromHex;
        let mut lines = s.split('\n');
        let domain = lines
            .next()
            .and_then(|preamble| preamble.strip_suffix(PREAMBLE))
            .map(Authority::from_str)
            .ok_or(ParseError::Format("Missing Preamble Line"))??;
        let address = tagged(ADDR_TAG, lines.next())
            .and_then(|a| <[u8; 20]>::from_hex(a).map_err(|e| e.into()))?;
        let statement = match (lines.next(), lines.next(), lines.next()) {
            (Some(""), Some(s), Some("")) => s.to_string(),
            _ => return Err(ParseError::Statement("Missing Statement")),
        };
        let uri = parse_line(URI_TAG, lines.next())?;
        let version = parse_line(VERSION_TAG, lines.next())?;
        let chain_id = parse_line(CHAIN_TAG, lines.next())?;
        let nonce = parse_line(NONCE_TAG, lines.next())?;
        let issued_at = tagged(IAT_TAG, lines.next()).and_then(|iat| {
            TimeStamp::from_str(iat)?;
            Ok(iat.into())
        })?;

        let mut line = lines.next();
        let expiration_time = match tag_optional(EXP_TAG, line)? {
            Some(exp) => {
                TimeStamp::from_str(exp)?;
                line = lines.next();
                Some(exp.into())
            }
            None => None,
        };
        let not_before = match tag_optional(NBF_TAG, line)? {
            Some(nbf) => {
                TimeStamp::from_str(nbf)?;
                line = lines.next();
                Some(nbf.into())
            }
            None => None,
        };

        let request_id = match tag_optional(RID_TAG, line)? {
            Some(rid) => {
                line = lines.next();
                Some(rid.into())
            }
            None => None,
        };

        let resources = match line {
            Some(RES_TAG) => lines.map(|s| parse_line("- ", Some(s))).collect(),
            Some(_) => Err(ParseError::Format("Unexpected Content")),
            None => Ok(vec![]),
        }?;

        Ok(Message {
            domain,
            address,
            statement,
            uri,
            version,
            chain_id,
            nonce,
            issued_at,
            expiration_time,
            not_before,
            request_id,
            resources,
        })
    }
}

#[derive(Error, Debug)]
pub enum VerificationError {
    #[error(transparent)]
    Crypto(#[from] k256::ecdsa::Error),
    #[error(transparent)]
    Serialization(#[from] fmt::Error),
    #[error("Recovered key does not match address")]
    Signer,
    #[error("Message is not currently valid")]
    Time,
}

impl Message {
    pub fn verify_eip191(&self, sig: &[u8; 65]) -> Result<Vec<u8>, VerificationError> {
        use k256::{
            ecdsa::{
                recoverable::{Id, Signature},
                signature::Signature as S,
                Signature as Sig,
            },
            elliptic_curve::sec1::ToEncodedPoint,
        };
        use sha3::{Digest, Keccak256};
        let pk = Signature::new(&Sig::from_bytes(&sig[..64])?, Id::new(&sig[64] % 27)?)?
            .recover_verify_key(&self.eip191_string()?)?;

        if Keccak256::default()
            .chain(&pk.to_encoded_point(false).as_bytes()[1..])
            .finalize()[12..]
            != self.address
        {
            Err(VerificationError::Signer)
        } else {
            Ok(pk.to_bytes().into_iter().collect())
        }
    }

    pub fn verify(&self, sig: [u8; 65]) -> Result<Vec<u8>, VerificationError> {
        if !self.valid_now() {
            Err(VerificationError::Time)
        } else {
            self.verify_eip191(&sig)
        }
    }

    pub fn valid_now(&self) -> bool {
        self.valid_at(&Utc::now())
    }

    pub fn valid_at(&self, t: &TimeStamp) -> bool {
        self.not_before
            .as_ref()
            .and_then(|s| TimeStamp::from_str(s).ok())
            .as_ref()
            .map(|nbf| t >= nbf)
            .unwrap_or(true)
            && self
                .expiration_time
                .as_ref()
                .and_then(|s| TimeStamp::from_str(s).ok())
                .as_ref()
                .map(|exp| t < exp)
                .unwrap_or(true)
    }

    pub fn eip191_string(&self) -> Result<Vec<u8>, fmt::Error> {
        let s = self.to_string();
        Ok(format!("\x19Ethereum Signed Message:\n{}{}", s.as_bytes().len(), s).into())
    }

    pub fn eip191_hash(&self) -> Result<[u8; 32], fmt::Error> {
        use sha3::{Digest, Keccak256};
        Ok(Keccak256::default()
            .chain(&self.eip191_string()?)
            .finalize()
            .into())
    }
}

const PREAMBLE: &str = " wants you to sign in with your Ethereum account:";
const ADDR_TAG: &str = "0x";
const URI_TAG: &str = "URI: ";
const VERSION_TAG: &str = "Version: ";
const CHAIN_TAG: &str = "Chain ID: ";
const NONCE_TAG: &str = "Nonce: ";
const IAT_TAG: &str = "Issued At: ";
const EXP_TAG: &str = "Expiration Time: ";
const NBF_TAG: &str = "Not Before: ";
const RID_TAG: &str = "Request ID: ";
const RES_TAG: &str = "Resources:";

#[cfg(test)]
mod tests {
    use super::*;
    use assert_json_diff::assert_json_eq;
    use hex::FromHex;

    #[test]
    fn parsing() {
        // correct order
        let message = r#"service.org wants you to sign in with your Ethereum account:
0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2

I accept the ServiceOrg Terms of Service: https://service.org/tos

URI: https://service.org/login
Version: 1
Chain ID: 1
Nonce: 32891756
Issued At: 2021-09-30T16:25:24Z
Resources:
- ipfs://bafybeiemxf5abjwjbikoz4mc3a3dla6ual3jsgpdr4cjr3oz3evfyavhwq/
- https://example.com/my-web2-claim.json"#;

        assert!(Message::from_str(message).is_ok());

        assert_eq!(message, &Message::from_str(message).unwrap().to_string());

        // incorrect order
        assert!(Message::from_str(
            r#"service.org wants you to sign in with your Ethereum account:
0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2

I accept the ServiceOrg Terms of Service: https://service.org/tos

URI: https://service.org/login
Version: 1
Nonce: 32891756
Chain ID: 1
Issued At: 2021-09-30T16:25:24Z
Resources:
- ipfs://bafybeiemxf5abjwjbikoz4mc3a3dla6ual3jsgpdr4cjr3oz3evfyavhwq/
- https://example.com/my-web2-claim.json"#,
        )
        .is_err())
    }

    #[test]
    fn siwe_compatible_json_deserialization() {
        let json = r#"
        {
            "domain": "localhost:3000",
            "address": "0xc766f6de2ff4edf69268f6ef2a7f81934dbb7f62",
            "chainId": "1",
            "issuedAt": "2021-12-28T21:43:31.297Z",
            "uri": "http://localhost:3000",
            "version": "1",
            "statement": "Tx submission service",
            "type": "Personal signature",
            "nonce": "375222496829012"
        }
        "#;

        let raw = "localhost:3000 wants you to sign in with your Ethereum account:\n0xC766F6De2fF4eDf69268f6ef2A7f81934dbB7f62\n\nTx submission service\n\nURI: http://localhost:3000\nVersion: 1\nChain ID: 1\nNonce: 375222496829012\nIssued At: 2021-12-28T21:43:31.297Z";

        let message = serde_json::from_str::<Message>(json).unwrap();
        assert_eq!(message.to_string(), raw);
    }

    #[test]
    fn siwe_compatible_json_serialization() {
        let json = r#"
        {
            "domain": "localhost:3000",
            "address": "0xc766f6de2ff4edf69268f6ef2a7f81934dbb7f62",
            "chainId": "1",
            "issuedAt": "2021-12-28T21:43:31.297Z",
            "uri": "http://localhost:3000",
            "version": "1",
            "statement": "Tx submission service",
            "nonce": "375222496829012"
        }
        "#;

        let raw = "localhost:3000 wants you to sign in with your Ethereum account:\n0xC766F6De2fF4eDf69268f6ef2A7f81934dbB7f62\n\nTx submission service\n\nURI: http://localhost:3000\nVersion: 1\nChain ID: 1\nNonce: 375222496829012\nIssued At: 2021-12-28T21:43:31.297Z";

        let message = Message::from_str(raw).unwrap();

        let reserialized =
            serde_json::from_str::<serde_json::Value>(&serde_json::to_string(&message).unwrap())
                .unwrap();

        assert_json_eq!(
            reserialized,
            serde_json::from_str::<serde_json::Value>(json).unwrap()
        );
    }
    #[test]
    fn serialize_deserialize_gives_same_string() {
        // correct order
        let message_str = r#"service.org wants you to sign in with your Ethereum account:
0xC02aaA39b223FE8D0A0e5C4F27eAD9083C756Cc2

I accept the ServiceOrg Terms of Service: https://service.org/tos

URI: https://service.org/login
Version: 1
Chain ID: 1
Nonce: 32891756
Issued At: 2021-09-30T16:25:24Z
Resources:
- ipfs://bafybeiemxf5abjwjbikoz4mc3a3dla6ual3jsgpdr4cjr3oz3evfyavhwq/
- https://example.com/my-web2-claim.json"#;

        let message = Message::from_str(message_str).unwrap();
        let message_json = serde_json::to_string(&message).unwrap();
        assert_eq!(
            serde_json::from_str::<Message>(&message_json)
                .unwrap()
                .to_string(),
            message_str
        );
    }

    #[test]
    fn validation() {
        let message = Message::from_str(
            r#"localhost:4361 wants you to sign in with your Ethereum account:
0x6Da01670d8fc844e736095918bbE11fE8D564163

SIWE Notepad Example

URI: http://localhost:4361
Version: 1
Chain ID: 1
Nonce: kEWepMt9knR6lWJ6A
Issued At: 2021-12-07T18:28:18.807Z"#,
        )
        .unwrap();
        let correct = <[u8; 65]>::from_hex(r#"6228b3ecd7bf2df018183aeab6b6f1db1e9f4e3cbe24560404112e25363540eb679934908143224d746bbb5e1aa65ab435684081f4dbb74a0fec57f98f40f5051c"#).unwrap();
        assert!(message.verify_eip191(&correct).is_ok());
        let incorrect = <[u8; 65]>::from_hex(r#"7228b3ecd7bf2df018183aeab6b6f1db1e9f4e3cbe24560404112e25363540eb679934908143224d746bbb5e1aa65ab435684081f4dbb74a0fec57f98f40f5051c"#).unwrap();
        assert!(message.verify_eip191(&incorrect).is_err());
    }

    #[test]
    fn validation1() {
        let message = Message::from_str(r#"localhost wants you to sign in with your Ethereum account:
0x4b60ffAf6fD681AbcC270Faf4472011A4A14724C

Allow localhost to access your orbit using their temporary session key: did:key:z6Mktud6LcDFb3heS7FFWoJhiCafmUPkCAgpvJLv5E6fgBJg#z6Mktud6LcDFb3heS7FFWoJhiCafmUPkCAgpvJLv5E6fgBJg

URI: did:key:z6Mktud6LcDFb3heS7FFWoJhiCafmUPkCAgpvJLv5E6fgBJg#z6Mktud6LcDFb3heS7FFWoJhiCafmUPkCAgpvJLv5E6fgBJg
Version: 1
Chain ID: 1
Nonce: PPrtjztx2lYqWbqNs
Issued At: 2021-12-20T12:29:25.907Z
Expiration Time: 2021-12-20T12:44:25.906Z
Resources:
- kepler://bafk2bzacecn2cdbtzho72x4c62fcxvcqj23padh47s5jyyrv42mtca3yrhlpa#put
- kepler://bafk2bzacecn2cdbtzho72x4c62fcxvcqj23padh47s5jyyrv42mtca3yrhlpa#del
- kepler://bafk2bzacecn2cdbtzho72x4c62fcxvcqj23padh47s5jyyrv42mtca3yrhlpa#get
- kepler://bafk2bzacecn2cdbtzho72x4c62fcxvcqj23padh47s5jyyrv42mtca3yrhlpa#list"#).unwrap();
        let correct = <[u8; 65]>::from_hex(r#"20c0da863b3dbfbb2acc0fb3b9ec6daefa38f3f20c997c283c4818ebeca96878787f84fccc25c4087ccb31ebd782ae1d2f74be076a49c0a8604419e41507e9381c"#).unwrap();
        assert!(message.verify_eip191(&correct).is_ok());
        let incorrect = <[u8; 65]>::from_hex(r#"30c0da863b3dbfbb2acc0fb3b9ec6daefa38f3f20c997c283c4818ebeca96878787f84fccc25c4087ccb31ebd782ae1d2f74be076a49c0a8604419e41507e9381c"#).unwrap();
        assert!(message.verify_eip191(&incorrect).is_err());
    }
}
