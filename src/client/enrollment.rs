//! Enrollment credentials shared by CLI and desktop clients.
use crate::error::{Result, TransportError};

#[derive(Debug, PartialEq, Eq)]
pub enum EnrollmentToken<'a> {
  Invite(&'a str),
  Pair(&'a str),
  OAuth { provider: &'a str, credential: &'a str },
  Public,
}

impl<'a> EnrollmentToken<'a> {
  pub fn parse(token: &'a str) -> Result<Self> {
    let invalid = || TransportError::Certificate("Invalid prefixed enrollment token".into());
    let (scheme, value) = token.split_once(':').ok_or_else(invalid)?;
    let valid = |value: &str| !value.is_empty() && value.trim() == value;
    match scheme {
      "invite" if valid(value) => Ok(Self::Invite(value)),
      "pair" if valid(value) => Ok(Self::Pair(value)),
      "oauth" => {
        let (provider, credential) = value.split_once(':').ok_or_else(invalid)?;
        if !valid(provider) || !valid(credential) { return Err(invalid()); }
        Ok(Self::OAuth { provider, credential })
      }
      "public" if value.is_empty() => Ok(Self::Public),
      _ => Err(invalid()),
    }
  }
}

#[cfg(test)]
mod tests {
  use super::*;

  #[test]
  fn enrollment_prefixes_preserve_opaque_credentials_and_reject_ambiguous_inputs() {
    assert_eq!(EnrollmentToken::parse("invite:opaque:credential").unwrap(), EnrollmentToken::Invite("opaque:credential"));
    assert_eq!(EnrollmentToken::parse("pair:one-time").unwrap(), EnrollmentToken::Pair("one-time"));
    assert_eq!(EnrollmentToken::parse("oauth:github:opaque:credential").unwrap(), EnrollmentToken::OAuth { provider: "github", credential: "opaque:credential" });
    assert_eq!(EnrollmentToken::parse("public:").unwrap(), EnrollmentToken::Public);
    for token in ["", "raw", "invite:", "pair:", "oauth:github", "oauth::secret", "oauth:github:", "other:secret", "public:secret", " invite:secret", "invite: secret"] {
      assert!(EnrollmentToken::parse(token).is_err(), "accepted {token:?}");
    }
  }
}
