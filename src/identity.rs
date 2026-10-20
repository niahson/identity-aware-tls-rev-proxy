use std::{
    net::SocketAddr,
    time::{SystemTime, UNIX_EPOCH},
};

use anyhow::{Context, Result, bail};
use rustls::pki_types::CertificateDer;
use serde::Serialize;
use x509_parser::{
    extensions::{GeneralName, ParsedExtension},
    parse_x509_certificate,
};

use crate::policy::canonical_spiffe_id;

#[derive(Clone, Debug)]
pub struct ConnectionIdentity {
    pub client: ClientIdentity,
    pub remote_addr: SocketAddr,
}

#[derive(Clone, Debug, Serialize)]
pub struct ClientIdentity {
    pub spiffe_id: String,
    pub subject: String,
    pub issuer: String,
    pub uri_sans: Vec<String>,
    pub dns_sans: Vec<String>,
    pub serial_number: String,
    pub not_before_unix: i64,
    pub not_after_unix: i64,
    pub presented_chain: Vec<CertificateSummary>,
    pub trust_validated_by_tls: bool,
}

#[derive(Clone, Debug, Serialize)]
pub struct CertificateSummary {
    pub subject: String,
    pub issuer: String,
    pub serial_number: String,
}

impl ClientIdentity {
    /// Parses the certificate metadata after Rustls has successfully validated the
    /// presented chain against the active client trust store.
    pub fn from_validated_chain(chain: &[CertificateDer<'_>], now: SystemTime) -> Result<Self> {
        let leaf_der = chain
            .first()
            .context("client did not present a certificate")?;
        let (_, leaf) = parse_x509_certificate(leaf_der.as_ref())
            .map_err(|error| anyhow::anyhow!("malformed client leaf certificate: {error}"))?;

        let mut uri_sans = Vec::new();
        let mut dns_sans = Vec::new();
        for extension in leaf.extensions() {
            if let ParsedExtension::SubjectAlternativeName(names) = extension.parsed_extension() {
                for name in &names.general_names {
                    match name {
                        GeneralName::URI(uri) => uri_sans.push((*uri).to_owned()),
                        GeneralName::DNSName(name) => dns_sans.push((*name).to_owned()),
                        _ => {}
                    }
                }
            }
        }

        let spiffe_ids = uri_sans
            .iter()
            .filter(|uri| uri.starts_with("spiffe://"))
            .map(|uri| canonical_spiffe_id(uri))
            .collect::<Result<Vec<_>>>()?;
        if spiffe_ids.len() != 1 {
            bail!("client certificate must contain exactly one canonical SPIFFE URI SAN");
        }

        let now: i64 = now
            .duration_since(UNIX_EPOCH)
            .context("system clock is before the Unix epoch")?
            .as_secs()
            .try_into()
            .context("system clock is outside the supported range")?;
        let not_before_unix = leaf.validity().not_before.timestamp();
        let not_after_unix = leaf.validity().not_after.timestamp();
        if now < not_before_unix {
            bail!("client certificate is not yet valid");
        }
        if now > not_after_unix {
            bail!("client certificate has expired");
        }

        let presented_chain = chain
            .iter()
            .map(|certificate| {
                let (_, parsed) =
                    parse_x509_certificate(certificate.as_ref()).map_err(|error| {
                        anyhow::anyhow!("malformed certificate in presented chain: {error}")
                    })?;
                Ok(CertificateSummary {
                    subject: parsed.subject().to_string(),
                    issuer: parsed.issuer().to_string(),
                    serial_number: parsed.raw_serial_as_string(),
                })
            })
            .collect::<Result<Vec<_>>>()?;

        Ok(Self {
            spiffe_id: spiffe_ids.into_iter().next().expect("length checked"),
            subject: leaf.subject().to_string(),
            issuer: leaf.issuer().to_string(),
            uri_sans,
            dns_sans,
            serial_number: leaf.raw_serial_as_string(),
            not_before_unix,
            not_after_unix,
            presented_chain,
            trust_validated_by_tls: true,
        })
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_a_missing_certificate() {
        let error = ClientIdentity::from_validated_chain(&[], SystemTime::now()).unwrap_err();
        assert!(error.to_string().contains("did not present a certificate"));
    }

    #[test]
    fn rejects_malformed_leaf_der() {
        let malformed = CertificateDer::from(vec![0x30, 0x03, 0x01, 0x01, 0xff]);
        let error =
            ClientIdentity::from_validated_chain(&[malformed], SystemTime::now()).unwrap_err();
        assert!(
            error
                .to_string()
                .contains("malformed client leaf certificate")
        );
    }
}
