use std::borrow::Cow;

use crate::lookup_value;
use serde::{Deserialize, Serialize};

/// Recovery Entry
/// <https://github.com/ehn-dcc-development/ehn-dcc-schema/blob/release/1.3.0/DCC.Types.schema.json>

#[derive(Serialize, Deserialize, Debug, Clone, PartialEq)]
pub struct Recovery {
    /// Disease agent targeted
    /// `https://id.uvci.eu/DCC.ValueSets.schema.json#/$defs/disease-agent-targeted`
    pub tg: Cow<'static, str>,
    /// ISO 8601 complete date of first positive NAA test result
    pub fr: Cow<'static, str>,
    /// Country of Test
    /// `https://id.uvci.eu/DCC.ValueSets.schema.json#/$defs/country_vt`
    pub co: Cow<'static, str>,
    /// Certificate Issuer
    /// `https://id.uvci.eu/DCC.Core.Types.schema.json#/$defs/issuer`
    pub is: String,
    /// ISO 8601 complete date: Certificate Valid From
    pub df: String,
    /// ISO 8601 complete date: Certificate Valid Until
    pub du: String,
    /// Unique Certificate Identifier, UVCI
    /// `https://id.uvci.eu/DCC.Core.Types.schema.json#/$defs/certificate_id`
    pub ci: String,
}

impl Recovery {
    pub fn expand_values(&mut self) {
        self.tg = lookup_value(&self.tg);
        self.fr = lookup_value(&self.fr);
        self.co = lookup_value(&self.co);
    }
}
