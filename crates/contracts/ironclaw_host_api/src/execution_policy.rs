//! Persistable, provider-neutral execution restrictions for one turn.

use serde::{Deserialize, Deserializer, Serialize};

use crate::{error::HostApiError, ids::CapabilityId};

const MAX_REQUIRED_SKILL_NAME_BYTES: usize = 64;

/// Exact skill name that must be activated before execution begins.
///
/// Skill source scopes are intentionally not persisted here: the activation
/// catalog already owns visibility and rejects ambiguous names. Persisting a
/// second source taxonomy would let this neutral contract drift from that
/// catalog.
#[derive(Debug, Clone, PartialEq, Eq, Hash, PartialOrd, Ord, Serialize)]
#[serde(transparent)]
pub struct RequiredSkill(String);

impl RequiredSkill {
    pub fn new(value: impl Into<String>) -> Result<Self, HostApiError> {
        let value = value.into();
        if value.trim() != value || value.is_empty() {
            return Err(HostApiError::invalid_id(
                "required_skill",
                value,
                "must be non-empty and have no surrounding whitespace",
            ));
        }
        if value.len() > MAX_REQUIRED_SKILL_NAME_BYTES {
            return Err(HostApiError::invalid_id(
                "required_skill",
                value,
                "must be at most 64 bytes",
            ));
        }
        let mut characters = value.chars();
        let Some(first) = characters.next() else {
            return Err(HostApiError::invalid_id(
                "required_skill",
                value,
                "must be non-empty",
            ));
        };
        if !first.is_ascii_alphanumeric()
            || !characters.all(|character| {
                character.is_ascii_alphanumeric() || matches!(character, '.' | '_' | '-')
            })
        {
            return Err(HostApiError::invalid_id(
                "required_skill",
                value,
                "must match the skill-name grammar: an ASCII alphanumeric followed by ASCII alphanumerics, dots, underscores, or hyphens",
            ));
        }
        Ok(Self(value))
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }
}

impl<'de> Deserialize<'de> for RequiredSkill {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: Deserializer<'de>,
    {
        Self::new(String::deserialize(deserializer)?).map_err(serde::de::Error::custom)
    }
}

/// Restrictions attached to a turn by a trusted host-owned caller.
#[derive(Debug, Clone, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct TurnExecutionPolicy {
    /// `None` preserves the caller's normal surface; `Some([])` exposes no
    /// capabilities; a non-empty value only narrows the existing surface.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub allowed_capability_ids: Option<Vec<CapabilityId>>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub required_skills: Vec<RequiredSkill>,
}

#[cfg(test)]
mod tests {
    use super::RequiredSkill;

    #[test]
    fn required_skill_uses_the_catalog_name_grammar() {
        assert!(RequiredSkill::new("code-review.v2").is_ok());
        assert!(RequiredSkill::new("-code-review").is_err());
        assert!(RequiredSkill::new("code/review").is_err());
        assert!(RequiredSkill::new("éxample").is_err());
        assert!(RequiredSkill::new("a".repeat(65)).is_err());
    }
}
