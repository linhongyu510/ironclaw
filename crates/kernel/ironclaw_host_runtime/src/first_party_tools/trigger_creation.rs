use ironclaw_triggers::TriggerExecutionSpec;
use serde::Deserialize;

use super::trigger_management::TriggerScheduleInput;

pub(super) struct TriggerCreateInput {
    pub(super) name: String,
    pub(super) schedule: TriggerScheduleInput,
    pub(super) definition: TriggerDefinitionInput,
}

#[derive(Deserialize)]
#[serde(deny_unknown_fields)]
struct TriggerCreateInputWire {
    name: String,
    schedule: TriggerScheduleInput,
    prompt: Option<String>,
    execution_contract: Option<TriggerExecutionSpec>,
}

impl<'de> Deserialize<'de> for TriggerCreateInput {
    fn deserialize<D>(deserializer: D) -> Result<Self, D::Error>
    where
        D: serde::Deserializer<'de>,
    {
        let wire = TriggerCreateInputWire::deserialize(deserializer)?;
        let definition = match (wire.prompt, wire.execution_contract) {
            (Some(prompt), None) => TriggerDefinitionInput::Legacy { prompt },
            (None, Some(execution_contract)) => {
                TriggerDefinitionInput::Structured { execution_contract }
            }
            (Some(_), Some(_)) => {
                return Err(serde::de::Error::custom(
                    "provide either prompt or execution_contract, not both",
                ));
            }
            (None, None) => {
                return Err(serde::de::Error::custom(
                    "provide either prompt or execution_contract",
                ));
            }
        };
        Ok(Self {
            name: wire.name,
            schedule: wire.schedule,
            definition,
        })
    }
}

pub(super) enum TriggerDefinitionInput {
    Legacy {
        prompt: String,
    },
    Structured {
        execution_contract: TriggerExecutionSpec,
    },
}
