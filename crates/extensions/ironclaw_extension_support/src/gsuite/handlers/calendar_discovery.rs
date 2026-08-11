use async_trait::async_trait;
use ironclaw_host_api::http::RuntimeHttpEgressResponse;
use serde_json::{Value, json};

use super::{
    CALENDAR_API_BASE, GsuiteDispatchError, add_network_usage, encode_percent,
    is_google_auth_expired_response, response_body_json,
};

pub(super) const MAX_CALENDARS: usize = 50;

pub(super) enum CalendarIdResolution {
    Ready {
        calendar_ids: Vec<String>,
        calendars: Vec<Value>,
        truncated: bool,
    },
    AuthExpired,
    DiscoveryFailed {
        response: RuntimeHttpEgressResponse,
    },
}

#[async_trait]
pub(super) trait CalendarDiscoveryRun {
    async fn get_calendar_discovery(
        &mut self,
        url: String,
    ) -> Result<RuntimeHttpEgressResponse, GsuiteDispatchError>;

    fn network_egress_bytes(&self) -> u64;
}

pub(super) async fn resolve_calendar_ids<R: CalendarDiscoveryRun>(
    run: &mut R,
    include_all_calendars: bool,
    selected_calendar_ids: Vec<String>,
) -> Result<CalendarIdResolution, GsuiteDispatchError> {
    if !include_all_calendars {
        return Ok(CalendarIdResolution::Ready {
            calendar_ids: selected_calendar_ids,
            calendars: Vec::new(),
            truncated: false,
        });
    }

    let mut calendars = Vec::new();
    let mut calendar_ids = Vec::new();
    let mut truncated = false;
    let mut page_token = None;
    loop {
        let response = run
            .get_calendar_discovery(list_calendars_page_url(page_token.as_deref()))
            .await?;
        if is_google_auth_expired_response(&response) {
            return Ok(CalendarIdResolution::AuthExpired);
        }
        if response.status != 200 {
            return Ok(CalendarIdResolution::DiscoveryFailed { response });
        }
        let body = response_body_json(&response)
            .map_err(|error| add_network_usage(error, run.network_egress_bytes()))?;
        if let Some(items) = body.get("items").and_then(Value::as_array) {
            for calendar in items {
                if calendar_ids.len() >= MAX_CALENDARS {
                    truncated = true;
                    break;
                }
                let Some(id) = calendar.get("id").and_then(Value::as_str) else {
                    continue;
                };
                calendar_ids.push(id.to_string());
                calendars.push(json!({
                    "id": id,
                    "summary": calendar.get("summary").and_then(Value::as_str).unwrap_or(""),
                    "primary": calendar.get("primary").and_then(Value::as_bool).unwrap_or(false),
                }));
            }
        }
        page_token = body
            .get("nextPageToken")
            .and_then(Value::as_str)
            .map(ToString::to_string);
        if page_token.is_none() || calendar_ids.len() >= MAX_CALENDARS {
            truncated |= page_token.is_some();
            break;
        }
    }

    Ok(CalendarIdResolution::Ready {
        calendar_ids,
        calendars,
        truncated,
    })
}

fn list_calendars_page_url(page_token: Option<&str>) -> String {
    let mut url = format!("{CALENDAR_API_BASE}/users/me/calendarList?maxResults=250");
    if let Some(page_token) = page_token {
        url.push_str("&pageToken=");
        url.push_str(&encode_percent(page_token));
    }
    url
}
