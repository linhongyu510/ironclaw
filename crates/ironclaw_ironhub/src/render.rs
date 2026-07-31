use super::model::{IronHubPhase, IronHubResponse};

pub fn render_reborn_ironhub_response(label: &str, response: &IronHubResponse) -> String {
    let mut output = String::new();
    push_line(&mut output, format_args!("IronHub {label}"));
    push_line(
        &mut output,
        format_args!(
            "phase: {}",
            match response.phase {
                IronHubPhase::Discovered => "discovered",
                IronHubPhase::Status => "status",
                IronHubPhase::Installed => "installed",
                IronHubPhase::Updated => "updated",
            }
        ),
    );
    push_line(
        &mut output,
        format_args!("total_entries: {}", response.total_entries),
    );
    push_line(
        &mut output,
        format_args!("returned_entries: {}", response.returned_entries),
    );
    if let Some(catalog_total) = response.catalog_total {
        push_line(&mut output, format_args!("catalog_total: {catalog_total}"));
    }
    push_line(
        &mut output,
        format_args!("truncated: {}", response.truncated),
    );
    if let Some(message) = &response.message {
        push_line(
            &mut output,
            format_args!("message: {}", terminal_safe(message)),
        );
    }
    for entry in &response.entries {
        push_line(
            &mut output,
            format_args!(
                "- {} {} {} [{}] ({})",
                entry.kind.as_str(),
                terminal_safe(&entry.name),
                terminal_safe(&entry.version),
                entry.provenance.as_wire(),
                terminal_safe(&entry.description)
            ),
        );
        if let Some(artifact_digest) = &entry.artifact_digest {
            push_line(
                &mut output,
                format_args!("  artifact_digest: {}", terminal_safe(artifact_digest)),
            );
        }
        if let Some(installation) = &entry.installation {
            push_line(
                &mut output,
                format_args!(
                    "  installed: version={} active={} update_available={}",
                    terminal_safe(&installation.version),
                    installation.active,
                    installation
                        .update_available
                        .map(|available| available.to_string())
                        .unwrap_or_else(|| "unknown".to_string())
                ),
            );
            for change in &installation.authority_changes {
                push_line(
                    &mut output,
                    format_args!("  authority_change: {}", terminal_safe(change)),
                );
            }
        }
    }
    output
}

fn terminal_safe(value: &str) -> String {
    value.chars().flat_map(char::escape_default).collect()
}

fn push_line(output: &mut String, args: std::fmt::Arguments<'_>) {
    use std::fmt::Write as _;
    #[allow(clippy::let_underscore_must_use)]
    let _ = output.write_fmt(args);
    output.push('\n');
}
