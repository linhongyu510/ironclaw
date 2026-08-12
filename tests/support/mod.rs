pub mod assertions;
pub mod cleanup;
pub mod mock_mcp_server;
pub mod mock_openai_server;
pub mod trace_llm;

#[allow(dead_code)]
pub fn trigger_execution_contract(goal: impl Into<String>) -> serde_json::Value {
    serde_json::json!({
        "version": 1,
        "goal": goal.into(),
        "success_criteria": ["Complete the requested task"],
        "output_instructions": "Return a concise result",
        "no_result_text": "No result"
    })
}
