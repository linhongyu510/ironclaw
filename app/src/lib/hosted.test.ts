import { describe, expect, it } from "vitest";
import {
  callbackAccountToken,
  hostedControlOrigin,
  hostedLoginUrl,
  preferredIronClawInstance
} from "./hosted";

describe("hosted account bootstrap", () => {
  it("routes production and staging through their account control planes", () => {
    expect(hostedControlOrigin("https://agent.near.ai")).toBe("https://private.near.ai");
    expect(hostedControlOrigin("https://agent-stg.near.ai")).toBe(
      "https://private-chat-stg.near.ai"
    );
  });

  it("builds the hosted OAuth URL and reads query or fragment tokens", () => {
    const url = hostedLoginUrl(
      "https://private.near.ai",
      "github",
      "ironclaw://auth/callback"
    );
    expect(url).toContain("/v1/auth/github");
    expect(url).toContain("oauth_channel=mobile");
    expect(callbackAccountToken("ironclaw://auth/callback?token=query")).toBe("query");
    expect(callbackAccountToken("ironclaw://auth/callback#token=fragment")).toBe("fragment");
  });

  it("selects a running IronClaw deployment", () => {
    expect(
      preferredIronClawInstance([
        { id: "open", service_type: "openclaw", dashboard_url: "https://open.example" },
        {
          id: "stopped",
          service_type: "ironclaw",
          status: "stopped",
          dashboard_url: "https://stopped.example"
        },
        {
          id: "running",
          service_type: "ironclaw-dind",
          status: "running",
          dashboard_url: "https://running.example"
        }
      ])?.id
    ).toBe("running");
  });
});
