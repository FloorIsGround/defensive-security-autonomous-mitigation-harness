# OpenCode Go availability in the custom investigator

On November 25, 2026 the authenticated workspace catalog returned 37 Go models. Of those, 31 were chat models advertising tool support. The remaining three decision models and three embedding models do not fit the investigator tool loop. Each of the 31 chat models received one synthetic service-state prompt through the production Go adapter with its own session ID, a 384-token output cap, and one available function. The pass condition was exactly one call to `record_state` with `state=inactive`.

Twenty-eight passed. The gateway denied the other three because those endpoints train on request data and the workspace privacy setting blocks them. The successful responses reported 7,657 input and 1,614 output tokens in total. These one-turn observations establish basic tool compatibility. They do not grade model quality on an investigation. [Model catalog API](https://opencode.ai/docs/console/api/models) · [Go models and privacy settings](https://opencode.ai/docs/console/go/)

| Worker model ID | Listed token pricing | Live tool-call result |
| --- | --- | --- |
| `beam-free` | Free | Passed |
| `claude-haiku-5-5` | Metered | Passed |
| `deepseek-v4-pro` | Metered | Passed |
| `deepseek-v4.1-flash` | Metered | Passed |
| `gemini-4-argon` | Metered | Passed |
| `glm-5.3` | Metered | Passed |
| `glm-5.3-flash` | Metered | Passed |
| `gpt-5.6-luna` | Metered | Passed |
| `gpt-6-luna` | Metered | Passed |
| `grok-4.7` | Metered | Passed |
| `hungerg-free` | Free | Passed |
| `hy3` | Metered | Passed |
| `hy4` | Metered | Passed |
| `hy4-flash-free` | Free | Passed |
| `hy4-preview` | Metered | Passed |
| `iceman-contributor-free` | Free | Blocked by workspace privacy setting |
| `kimi-k2.7-code` | Metered | Passed |
| `kimi-k3` | Metered | Passed |
| `kimi-k3.1-pro` | Metered | Passed |
| `longcat-2.5` | Metered | Passed |
| `mimo-v2.6-flash` | Metered | Passed |
| `mimo-v2.6-pro` | Metered | Passed |
| `minimax-m3` | Metered | Passed |
| `minimax-m3.1-flash` | Metered | Passed |
| `muse-spark-1.2-contributor` | Metered | Blocked by workspace privacy setting |
| `muse-spark-1.3-contributor` | Metered | Blocked by workspace privacy setting |
| `qwen3.7-plus` | Metered | Passed |
| `qwen3.8-flash` | Metered | Passed |
| `qwen3.8-max` | Metered | Passed |
| `qwen4-max` | Metered | Passed |
| `step-5-preview` | Metered | Passed |

Run `PYTHONPATH=reasoner python3 -m defsec_reasoner opencode-go models` from the repository root to refresh the authenticated catalog without sending prompts. Pricing and workspace eligibility can change.

## Guided investigation check

On the Phase 18 new-service case, each of the three additional runs requested a watch, received a fresh active/running unit sample, cited observation 3, and passed audit verification. GPT-6 Luna with high effort and HungerG Free both persisted the expected `supports` verdict. Hy4 Flash Free persisted `unresolved` and failed the verdict gate. Luna used three calls in the initial session and one in the follow-up. HungerG and Hy4 each used two initial calls and one follow-up. Beam Free previously passed this same end-to-end case through the Go adapter. Each result represents one guided episode. [Phase 18 scoring protocol](phase18-protocol.md)
