# OPENCLAW.md

Operational guidance for an OpenClaw agent using the capability gateway.

1. Identify the exact capability required for the user's requested pentest
   action. OpenClaw performs this reasoning; do not add or use natural-language
   mapping infrastructure.
2. From the project root, run `python capability.py decide-json <capability>`.
3. If the JSON `action` is `execute`, proceed through the capability's normal
   execution path only subject to the existing authorization and safety controls;
   the gateway itself grants no execution or network authorization.
4. If the JSON `action` is `propose_build`, the capability is unavailable and a
   build must be proposed. **Preferred route — when the user has specific
   requirements** (which is the normal case): create a concrete, project-local
   JSON request that captures the user's actual `capability`, `objective`, and
   `requirements`. The request must be a JSON object with at least:

   ```json
   {
     "capability": "<exact capability name>",
     "objective": "<what the user actually needs>",
     "requirements": ["<user requirement>", "<user requirement>"]
   }
   ```

   Show the user a summary of those requirements and ask for explicit approval:

   ```text
   Required capability is not available.

   I can hand this build request to OpenCode Architect:
   <short objective>
   Requirements:
   - <requirement>
   - <requirement>

   Approve handoff?
   ```

5. Only after explicit user approval, write that exact request to a project-local
   JSON file (inside this project directory) and run
   `python capability.py handoff-request <request-file> --approved`. This
   **submits the approved request verbatim** to the already-running local OpenCode
   Server API and returns immediately with the new OpenCode session ID (JSON
   `status: submitted`); the requirements are not regenerated, summarized,
   replaced, or altered. Never run `handoff-request` without approval.
6. **Legacy compatibility route — name only, no user-specific requirements:**
   generate the default request with
   `python capability.py build-request <capability>`, show the user the same
   approval message shape (substituting the generated JSON `objective` for
   `<short objective>`), and only after approval run
   `python capability.py handoff <capability> --approved`. Prefer the
   file-based `handoff-request` route from steps 4–5 whenever the user has
   specific requirements.
7. On exit `0`, report the returned `opencode_session_id` (and `capability`) to
   the user. The submission only confirms the request was accepted — it does not
   mean the build completed. Do not poll, stream, monitor, wait for, or auto-run
   the build or the newly requested capability.
