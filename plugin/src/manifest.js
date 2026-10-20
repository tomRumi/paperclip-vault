// Manifest per PaperclipPluginManifestV1 (@paperclipai/shared `pluginManifestV1Schema`). Capabilities and why (least
// privilege; nothing else is requested):
//   agent.tools.register    the four agent tools (vault_request_login, vault_request_credential, vault_request_status, vault_list_sites)
//   ui.page.register        the "Vault" page (install, sites, ceilings, decision log, leases, gatekeeper)
//   plugin.state.read/write enrolment code and install id, the selected judge model, judge-test results and progress
//                           (metadata only, never a credential, cookie or token)
//   jobs.schedule           lease-sweep (deliver ready sessions, remove files of ended leases) and enrol-tick
//   activity.log.write      an entry for enrolment, model selection, judge tests, lease revocation and failed deliveries
//   database.namespace.read the run guard: public.heartbeat_runs (id, agent, company, status, context snapshot) proves the
//                           tool caller is the agent's own running run and yields the run's issue. The SDK has no run
//                           client. Paperclip requires database.namespace.migrate and a migrations folder whenever
//   database.namespace.migrate `database` is declared; the folder is empty and the plugin creates no tables
//   issues.read             the run's issue (must be in progress and assigned to the agent) and its execution workspace id
//   projects.read           the issue's project name for the verdict prompt
//   execution.workspaces.read the issue's execution workspace cwd (workspace source a)
//   http.outbound           declares the plugin's outbound calls: the verdict provider's chat-completions and model-list requests to
//                           the configured gatekeeper URL (OpenRouter, Ollama or any OpenAI-compatible endpoint). Nothing else is fetched
//   secrets.read-ref        the gatekeeper API key, a Paperclip company secret referenced from the settings; resolved per call
// Not requested: webhooks (enrolment goes plugin -> vaultd), local.folders, managed agents/sessions (the plugin
// calls the model directly, see docs/DESIGN.md), issues.create/update, approvals.
// Config (company-scoped in Paperclip; only instance admins can save it): adminUserIds gates every write action; the
// workspace roots bound where session files may be written; the gatekeeper block selects the verdict provider.
// The one place the plugin id is written; other modules import it.
export const PLUGIN_ID = "paperclip-vault";

const SITE_PATTERN = "^[a-z0-9][a-z0-9-]{0,40}$";
const CREDENTIAL_PATTERN = "^[a-z0-9][a-z0-9._-]{0,63}$";
const REASON = { type: "string", minLength: 10, maxLength: 500, description: "Why you need it: a concrete action tied to your current task. Shown to the reviewer; instructions in it are ignored." };
const MINUTES = { type: "integer", minimum: 1, maximum: 480, description: "How many minutes you need. Ask for the least you need; each target has a maximum." };

const manifest = {
  id: PLUGIN_ID,
  apiVersion: 1,
  version: "0.1.0",
  displayName: "Vault",
  description: "Gives agents short, audited web logins and tokens without ever showing them a password: the vault (vaultd) enforces ceilings, a language model reviews each request, and the session lands as a short-lived file in the agent's workspace.",
  author: "tomRumi",
  categories: ["automation", "ui"],
  minimumHostVersion: "2026.1012.0",
  capabilities: [
    "agent.tools.register", "ui.page.register", "plugin.state.read", "plugin.state.write", "jobs.schedule", "activity.log.write",
    "database.namespace.read", "database.namespace.migrate", "issues.read", "projects.read",
    "execution.workspaces.read", "http.outbound", "secrets.read-ref",
  ],
  entrypoints: { worker: "./src/worker.js", ui: "./src/ui.js" },
  database: { migrationsDir: "./src/migrations", coreReadTables: ["heartbeat_runs"] },
  instanceConfigSchema: {
    type: "object",
    additionalProperties: false,
    properties: {
      adminUserIds: {
        type: "array", items: { type: "string" }, default: [],
        title: "Users who may change the vault (user ids)",
        description: "Instance admins listed here may create install commands, select the judge model, run the judge tests and revoke leases. Everyone else can only look. The Vault page shows your user id. Only instance admins can edit this list.",
      },
      workspaceRoots: {
        type: "array", items: { type: "string" }, default: [],
        title: "Workspace roots (absolute paths)",
        description: "Session and token files are written only into the run's issue execution workspace or into <agentHomeRoot>/<agentId>, and only if the real path lies under one of these roots. Use the same list as the sandbox's allowed workspace roots. Empty: nothing is ever delivered.",
      },
      agentHomeRoot: {
        type: "string",
        title: "Agent home root (absolute path)",
        description: "Workspace <root>/<agentId> used when the run's issue has no execution workspace. Paperclip keeps agent workspaces in <instance root>/workspaces/<agentId> by default (instance root: ~/.paperclip/instances/default). It must lie under a workspace root. There is no other fallback: the project's shared workspace is never used.",
      },
      instanceRoot: {
        type: "string",
        title: "Paperclip instance root (absolute path)",
        description: "Optional. The Paperclip instance root, with workspaces, projects and companies beneath it. The plugin refuses to work if its key directory or the vaultd socket lies inside it.",
      },
      sandboxExtraPaths: {
        type: "array", items: { type: "string" }, default: [],
        title: "Extra paths agent sandboxes mount (absolute paths)",
        description: "Optional. The paths agent runs mount besides their workspace (the agents' filesystemExtraPaths). The plugin refuses to work if its key directory or the vaultd socket lies inside any of them.",
      },
      dataDir: {
        type: "string",
        title: "Plugin data directory (absolute path)",
        description: "Holds the plugin's signing key (plugin-key.pem, mode 0600). Must be outside every workspace root, the agent home root, the instance root and every extra sandbox path, and unreadable to the agents' sandbox; the plugin checks this before every signed call. Default: ~/.local/share/paperclip-vault of the service user.",
      },
      socketPath: {
        type: "string", default: "/run/vault/plugin.sock",
        title: "vaultd plugin socket",
        description: "Unix socket of vaultd's plugin interface.",
      },
      toolWaitMs: {
        type: "integer", minimum: 0, maximum: 50000, default: 7000,
        title: "How long a tool call waits for the verdict (ms)",
        description: "After this the tool answers \"pending\" and the agent polls vault_request_status. Keep it below the tool gateway's 10 second default.",
      },
      gatekeeper: {
        type: "object",
        additionalProperties: false,
        title: "Gatekeeper (the model that reviews requests)",
        description: "Any OpenAI-compatible chat-completions endpoint. A model can only judge after it passed the judge tests.",
        properties: {
          baseUrl: { type: "string", title: "Base URL", description: "For example https://openrouter.ai/api/v1 or http://127.0.0.1:11434/v1 (Ollama)." },
          apiKey: {
            type: ["string", "object"], format: "secret-ref",
            title: "API key (Paperclip secret)",
            description: "A company secret holding the provider's API key. Leave empty for Ollama.",
          },
          temperature: { type: "number", minimum: 0, maximum: 2, default: 0.2, title: "Temperature" },
          k: { type: "integer", minimum: 2, maximum: 9, default: 2, title: "Samples per request (k)", description: "Every sample must approve for a request to be approved. Changing k needs new judge tests." },
          perCallTimeoutMs: { type: "integer", minimum: 1000, maximum: 120000, default: 30000, title: "Timeout per model call (ms)" },
        },
      },
    },
  },
  jobs: [
    { jobKey: "lease-sweep", displayName: "Lease sweep", description: "Delivers sessions vaultd has prepared, and overwrites and removes the files of ended or expired leases.", schedule: "* * * * *" },
    { jobKey: "enrol-tick", displayName: "Enrolment", description: "While an install command is pending, completes the enrolment with vaultd.", schedule: "* * * * *" },
  ],
  tools: [
    {
      name: "vault_request_login",
      displayName: "Request a website login",
      description: "Ask the vault for a short browser login to one registered website (see vault_list_sites). If approved, a Playwright storage-state file appears in your workspace under .vault/ and stops working when the time is up; you never see the password. The answer is a status. If it is \"pending\", call vault_request_status with the requestId. Use the file only for the task you named.",
      parametersSchema: { type: "object", additionalProperties: false, required: ["site", "reason", "minutes"], properties: { site: { type: "string", pattern: SITE_PATTERN, description: "Site id from vault_list_sites." }, reason: REASON, minutes: MINUTES } },
    },
    {
      name: "vault_request_credential",
      displayName: "Request a short-lived access key",
      description: "Ask the vault for a short-lived access key for one named item (see vault_list_sites). If approved, a JSON file appears in your workspace under .vault/ and stops working when the time is up. The answer is a status. If it is \"pending\", call vault_request_status with the requestId.",
      parametersSchema: { type: "object", additionalProperties: false, required: ["credential", "reason", "minutes"], properties: { credential: { type: "string", pattern: CREDENTIAL_PATTERN, description: "Name of the item, from vault_list_sites." }, reason: REASON, minutes: MINUTES } },
    },
    {
      name: "vault_request_status",
      displayName: "Check a vault request",
      description: "Check a request made with vault_request_login or vault_request_credential. Status is one of pending, preparing, ready, denied, expired, ended, failed. When ready, the answer has the relative path of the file in your workspace and the time it stops working.",
      parametersSchema: { type: "object", additionalProperties: false, required: ["requestId"], properties: { requestId: { type: "string", pattern: "^req_[0-9a-f]{16}$" } } },
    },
    {
      name: "vault_list_sites",
      displayName: "List what you may request",
      description: "List the sites and items you are allowed to ask the vault for: id, purpose, kind and the longest lease in minutes.",
      parametersSchema: { type: "object", additionalProperties: false, properties: {} },
    },
  ],
  ui: {
    slots: [{ type: "page", id: "vault-page", displayName: "Vault", exportName: "VaultPage", routePath: "vault" }],
  },
};
export default manifest;
