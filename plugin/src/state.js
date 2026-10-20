// Plugin state (ctx.state, instance scope): metadata only, never a credential, cookie or token. The decision log and the
// leases are not kept here: they are read live from vaultd, the single source of truth.
//
//   vault.enrol          {code, expiresAt, createdBy, companyId, lastError?}  the pending one-time enrolment code
//   vault.install        {installId, vaultdVersion, enrolledAt, kid}           set when vaultd accepted the enrolment
//   vault.pending        {requestId: {...}}  requests created by an agent and not yet delivered or finished
//   vault.deliveries     {requestId: {...}}  files written into workspaces that must be removed at lease end
//   vault.model          {model, provider, k, selectedBy, selectedAt}          the model that judges requests
//   vault.models         {fetchedAt, provider, models: [{id}]}                 the last model list from the provider
//   vault.judge-records  {"<provider>|<model>": {...}}                         results of the judge tests run by this plugin
//   vault.judge-run      {state, model, provider, k, done, total, ...}         progress / result of the running or last test run
//
// One worker process owns the state, so read-modify-write is serialised in-process.

const key = (stateKey) => Object.freeze({ scopeKind: "instance", stateKey });
export const KEYS = Object.freeze({
  enrol: key("vault.enrol"),
  install: key("vault.install"),
  pending: key("vault.pending"),
  deliveries: key("vault.deliveries"),
  model: key("vault.model"),
  models: key("vault.models"),
  records: key("vault.judge-records"),
  judgeRun: key("vault.judge-run"),
});

const plain = (v) => (v && typeof v === "object" && !Array.isArray(v) ? v : {});

export function createState(ctx) {
  let queue = Promise.resolve();
  const exclusive = (fn) => { const run = queue.then(fn, fn); queue = run.catch(() => {}); return run; };
  const read = async (k) => (await ctx.state.get(k)) ?? null;

  /** A map of records under one state key, with atomic put/drop. */
  const mapOf = (k) => ({
    all: async () => plain(await read(k)),
    get: async (id) => plain(await read(k))[id] ?? null,
    put: (id, value) => exclusive(async () => { await ctx.state.set(k, { ...plain(await read(k)), [id]: value }); }),
    drop: (id) => exclusive(async () => {
      const m = plain(await read(k));
      if (!(id in m)) return;
      delete m[id];
      await ctx.state.set(k, m);
    }),
    update: (id, fn) => exclusive(async () => {
      const m = plain(await read(k));
      if (!(id in m)) return null;
      m[id] = fn(m[id]);
      await ctx.state.set(k, m);
      return m[id];
    }),
  });

  return {
    exclusive,
    enrol: () => read(KEYS.enrol),
    setEnrol: (v) => ctx.state.set(KEYS.enrol, v),
    clearEnrol: () => ctx.state.delete(KEYS.enrol),
    install: () => read(KEYS.install),
    setInstall: (v) => ctx.state.set(KEYS.install, v),
    pending: mapOf(KEYS.pending),
    deliveries: mapOf(KEYS.deliveries),
    records: mapOf(KEYS.records),
    model: () => read(KEYS.model),
    setModel: (v) => ctx.state.set(KEYS.model, v),
    models: () => read(KEYS.models),
    setModels: (v) => ctx.state.set(KEYS.models, v),
    judgeRun: () => read(KEYS.judgeRun),
    setJudgeRun: (v) => ctx.state.set(KEYS.judgeRun, v),
  };
}

/** Key of a judge-test record: one per (provider backend, model). */
export const recordKey = (provider, model) => `${provider}|${model}`;
