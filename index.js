/**
 * Remote-machine tools over the locally installed `ssh` and `rsync` binaries:
 * `remote_exec`, `remote_read`, `remote_edit`, `remote_rsync`, `remote_test`.
 *
 * Self-contained by design. A profile bundle installed from a local directory
 * is linked as a symlink, so Node resolves its bare imports from the link's
 * realpath, where no `node_modules` exists. This module therefore imports only
 * `node:` builtins and registers tools through the raw registry shape, like the
 * other local bundles in this profile.
 *
 * Scope and trust. Every tool runs as the configured remote user with no
 * sandbox: the local filesystem policy does not apply, and only the host
 * allowlist plus the destructive-command approval gate stand between the model
 * and the remote machine. Hosts resolve from `~/.ssh/config`; a host argument
 * is an alias there, never an ad-hoc `user@host`, so keys, ports, and
 * ProxyJump stay in ssh's own configuration.
 *
 * Quoting. Commands travel as one ssh argument and run in the remote login
 * shell. Path and cwd arguments are single-quoted for that shell, so a path
 * containing spaces or metacharacters cannot escape into a second command.
 * File writes stream over ssh stdin, which avoids encoding and length limits
 * entirely.
 *
 * @module dsh-remote
 */
import { spawn } from 'node:child_process'
import { mkdirSync, readFileSync } from 'node:fs'
import { homedir, tmpdir } from 'node:os'
import { join } from 'node:path'

/** Stable Loader identity. */
const name = 'dsh-remote'

/** Services used by the remote tools. */
const inject = ['tools']

/** Commands that warrant a human decision before they reach the remote host. */
const DEFAULT_APPROVAL_PATTERNS = [
  String.raw`\brm\s+(-[a-zA-Z]*\s+)*-[a-zA-Z]*[rf]`,
  String.raw`\bmkfs(\.\w+)?\b`,
  String.raw`\bdd\b[^|]*\bof=/dev/`,
  String.raw`>\s*/dev/(sd|nvme|vd|mmcblk)`,
  String.raw`\b(shutdown|reboot|halt|poweroff)\b`,
  String.raw`\b(fdisk|parted|wipefs)\b`,
  String.raw`\b(iptables|nft)\s+(-F|flush)\b`,
  String.raw`\bgit\s+(reset\s+--hard|clean\s+-[a-zA-Z]*[fd])`,
  String.raw`\b(DROP|TRUNCATE)\s+(TABLE|DATABASE)\b`,
  String.raw`\bchmod\s+(-R\s+)?777\s+/(\s|$)`,
  String.raw`\b(useradd|userdel|passwd|visudo)\b`,
  String.raw`\b(kill|pkill|killall)\s+-9\b`,
  // `remote_rsync` carries the flag as an argument rather than in a command line.
  String.raw`"delete"\s*:\s*true`,
]

/** Deployment defaults, applied over the raw row config. */
const DEFAULT_CONFIG = {
  allowHosts: [],
  allowFromSshConfig: true,
  sshConfig: join(homedir(), '.ssh', 'config'),
  // Empty keeps ssh's own config chain. Setting it to the user config path makes
  // ssh read that file alone, for a deployment whose real system ssh_config is
  // unreadable. The sandboxed bash tool's `Bad owner or permissions` failure is
  // NOT such a case: that sandbox maps the host root uid, so root-owned files
  // look like `nobody` there, while these tools spawn ssh from the host.
  sshConfigFile: '',
  approvalPatterns: DEFAULT_APPROVAL_PATTERNS,
  reuseConnections: true,
  connectTimeoutSec: 10,
  timeoutMs: 120000,
  maxOutputBytes: 65536,
}

/**
 * Merge a row config over the deployment defaults.
 *
 * @param raw - the row's `config`, or undefined.
 * @returns a complete configuration object.
 */
function normalizeConfig(raw) {
  const source = raw !== null && typeof raw === 'object' ? raw : {}
  const pick = (key) => (source[key] === undefined ? DEFAULT_CONFIG[key] : source[key])
  return {
    allowHosts: Array.isArray(pick('allowHosts')) ? pick('allowHosts') : DEFAULT_CONFIG.allowHosts,
    allowFromSshConfig: pick('allowFromSshConfig') !== false,
    sshConfig: typeof pick('sshConfig') === 'string' && pick('sshConfig') !== '' ? pick('sshConfig') : DEFAULT_CONFIG.sshConfig,
    sshConfigFile: typeof pick('sshConfigFile') === 'string' ? pick('sshConfigFile') : DEFAULT_CONFIG.sshConfigFile,
    approvalPatterns: Array.isArray(pick('approvalPatterns')) ? pick('approvalPatterns') : DEFAULT_CONFIG.approvalPatterns,
    reuseConnections: pick('reuseConnections') !== false,
    connectTimeoutSec: Number.isFinite(pick('connectTimeoutSec')) ? pick('connectTimeoutSec') : DEFAULT_CONFIG.connectTimeoutSec,
    timeoutMs: Number.isFinite(pick('timeoutMs')) ? pick('timeoutMs') : DEFAULT_CONFIG.timeoutMs,
    maxOutputBytes: Number.isSafeInteger(pick('maxOutputBytes')) ? pick('maxOutputBytes') : DEFAULT_CONFIG.maxOutputBytes,
  }
}

/**
 * Compile one author-facing schema node into the registry's JSON Schema subset.
 *
 * Property nodes carry `required: true`; the compiler lifts those into the
 * object's `required` array, which is what the registry actually enforces.
 *
 * @param spec - author-facing schema node.
 * @returns the equivalent JSON Schema node.
 */
function compileSchema(spec) {
  if (spec === undefined || spec === null) return {}
  if (Array.isArray(spec.oneOf)) return { oneOf: spec.oneOf.map((branch) => compileSchema(branch)) }
  const type = spec.type
  // An author-only unconstrained node becomes an annotation-only schema.
  if (type === 'json') return {}
  const node = {}
  if (type !== undefined) node.type = type
  for (const key of ['description', 'title', 'default', 'examples']) {
    if (spec[key] !== undefined) node[key] = spec[key]
  }
  if (spec.enum !== undefined) node.enum = [...spec.enum]
  if (spec.const !== undefined) node.const = spec.const
  if (type === 'array') node.items = spec.items === undefined ? {} : compileSchema(spec.items)
  if (type === 'object') {
    const properties = {}
    const required = []
    for (const [key, child] of Object.entries(spec.properties ?? {})) {
      if (child !== null && typeof child === 'object' && child.required === true) required.push(key)
      properties[key] = compileSchema(child)
    }
    node.properties = properties
    // Absent means "additional properties accepted", which parameters rely on.
    if (spec.additionalProperties !== undefined) node.additionalProperties = spec.additionalProperties
    if (required.length > 0) node.required = required
  }
  return node
}

/**
 * Validate one value against a compiled JSON Schema node.
 *
 * @param schema - compiled schema node.
 * @param value - candidate value.
 * @param path - diagnostic path.
 * @returns path-qualified violations; empty means valid.
 */
function validateValue(schema, value, path) {
  if (schema === null || typeof schema !== 'object') return []
  if (Array.isArray(schema.oneOf)) {
    const matches = schema.oneOf.filter((branch) => validateValue(branch, value, path).length === 0)
    return matches.length === 1 ? [] : [`${path} must match exactly one allowed shape`]
  }
  const type = schema.type
  const violations = []
  if (type === undefined) return violations
  if (type === 'object') {
    if (value === null || typeof value !== 'object' || Array.isArray(value)) return [`${path} must be an object`]
    const properties = schema.properties ?? {}
    for (const key of schema.required ?? []) {
      if (!Object.hasOwn(value, key)) violations.push(`${path}.${key} is required`)
    }
    if (schema.additionalProperties === false) {
      for (const key of Object.keys(value)) {
        if (!Object.hasOwn(properties, key)) violations.push(`${path}.${key} is not an accepted property`)
      }
    }
    for (const [key, child] of Object.entries(properties)) {
      if (Object.hasOwn(value, key)) violations.push(...validateValue(child, value[key], `${path}.${key}`))
    }
    return violations
  }
  if (type === 'array') {
    if (!Array.isArray(value)) return [`${path} must be an array`]
    for (const [index, item] of value.entries()) violations.push(...validateValue(schema.items ?? {}, item, `${path}[${index}]`))
    return violations
  }
  const ok = type === 'string' ? typeof value === 'string'
    : type === 'integer' ? Number.isInteger(value)
      : type === 'number' ? typeof value === 'number' && Number.isFinite(value)
        : type === 'boolean' ? typeof value === 'boolean'
          : type === 'null' ? value === null
            : true
  if (!ok) violations.push(`${path} must be a ${type}`)
  else if (Array.isArray(schema.enum) && !schema.enum.includes(value)) violations.push(`${path} must be one of ${schema.enum.map((entry) => JSON.stringify(entry)).join(', ')}`)
  return violations
}

/**
 * Build a registry-ready tool from an author-facing definition, validating
 * arguments exactly as the first-party `defineTool` helper would.
 *
 * @param options - name, description, parameter spec, output spec, presenters, and execute body.
 * @returns a definition the tool registry accepts.
 */
function defineTool(options) {
  const parameters = { type: 'object', properties: compileSchema({ type: 'object', properties: options.parameters }).properties }
  const requirements = Object.entries(options.parameters)
    .filter(([, child]) => child !== null && typeof child === 'object' && child.required === true)
    .map(([key]) => key)
  if (requirements.length > 0) parameters.required = requirements
  const outputSchema = compileSchema(options.output.schema)
  const validate = (args) => validateValue(parameters, args, 'arguments')
  const tool = {
    name: options.name,
    description: options.description,
    parameters,
    output: {
      schema: outputSchema,
      render: (args, value) => options.output.render(args, value),
    },
    async execute(args, exec) {
      const violations = validate(args)
      if (violations.length > 0) throw new Error(`invalid arguments: ${violations.join('; ')}`)
      return options.execute(args, exec)
    },
  }
  if (options.presentCall !== undefined) {
    tool.presentCall = (args) => (validate(args).length > 0 ? undefined : options.presentCall(args))
  }
  if (options.timeoutMs !== undefined) tool.timeoutMs = options.timeoutMs
  return tool
}

/** Quote one string for the remote POSIX shell. */
function shq(value) {
  return `'${String(value).replace(/'/g, `'\\''`)}'`
}

/** Parse the `Host` aliases declared in one SSH configuration file. */
function parseSshHosts(path) {
  let text
  try {
    text = readFileSync(path, 'utf8')
  } catch {
    return []
  }
  const hosts = []
  for (const line of text.split('\n')) {
    const match = /^\s*Host\s+(.+?)\s*$/i.exec(line)
    if (match === null) continue
    for (const token of match[1].split(/\s+/)) {
      if (token === '' || /[*?![\]]/.test(token)) continue
      if (!hosts.includes(token)) hosts.push(token)
    }
  }
  return hosts
}

/** Compile one allowlist entry into a matcher. */
function globMatcher(pattern) {
  const source = pattern
    .replace(/[.+^${}()|[\]\\]/g, '\\$&')
    .replace(/\*/g, '.*')
    .replace(/\?/g, '.')
  return new RegExp(`^${source}$`)
}

/** Resolve the host aliases this deployment accepts. */
function allowedHosts(config) {
  const base = config.allowFromSshConfig ? parseSshHosts(config.sshConfig) : []
  const patterns = config.allowHosts.filter((entry) => entry.trim() !== '')
  if (patterns.length === 0) return base
  return base.filter((host) => {
    let allowed = false
    for (const pattern of patterns) {
      const negated = pattern.startsWith('!')
      const matcher = globMatcher(negated ? pattern.slice(1) : pattern)
      if (matcher.test(host)) allowed = !negated
    }
    return allowed
  })
}

/** Reject a host outside the resolved allowlist. */
function requireHost(config, host) {
  const hosts = allowedHosts(config)
  if (hosts.includes(host)) return
  const hint = hosts.length === 0
    ? `no host is allowed: config.sshConfig (${config.sshConfig}) declares no usable Host alias`
    : `allowed hosts: ${hosts.join(', ')}`
  throw new Error(`host "${host}" is not allowed. ${hint}`)
}

/** Absolute socket path for connection multiplexing, kept short for the socket limit. */
function controlPath() {
  const dir = join(tmpdir(), 'dsh-ssh')
  mkdirSync(dir, { recursive: true })
  return join(dir, 'cm-%C')
}

/** Build the argv for one ssh invocation. */
function sshArgs(config, host, command) {
  const args = ['-o', 'BatchMode=yes', '-o', `ConnectTimeout=${config.connectTimeoutSec}`]
  // `-F` replaces the whole configuration chain, including the system file.
  if (config.sshConfigFile !== '') args.push('-F', config.sshConfigFile)
  if (config.reuseConnections) {
    args.push('-o', 'ControlMaster=auto', '-o', `ControlPath=${controlPath()}`, '-o', 'ControlPersist=300')
  }
  args.push(host, command)
  return args
}

/** Build the argv for one rsync invocation that travels through ssh. */
function rsyncArgs(config, source, destination, extra) {
  const sshCommand = ['ssh', '-o', 'BatchMode=yes', '-o', `ConnectTimeout=${config.connectTimeoutSec}`]
  if (config.sshConfigFile !== '') sshCommand.push('-F', config.sshConfigFile)
  if (config.reuseConnections) {
    sshCommand.push('-o', 'ControlMaster=auto', '-o', `ControlPath=${controlPath()}`, '-o', 'ControlPersist=300')
  }
  return ['-az', '--partial', '-e', sshCommand.join(' '), ...extra, source, destination]
}

/** Retain the last `bytes` bytes of one string without splitting a surrogate pair. */
function tailBytes(text, bytes) {
  if (bytes <= 0) return ''
  const buffer = Buffer.from(text, 'utf8')
  if (buffer.length <= bytes) return text
  const sliced = buffer.subarray(buffer.length - bytes).toString('utf8')
  const first = sliced.codePointAt(0)
  return first !== undefined && first > 0xffff ? sliced.slice(2) : sliced.replace(/^\ufffd/, '')
}

/**
 * Run one child process, collecting bounded output.
 *
 * @param bin - executable name.
 * @param args - argument vector, never shell-interpreted locally.
 * @param opts - stdin text, deadline, output cap, and caller cancellation.
 * @returns exit code, captured streams, and whether output was truncated.
 */
function runProcess(bin, args, opts) {
  return new Promise((resolve, reject) => {
    // A detached child leads its own process group, so a deadline or a caller
    // abort can kill it and everything it spawned instead of leaving orphans
    // that still hold the output pipes open.
    const child = spawn(bin, args, { stdio: ['pipe', 'pipe', 'pipe'], detached: true })
    const cap = opts.maxBytes
    let stdout = ''
    let stderr = ''
    let stdoutBytes = 0
    let stderrBytes = 0
    let truncated = false
    let settled = false
    let timer
    const collect = (chunk, which) => {
      const text = chunk.toString('utf8')
      const bytes = Buffer.byteLength(text, 'utf8')
      if (which === 'out') {
        stdoutBytes += bytes
        if (stdoutBytes > cap) truncated = true
        stdout = tailBytes(stdout + text, cap)
      } else {
        stderrBytes += bytes
        if (stderrBytes > cap) truncated = true
        stderr = tailBytes(stderr + text, cap)
      }
    }
    const finish = (code, signalName) => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      opts.signal?.removeEventListener('abort', onAbort)
      child.stdout.destroy()
      child.stderr.destroy()
      resolve({
        // A killed child reports no code; `killed` lets the caller distinguish
        // a local deadline from a remote process that chose that exit status.
        exitCode: code === null ? -1 : code,
        killed: signalName !== null,
        stdout,
        stderr,
        truncated,
      })
    }
    const fail = (error) => {
      if (settled) return
      settled = true
      clearTimeout(timer)
      opts.signal?.removeEventListener('abort', onAbort)
      reject(error)
    }
    const kill = () => {
      try {
        process.kill(-child.pid, 'SIGKILL')
      } catch {
        child.kill('SIGKILL')
      }
    }
    const onAbort = () => kill()
    timer = setTimeout(kill, opts.timeoutMs)
    child.on('error', (error) => {
      const hint = error.code === 'ENOENT' ? ` (${bin} is not installed or not on PATH)` : ''
      fail(new Error(`cannot run ${bin}: ${error.message}${hint}`))
    })
    child.stdout.on('data', (chunk) => collect(chunk, 'out'))
    child.stderr.on('data', (chunk) => collect(chunk, 'err'))
    if (opts.signal !== undefined) {
      opts.signal.addEventListener('abort', onAbort, { once: true })
      // A signal that is already aborted never fires the listener above.
      if (opts.signal.aborted) kill()
    }
    // Settle on process exit rather than pipe close: a killed descendant can
    // hold the inherited pipe open long after the process itself is gone.
    child.on('exit', (code, signalName) => finish(code, signalName))
    child.on('close', (code, signalName) => finish(code, signalName))
    if (opts.input !== undefined) child.stdin.end(opts.input)
    else child.stdin.end()
  })
}

/** Compose the remote command that changes directory before running. */
function inCwd(cwd, command) {
  return cwd === undefined || cwd === '' ? command : `cd ${shq(cwd)} && ${command}`
}

/** Render one text block. */
const oneText = (text) => [{ type: 'text', text }]

/** Reject a value that is not a non-empty string argument. */
function requireText(value, label) {
  if (typeof value !== 'string' || value.trim() === '') throw new Error(`${label} must be a non-empty string`)
  return value
}

/** Resolve one call deadline from the per-call override and the configured default. */
function resolveTimeout(config, requested) {
  const value = requested === undefined ? config.timeoutMs : requested
  if (!Number.isFinite(value) || value < 1000) throw new Error('timeoutMs must be a number of at least 1000')
  return Math.min(value, 1800000)
}

/**
 * Register the remote tools and the prompt section that lists allowed hosts.
 *
 * @param ctx - Host context carrying the tool registry.
 * @param rawConfig - the row's raw config; deployment defaults fill the rest.
 */
function apply(ctx, rawConfig) {
  const config = normalizeConfig(rawConfig)
  const maxBytes = config.maxOutputBytes
  if (maxBytes < 1024) throw new Error('dsh-remote requires maxOutputBytes of at least 1024')
  const approvalMatchers = config.approvalPatterns.map((pattern) => {
    try {
      return new RegExp(pattern)
    } catch (error) {
      throw new Error(`dsh-remote approvalPatterns entry ${JSON.stringify(pattern)} is not a valid regex: ${error.message}`)
    }
  })

  /** Run one remote command after allowlist and shell-quoting checks. */
  const execRemote = async (exec, host, command, cwd, timeoutMs) => {
    requireHost(config, host)
    requireText(command, 'command')
    const remoteCommand = inCwd(cwd, command)
    const result = await runProcess('ssh', sshArgs(config, host, remoteCommand), {
      timeoutMs: resolveTimeout(config, timeoutMs),
      maxBytes,
      signal: exec.signal,
    })
    return { host, command: remoteCommand, ...result }
  }

  /** Stream content into a remote file over ssh stdin. */
  const writeRemoteFile = async (exec, host, path, content) => {
    const result = await runProcess('ssh', sshArgs(config, host, `cat > ${shq(path)}`), {
      input: content,
      timeoutMs: resolveTimeout(config, undefined),
      maxBytes,
      signal: exec.signal,
    })
    if (result.exitCode !== 0) throw new Error(`writing ${host}:${path} failed: ${result.stderr.trim() || `exit code ${result.exitCode}`}`)
    return Buffer.byteLength(content, 'utf8')
  }

  // Ask before a command that matches a destructive pattern. Non-remote tools
  // delegate unchanged, so the local `bash` tool keeps its own policy.
  ctx.on('tools/pre-execute', (exec, next) => {
    if (!String(exec.name).startsWith('remote_')) return next()
    const text = JSON.stringify(exec.arguments ?? {})
    const hit = approvalMatchers.find((matcher) => matcher.test(text))
    if (hit === undefined) return next()
    return Promise.resolve({
      kind: 'ask',
      reason: `remote command on "${exec.arguments?.host ?? 'unknown host'}" matches the destructive pattern ${hit} and can damage that machine beyond DSH's control`,
    })
  })

  ctx.tools.register(defineTool({
    name: 'remote_exec',
    description: 'Run a command on an allowed remote machine over ssh and return its exit code with captured stdout and stderr. The command runs in the remote login shell as the configured user, with no sandbox; pass `cwd` instead of `cd`. Output is truncated to the tail. A command that matches the deployment\'s destructive patterns asks for approval first.',
    parameters: {
      host: { type: 'string', required: true, description: 'SSH-config Host alias. Only aliases the deployment allows are accepted.' },
      command: { type: 'string', required: true, description: 'Shell command to run on the remote machine.' },
      cwd: { type: 'string', description: 'Absolute remote directory to run in. Omit to use the remote login shell default.' },
      description: { type: 'string', description: 'Short human-readable summary of what the command does.' },
      timeoutMs: { type: 'integer', description: 'Deadline in milliseconds; at least 1000 and at most 30 minutes. Defaults to the deployment setting.' },
    },
    output: {
      schema: {
        type: 'object',
        additionalProperties: false,
        properties: {
          host: { type: 'string', required: true },
          command: { type: 'string', required: true },
          exitCode: { type: 'integer', required: true },
          killed: { type: 'boolean', required: true },
          stdout: { type: 'string', required: true },
          stderr: { type: 'string', required: true },
          truncated: { type: 'boolean', required: true },
        },
      },
      render: (_args, value) => {
        const parts = [`$ ${value.command}`]
        if (value.stdout !== '') parts.push(value.stdout)
        if (value.stderr !== '') parts.push(`[stderr]\n${value.stderr}`)
        parts.push(`[exit code: ${value.exitCode}]`)
        if (value.truncated) parts.push('[output truncated to the tail]')
        return oneText(parts.join('\n'))
      },
    },
    presentCall: (args) => ({
      card: 'terminal',
      title: args.command,
      ...(args.description === undefined ? {} : { description: args.description }),
      ...(args.cwd === undefined ? {} : { cwd: args.cwd }),
    }),
    execute: (args, exec) => execRemote(exec, args.host, args.command, args.cwd, args.timeoutMs),
  }))

  ctx.tools.register(defineTool({
    name: 'remote_read',
    description: 'Read a text file on an allowed remote machine and return line-numbered content. Use it before remote_edit, because the edit needs exact current text. Rejects binary content.',
    parameters: {
      host: { type: 'string', required: true, description: 'SSH-config Host alias the deployment allows.' },
      path: { type: 'string', required: true, description: 'Absolute path of the remote file.' },
      offset: { type: 'integer', description: '1-based first line to return. Defaults to 1.' },
      limit: { type: 'integer', description: 'Maximum number of lines to return. Defaults to 2000.' },
    },
    output: {
      schema: {
        type: 'object',
        additionalProperties: false,
        properties: {
          host: { type: 'string', required: true },
          path: { type: 'string', required: true },
          offset: { type: 'integer', required: true },
          totalLines: { type: 'integer', required: true },
          lines: {
            type: 'array',
            required: true,
            items: {
              type: 'object',
              additionalProperties: false,
              properties: {
                number: { type: 'integer', required: true },
                text: { type: 'string', required: true },
              },
            },
          },
          truncated: { type: 'boolean', required: true },
        },
      },
      render: (_args, value) => {
        const body = value.lines.map((line) => `${line.number}\t${line.text}`).join('\n')
        const note = value.truncated ? `\n[showing ${value.lines.length} of ${value.totalLines} lines]` : ''
        return oneText(`${value.host}:${value.path}\n${body}${note}`)
      },
    },
    presentCall: (args) => ({ card: 'generic', kind: 'read', title: `Read ${args.host}:${args.path}`, locations: [{ path: args.path, ...(args.offset === undefined ? {} : { line: args.offset }) }] }),
    async execute(args, exec) {
      const offset = args.offset === undefined ? 1 : args.offset
      const limit = args.limit === undefined ? 2000 : args.limit
      if (!Number.isSafeInteger(offset) || offset < 1) throw new Error('offset must be a positive integer')
      if (!Number.isSafeInteger(limit) || limit < 1 || limit > 20000) throw new Error('limit must be an integer between 1 and 20000')
      const remoteCommand = `wc -l < ${shq(args.path)} && sed -n ${shq(`${offset},${offset + limit - 1}p`)} ${shq(args.path)}`
      const result = await execRemote(exec, args.host, remoteCommand, undefined, undefined)
      if (result.exitCode !== 0) throw new Error(`${args.host}:${args.path} could not be read: ${result.stderr.trim() || `exit code ${result.exitCode}`}`)
      const newline = result.stdout.indexOf('\n')
      const totalLines = Number.parseInt(newline === -1 ? result.stdout : result.stdout.slice(0, newline), 10)
      const body = newline === -1 ? '' : result.stdout.slice(newline + 1)
      const raw = body === '' ? [] : body.replace(/\n$/, '').split('\n')
      if (/[\u0000-\u0008\u000e-\u001f]/.test(raw.join('\n'))) throw new Error(`${args.host}:${args.path} looks like a binary file and cannot be read as text`)
      return {
        host: args.host,
        path: args.path,
        offset,
        totalLines: Number.isFinite(totalLines) ? totalLines : raw.length,
        lines: raw.map((text, index) => ({ number: offset + index, text })),
        truncated: raw.length >= limit,
      }
    },
  }))

  ctx.tools.register(defineTool({
    name: 'remote_edit',
    description: 'Create or change a text file on an allowed remote machine. `replace` needs the exact current text and fails unless it matches exactly once, so read the file first; `create` refuses to touch an existing file; `overwrite` replaces the whole file. Content streams over ssh stdin, so no quoting or length limit applies.',
    parameters: {
      host: { type: 'string', required: true, description: 'SSH-config Host alias the deployment allows.' },
      path: { type: 'string', required: true, description: 'Absolute path of the remote file.' },
      mode: {
        type: 'string',
        required: true,
        enum: ['replace', 'create', 'overwrite'],
        description: 'replace patches old_string; create writes a new file and fails if it exists; overwrite replaces the whole file.',
      },
      old_string: { type: 'string', description: 'Exact text to replace. Required for replace mode.' },
      new_string: { type: 'string', description: 'Replacement text. Required for replace mode; may be empty to delete the match.' },
      content: { type: 'string', description: 'Complete file content. Required for create and overwrite modes.' },
      replace_all: { type: 'boolean', description: 'Replace every occurrence instead of requiring exactly one.' },
    },
    output: {
      schema: {
        type: 'object',
        additionalProperties: false,
        properties: {
          host: { type: 'string', required: true },
          path: { type: 'string', required: true },
          mode: { type: 'string', required: true },
          replacements: { type: 'integer', required: true },
          bytesWritten: { type: 'integer', required: true },
        },
      },
      render: (_args, value) => oneText(value.mode === 'replace'
        ? `Edited ${value.host}:${value.path} (${value.replacements} replacement${value.replacements === 1 ? '' : 's'})`
        : `Wrote ${value.host}:${value.path} (${value.bytesWritten} bytes)`),
    },
    presentCall: (args) => ({
      card: 'diff',
      title: `${args.mode === 'replace' ? 'Edit' : 'Write'} ${args.host}:${args.path}`,
      diffs: [{
        path: args.path,
        oldText: args.mode === 'replace' ? args.old_string ?? null : null,
        newText: args.mode === 'replace' ? args.new_string ?? '' : args.content ?? '',
      }],
      locations: [{ path: args.path }],
    }),
    async execute(args, exec) {
      requireHost(config, args.host)
      requireText(args.path, 'path')
      if (args.mode === 'create' || args.mode === 'overwrite') {
        if (typeof args.content !== 'string') throw new Error(`mode "${args.mode}" requires content`)
        if (args.mode === 'create') {
          const probe = await execRemote(exec, args.host, `test -e ${shq(args.path)} && echo EXISTS || echo ABSENT`, undefined, undefined)
          if (probe.stdout.trim() === 'EXISTS') throw new Error(`${args.host}:${args.path} already exists; use mode "replace" to change it or "overwrite" to replace it`)
        }
        const bytesWritten = await writeRemoteFile(exec, args.host, args.path, args.content)
        return { host: args.host, path: args.path, mode: args.mode, replacements: 0, bytesWritten }
      }
      if (args.mode !== 'replace') throw new Error(`unknown mode "${args.mode}"`)
      if (typeof args.old_string !== 'string' || args.old_string === '') throw new Error('mode "replace" requires a non-empty old_string')
      if (typeof args.new_string !== 'string') throw new Error('mode "replace" requires new_string')
      const current = await runProcess('ssh', sshArgs(config, args.host, `cat ${shq(args.path)}`), {
        timeoutMs: resolveTimeout(config, undefined),
        maxBytes,
        signal: exec.signal,
      })
      if (current.exitCode !== 0) throw new Error(`${args.host}:${args.path} could not be read: ${current.stderr.trim() || `exit code ${current.exitCode}`}`)
      if (current.truncated) throw new Error(`${args.host}:${args.path} exceeds the output cap, so a literal replace cannot be applied safely; lower the file size or edit it on the remote host`)
      const occurrences = current.stdout.split(args.old_string).length - 1
      if (occurrences === 0) throw new Error(`old_string was not found in ${args.host}:${args.path}; read the file and copy the exact text`)
      if (occurrences > 1 && args.replace_all !== true) throw new Error(`old_string appears ${occurrences} times in ${args.host}:${args.path}; pass replace_all to change every occurrence or include more surrounding text`)
      const updated = args.replace_all === true
        ? current.stdout.split(args.old_string).join(args.new_string)
        : current.stdout.replace(args.old_string, args.new_string)
      const bytesWritten = await writeRemoteFile(exec, args.host, args.path, updated)
      return { host: args.host, path: args.path, mode: args.mode, replacements: args.replace_all === true ? occurrences : 1, bytesWritten }
    },
  }))

  ctx.tools.register(defineTool({
    name: 'remote_rsync',
    description: 'Copy files or directories between the local workspace and an allowed remote machine, or between two allowed remote machines, through the local rsync binary. Paths on the remote side are absolute; local paths resolve against the session working directory. `up` sends, `down` fetches. `delete` removes destination entries missing from the source and asks for approval.',
    parameters: {
      direction: { type: 'string', required: true, enum: ['up', 'down'], description: 'up copies from the local side to the remote; down copies from the remote to the local side.' },
      host: { type: 'string', required: true, description: 'SSH-config Host alias the deployment allows.' },
      source: { type: 'string', required: true, description: 'Absolute source path, or the remote path under direction down.' },
      destination: { type: 'string', required: true, description: 'Absolute destination path on the opposite side.' },
      delete: { type: 'boolean', description: 'Delete destination entries absent from the source. Destructive; approved separately.' },
      dryRun: { type: 'boolean', description: 'Report the transfer without changing anything.' },
      timeoutMs: { type: 'integer', description: 'Deadline in milliseconds; at least 1000 and at most 30 minutes.' },
    },
    output: {
      schema: {
        type: 'object',
        additionalProperties: false,
        properties: {
          host: { type: 'string', required: true },
          direction: { type: 'string', required: true },
          source: { type: 'string', required: true },
          destination: { type: 'string', required: true },
          exitCode: { type: 'integer', required: true },
          output: { type: 'string', required: true },
          truncated: { type: 'boolean', required: true },
        },
      },
      render: (_args, value) => oneText(`rsync ${value.direction} ${value.host}: ${value.source} -> ${value.destination}\n${value.output}\n[exit code: ${value.exitCode}]`),
    },
    presentCall: (args) => ({ card: 'terminal', title: `rsync ${args.direction} ${args.host}: ${args.source} -> ${args.destination}` }),
    async execute(args, exec) {
      requireHost(config, args.host)
      requireText(args.source, 'source')
      requireText(args.destination, 'destination')
      const extra = []
      if (args.delete === true) extra.push('--delete')
      if (args.dryRun === true) extra.push('--dry-run')
      const remote = `${args.host}:`
      const source = args.direction === 'up' ? args.source : `${remote}${args.source}`
      const destination = args.direction === 'up' ? `${remote}${args.destination}` : args.destination
      const result = await runProcess('rsync', rsyncArgs(config, source, destination, extra), {
        timeoutMs: resolveTimeout(config, args.timeoutMs),
        maxBytes,
        signal: exec.signal,
      })
      return {
        host: args.host,
        direction: args.direction,
        source,
        destination,
        exitCode: result.exitCode,
        output: [result.stdout, result.stderr].filter((part) => part !== '').join('\n').trim(),
        truncated: result.truncated,
      }
    },
  }))

  ctx.tools.register(defineTool({
    name: 'remote_test',
    description: 'Run the test suite of a project on an allowed remote machine and return the command, its exit code, and a bounded tail of the output. With no `command`, the suite is detected from the project files in `cwd` (pytest, npm, go, cargo, make). Use it after remote_edit to check the change on the real machine.',
    parameters: {
      host: { type: 'string', required: true, description: 'SSH-config Host alias the deployment allows.' },
      cwd: { type: 'string', required: true, description: 'Absolute remote project directory.' },
      command: { type: 'string', description: 'Test command to run. Omit to autodetect the suite from the project files.' },
      timeoutMs: { type: 'integer', description: 'Deadline in milliseconds; at least 1000 and at most 30 minutes. Defaults to 10 minutes.' },
    },
    output: {
      schema: {
        type: 'object',
        additionalProperties: false,
        properties: {
          host: { type: 'string', required: true },
          cwd: { type: 'string', required: true },
          command: { type: 'string', required: true },
          exitCode: { type: 'integer', required: true },
          killed: { type: 'boolean', required: true },
          summary: { type: 'string', required: true },
          output: { type: 'string', required: true },
          truncated: { type: 'boolean', required: true },
        },
      },
      render: (_args, value) => {
        const parts = [`$ ${value.command}`, `[exit code: ${value.exitCode}]${value.killed ? ' [killed by deadline]' : ''}`]
        if (value.summary !== '') parts.push(value.summary)
        if (value.output !== '') parts.push(value.output)
        if (value.truncated) parts.push('[output truncated to the tail]')
        return oneText(parts.join('\n'))
      },
    },
    presentCall: (args) => ({ card: 'terminal', title: args.command ?? `detect and run tests in ${args.cwd}`, cwd: args.cwd }),
    async execute(args, exec) {
      const command = args.command ?? [
        'if [ -f pytest.ini ] || [ -f pyproject.toml ] || [ -f tox.ini ]; then python3 -m pytest -q',
        'elif [ -f package.json ]; then npm test --silent',
        'elif [ -f go.mod ]; then go test ./...',
        'elif [ -f Cargo.toml ]; then cargo test',
        'elif [ -f Makefile ]; then make test',
        `else echo ${shq('NO_TEST_SUITE')}; exit 127; fi`,
      ].join('; ')
      const result = await execRemote(exec, args.host, command, args.cwd, args.timeoutMs ?? 600000)
      const combined = [result.stdout, result.stderr].filter((part) => part !== '').join('\n').trim()
      if (result.exitCode === 127 && combined.includes('NO_TEST_SUITE')) {
        throw new Error(`no test suite detected in ${args.host}:${args.cwd}; pass an explicit command`)
      }
      const summary = combined.split('\n')
        .filter((line) => /(\d+\s+(passed|failed|error)|Tests?:|Test Suites?:|^ok\s|^FAIL\s|error\[|test result:)/i.test(line))
        .slice(-8)
        .join('\n')
      return {
        host: args.host,
        cwd: args.cwd,
        command,
        exitCode: result.exitCode,
        killed: result.killed,
        summary,
        output: tailBytes(combined, Math.floor(maxBytes / 2)),
        truncated: result.truncated,
      }
    },
  }))

  const systemPrompt = ctx.get('systemPrompt')
  if (systemPrompt !== undefined) {
    const hosts = allowedHosts(config)
    const text = hosts.length === 0
      ? 'Remote tools are installed but no host is allowed. Add Host entries to the SSH configuration or allow them in the dsh-remote config before calling remote_*.'
      : `Remote tools (remote_exec, remote_read, remote_edit, remote_rsync, remote_test) run against these allowed hosts: ${hosts.join(', ')}. Pass the alias as \`host\`; ad-hoc user@host is rejected. Never run a destructive remote command without the user asking for it.`
    systemPrompt.section({
      name: 'tool:remote',
      order: systemPrompt.getSectionOrder('TOOL_BASH'),
      text,
    })
  }
}

export { apply, inject, name }
