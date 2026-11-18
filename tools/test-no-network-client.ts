#!/usr/bin/env node

import { readdirSync, readFileSync, statSync } from "node:fs";
import { extname, resolve } from "node:path";
import { fileURLToPath } from "node:url";
import { main, requireValue, ROOT, runText } from "./lib.ts";

export type CargoDependency = { path?: string; name: string; kind: string | null; rename: string | null; optional: boolean; uses_default_features: boolean; features: string[]; source: string | null };
export type CargoPackage = { name: string; dependencies: CargoDependency[] };
const EXPECTED: Record<string, Record<string, string[]>> = {
    normal: {
        anyhow: [],
        "ed25519-dalek": [],
        env_logger: [],
        hex: [],
        libc: [],
        log: [],
        nix: ["fs", "process", "ptrace", "signal", "user"],
        semver: [],
        serde: ["derive"],
        serde_json: [],
        sha2: [],
        "voboost-contract": [],
        "voboost-shared": [],
        "voboost-qconn": [],
    },
    build: { anyhow: [] },
    dev: { "ed25519-dalek": ["pem", "pkcs8"], tempfile: [] },
};
const NETWORK = new Set(["net", "socket", "socketpair", "connect", "listen", "accept", "accept4", "getaddrinfo", "getnameinfo", "TcpStream", "TcpListener", "UdpSocket", "ToSocketAddrs", "HttpConnector", "reqwest", "hyper", "ureq", "surf", "tonic", "syscall", "SYS_socket", "SYS_connect", "SYS_accept", "SYS_accept4", "SYS_listen", "__NR_socket", "__NR_connect", "__NR_accept", "__NR_accept4", "__NR_listen", "dlopen", "dlsym"]);
const PROCESS = new Set(["execve", "execv", "execvp", "execvpe", "fexecve", "posix_spawn", "posix_spawnp", "popen", "system"]);
const ALLOWED_COMMANDS = new Set(["/system/bin/getprop", "/system/bin/setprop"]);
const INTERNAL_HELPER_COMMAND = /\bfn\s+spawn_internal_inject_helper\s*\(\s*\)\s*->\s*std\s*::\s*io\s*::\s*Result\s*<\s*std\s*::\s*process\s*::\s*Child\s*>\s*\{\s*std\s*::\s*process\s*::\s*Command\s*::\s*new\s*\(\s*"\/data\/voboost\/voboost-inject"\s*\)\s*\.\s*arg\s*\(\s*"--internal-inject-helper"\s*\)\s*\.\s*env_clear\s*\(\s*\)\s*\.\s*env\s*\(\s*"VOBOOST_HELPER_DEBUG"\s*,\s*if\s+log\s*::\s*is_debug\s*\(\s*\)\s*\{\s*"1"\s*\}\s*else\s*\{\s*"0"\s*\}\s*,?\s*\)\s*\.\s*stdin\s*\(\s*std\s*::\s*process\s*::\s*Stdio\s*::\s*piped\s*\(\s*\)\s*\)\s*\.\s*stdout\s*\(\s*std\s*::\s*process\s*::\s*Stdio\s*::\s*piped\s*\(\s*\)\s*\)\s*\.\s*stderr\s*\(\s*std\s*::\s*process\s*::\s*Stdio\s*::\s*piped\s*\(\s*\)\s*\)\s*\.\s*spawn\s*\(\s*\)\s*\}/g;

function files(root: string): string[] {
    return readdirSync(root).flatMap((name) => {
        const path = resolve(root, name);
        if (name === "target") return [];
        return statSync(path).isDirectory() ? files(path) : [path];
    });
}

export function stripComments(source: string): string {
    let output = "";
    let index = 0;
    let state: "code" | "line" | "block" | "string" = "code";
    let depth = 0;
    while (index < source.length) {
        const pair = source.slice(index, index + 2);
        const character = source[index];
        if (state === "code") {
            if (pair === "//") { state = "line"; output += "  "; index += 2; continue; }
            if (pair === "/*") { state = "block"; depth = 1; output += "  "; index += 2; continue; }
            if (character === '"') state = "string";
            output += character;
        } else if (state === "line") {
            if (character === "\n") { state = "code"; output += character; } else output += " ";
        } else if (state === "block") {
            if (pair === "/*") { depth += 1; output += "  "; index += 2; continue; }
            if (pair === "*/") { depth -= 1; output += "  "; index += 2; if (depth === 0) state = "code"; continue; }
            output += character === "\n" ? "\n" : " ";
        } else {
            output += character;
            if (character === "\\" && index + 1 < source.length) output += source[++index];
            else if (character === '"') state = "code";
        }
        index += 1;
    }
    return output;
}

function decodeString(literal: string): string {
    const raw = /^(?:b?r)(#{0,16})"([\s\S]*)"\1$/.exec(literal);
    if (raw) return raw[2];
    requireValue(/^b?"(?:\\.|[^"\\])*"$/.test(literal), `unsupported Rust string literal ${literal}`);
    const body = literal.replace(/^b?"|"$/g, "");
    let output = "";
    for (let index = 0; index < body.length; index += 1) {
        if (body[index] !== "\\") { output += body[index]; continue; }
        const escape = body[++index];
        const simple: Record<string, string> = { n: "\n", r: "\r", t: "\t", "0": "\0", "\\": "\\", '"': '"', "'": "'" };
        if (escape in simple) output += simple[escape];
        else if (escape === "x") { output += String.fromCharCode(Number.parseInt(body.slice(index + 1, index + 3), 16)); index += 2; }
        else if (escape === "u" && body[index + 1] === "{") {
            const end = body.indexOf("}", index + 2); requireValue(end >= 0, "invalid Rust Unicode escape"); output += String.fromCodePoint(Number.parseInt(body.slice(index + 2, end).replaceAll("_", ""), 16)); index = end;
        } else if (escape === "\n") { while (/[ \t\r\n]/.test(body[index + 1] ?? "")) index += 1; }
        else throw new Error(`unsupported Rust escape \\${escape}`);
    }
    return output;
}

/** Explicit transport owners only; these exceptions never authorize a generic network client. */
function localTransports(label: string, code: string): string {
    for(const match of code.matchAll(/link_name\s*=\s*((?:b?r)(#{0,16})"[\s\S]*?"\2|b?"(?:\\.|[^"\\])*")/gu)) {
        const symbol=decodeString(match[1]);requireValue(!NETWORK.has(symbol)&&!PROCESS.has(symbol),`forbidden raw FFI link name ${symbol} in ${label}`);
    }
    requireValue(!/\buse\s+libc\s*::[^;]*\b(?:socket|connect|listen|accept|accept4)\b/u.test(code),`aliased raw socket entry point in ${label}`);
    const listeners=[...code.matchAll(/\bUnixListener\s*::\s*([A-Za-z_][A-Za-z0-9_]*)/gu)];
    if(["daemon/src/canonical_log.rs","daemon/src/owner/main.rs"].includes(label))
        requireValue(listeners.length===1&&/UnixListener::bind\(&path\)/u.test(code),`extra or redirected local listener in ${label}`);
    else requireValue(listeners.length===0,`unapproved local listener in ${label}`);
    const streams=[...code.matchAll(/\bUnixStream\s*::\s*([A-Za-z_][A-Za-z0-9_]*)/gu)];
    if(["daemon/src/owner/io.rs","daemon/src/install_acceptance.rs","daemon/src/ota_transport.rs"].includes(label))
        requireValue(streams.length===1&&streams[0][1]==="from_raw_fd",`extra or unbound local stream in ${label}`);
    else requireValue(streams.length===0,`unapproved local stream construction in ${label}`);
    if(label === "daemon/src/ota_transport.rs") {
        requireValue(!/\bAF_(?!UNIX\b)[A-Za-z0-9_]+/u.test(code),"OTA transport introduced another socket family");
        for(const [symbol,count] of [["socket",1],["listen",1],["accept4",1],["connect",0]] as const)
            requireValue([...code.matchAll(new RegExp(`\\blibc\\s*::\\s*${symbol}\\b`,"gu"))].length===count,`OTA raw ${symbol} surface changed`);
    }
    if(label === "daemon/src/canonical_log.rs") requireValue(code.includes("start_app_listener(DAEMON_SOCKET)")&&[...code.matchAll(/\bstart_app_listener\s*\(/gu)].length===2,"app ingress is no longer a single fixed local listener");
    const ownerIo = label === "daemon/src/owner/io.rs";
    const acceptance = label === "daemon/src/install_acceptance.rs";
    if (ownerIo || acceptance) {
        requireValue(!/\bAF_(?!UNIX\b)[A-Za-z0-9_]+/u.test(code), `${label} has a nonlocal socket family`);
        const sockets = /\blibc\s*::\s*socket\s*\(\s*libc\s*::\s*AF_UNIX\s*,\s*libc\s*::\s*SOCK_STREAM\s*,\s*0\s*\)/gu;
        requireValue([...code.matchAll(sockets)].length === 1, `${label} must have one explicit AF_UNIX stream socket`);
        code = code.replace(sockets, "local_socket()");
        const connects = ownerIo
            ? /\blibc\s*::\s*connect\s*\(\s*fd\s*,\s*&address\s+as\s+\*const\s+_\s+as\s+\*const\s+libc::sockaddr\s*,\s*length\s*\)/gu
            : /\blibc\s*::\s*connect\s*\(\s*fd\s*,\s*\(&address\s+as\s+\*const\s+libc::sockaddr_un\)\.cast\(\)\s*,\s*std::mem::size_of_val\(&address\)\s+as\s+libc::socklen_t\s*,?\s*\)/gu;
        requireValue([...code.matchAll(connects)].length === 1, `${label} must connect only its sockaddr_un backing`);
        code = code.replace(connects, "local_connection()");
        if (ownerIo) code = code.replace(/\bfn\s+connect\s*\(path:\s*&Path,\s*deadline:\s*Instant\)/u, "fn owner_connection(path: &Path, deadline: Instant)");
    }
    if (label === "daemon/src/owner/client.rs") {
        requireValue(code.includes("NativeExecutableRole::Daemon") && code.includes("crate::peer::verify("), "owner client lost signed peer verification");
        code = code.replace(/crate::io::connect\(&root\.join\("run\/owner\.sock"\),\s*deadline\)/gu, "owner_connection()");
    }
    if (label === "daemon/src/owner_client.rs") {
        requireValue(code.includes("crate::owner_peer::verify(&stream, NativeExecutableRole::Daemon)") && code.includes("crate::owner_io::request("), "inject owner IPC lost signed peer or framed request");
        code = code.replace(/crate::owner_io::connect\(\s*&Path::new\(crate::config::RUN_DIR\)\.join\("owner\.sock"\),\s*deadline,?\s*\)/gu, "owner_connection()");
    }
    if (label === "daemon/src/owner/main.rs") {
        requireValue(code.includes('let path = Path::new(config::RUN_DIR).join("owner.sock");') && code.includes("peer::verify_roles("), "owner listener lost fixed path or peer verification");
        code = code.replace(/io::connect\(&path,\s*Instant::now\(\)\s*\+\s*Duration::from_millis\(500\)\)/gu, "owner_connection()").replace(/listener\.accept\(\)/gu, "listener.local_peer()");
    }
    if (["daemon/src/owner/io.rs", "daemon/src/owner/client.rs", "daemon/src/owner/main.rs", "daemon/src/owner/peer.rs", "daemon/src/owner_client.rs", "daemon/src/install_acceptance.rs"].includes(label))
        code = code.replace(/std::os::unix::net\b/gu, "std::os::unix::local_transport");
    if (label === "daemon/src/owner/native/can.rs") {
        requireValue(!/\bAF_(?!NETLINK\b)[A-Za-z0-9_]+/u.test(code), "native CAN introduced another socket family");
        const channel = /libc::socket\(\s*libc::AF_NETLINK,\s*libc::SOCK_DGRAM\s*\|\s*libc::SOCK_CLOEXEC\s*\|\s*libc::SOCK_NONBLOCK,\s*21,?\s*\)/gu;
        requireValue([...code.matchAll(channel)].length === 1, "native CAN requires one fixed nonblocking protocol21 descriptor");
        requireValue([...code.matchAll(/libc::bind\(/gu)].length === 1 && code.includes("address.nl_pid = unsafe { libc::getpid() } as u32;") && code.includes("address.nl_groups = 1;"), "native CAN bind differs from owned PID/group1");
        requireValue(code.includes("libc::MSG_DONTWAIT | libc::MSG_TRUNC") && code.includes("libc::MSG_CTRUNC") && code.includes("sender.nl_pid") && code.includes("sender.nl_groups"), "native CAN lost bounded receive/sender guards");
        requireValue(code.includes("sender_pid != 0") && code.includes("sender_groups != 1") && code.includes("usize::from(bytes[1]) + 2"), "native CAN lost exact frame validation");
        code = code.replace(channel, "can_receive_descriptor()");
    }
    if (label === "daemon/src/cluster_uninstall_transport.rs") {
        requireValue(code.includes('const ENDPOINT: &str = "172.16.100.22:8000";') && code.includes("use voboost_qconn::Qconn;"), "QNX transport endpoint or typed qconn changed");
        requireValue(!/\b(?:TcpListener|UdpSocket|ToSocketAddrs|AF_[A-Z0-9_]+)\b/u.test(code), "QNX transport contains another network primitive");
        const calls = [...code.matchAll(/\bTcpStream\s*::\s*([A-Za-z_][A-Za-z0-9_]*)/gu)];
        requireValue(calls.length === 1 && calls[0][1] === "connect_timeout", "QNX transport must have one bounded connection");
        const bounded = /TcpStream::connect_timeout\(&address,\s*self\.remaining\(\)\?\.min\(Duration::from_secs\(2\)\)\)/gu;
        requireValue([...code.matchAll(bounded)].length === 1 && /let address: SocketAddr = ENDPOINT\s*\.parse\(\)/u.test(code), "QNX connection is not bound to the fixed endpoint/deadline");
        requireValue(!/(?:"|r#*")[^"\n]*(?:\/bin\/(?:sh|bash)|\/usr\/bin\/env)(?:["\s]|$)/u.test(code), "QNX transport introduced a shell executable");
        requireValue(/self\.connect\(\)\?\.launch_receipt\(executable, argv\)/u.test(code) && [...code.matchAll(/\.launch_receipt\(/gu)].length === 1 && [...code.matchAll(/\.launch\(/gu)].length === 1 && code.includes('.launch("/bin/shutdown", &["/bin/shutdown", "-S", "reboot"])'), "QNX execution surface differs from fixed finalizer receipt and shutdown");
        code = code.replace(bounded, "qnx_connection()").replace(/use std::net::\{SocketAddr, TcpStream\};/u,"use FixedQnxTransport;").replace(/stream:\s*TcpStream\b/gu,"stream: FixedQnxStream").replace(/\bfn connect\(&self\)/u, "fn qnx_connection(&self)").replace(/self\.connect\(\)/gu, "self.qnx_connection()");
    }
    if(label === "daemon/src/pw_transport.rs") code = code.replace(/std::net::IpAddr/gu,"LiteralIpAddress");
    if(label === "daemon/src/pw_live.rs") code = code.replace("fn accept(&mut self, wire: Wire, binding: EndpointBinding, lifecycle: i64, now: u64)","fn accept_sample(&mut self, wire: Wire, binding: EndpointBinding, lifecycle: i64, now: u64)").replace("cache.accept(wire, bound, lifecycle, now)","cache.accept_sample(wire, bound, lifecycle, now)");
    if(label === "daemon/src/install_acceptance.rs") code = code.replace(/std::net::Shutdown::Write/gu,"LocalWriteShutdown");
    return code.replace(/libc::syscall\(libc::SYS_gettid\)/gu,"current_thread_id()");
}

function typedCommands(label: string, code: string): { code: string; typed: boolean; structure: boolean } {
    let typed = false, structure = false;
    code = code.replace(/\buse\s+voboost_contract::runtime_owner::\{\s*((?:self|Command|Outcome|Reply|Request|MAX_CONFIG_BYTES|SCHEMA)(?:\s*,\s*(?:self|Command|Outcome|Reply|Request|MAX_CONFIG_BYTES|SCHEMA))*\s*,?)\s*\};/gu, (value, names: string) => {
        if (/\bCommand\b/u.test(names)) typed = true;
        return value.replace(/\bCommand\b/gu, "OwnerProtocolType");
    });
    if (label === "daemon/src/icon_quiescence.rs" && code.includes("use voboost_contract::icon_cache_quiescence::Command;")) {
        typed = true; structure = true; code = code.replace("use voboost_contract::icon_cache_quiescence::Command;", "use IconProtocolType;");
    }
    if (label === "daemon/src/launcher_page.rs") {
        const declaration = /struct Command\s*\{\s*schema_version:\s*u32,\s*operation:\s*String,\s*request_id:\s*String,\s*generation_id:\s*String,\s*catalog_sha256:\s*String,\s*document_generation:\s*i64,\s*\}/u;
        requireValue(declaration.test(code) && code.includes('deny_unknown_fields'), "launcher typed observation command schema differs");
        typed = true; structure = true; code = code.replace(declaration, value => value.replace("Command", "LauncherProtocolType"));
    }
    code = code.replace(/\bvoboost_contract::runtime_owner::Command\b/gu, "OwnerProtocolType");
    return { code, typed, structure };
}

export function auditSource(label: string, source: string): void {
    let code = localTransports(label, stripComments(source));
    const protocol = typedCommands(label, code); code = protocol.code;
    if (label === "daemon/src/canonical_log.rs") {
        requireValue(code.includes('pub const DAEMON_SOCKET: &str = "/data/voboost/run/daemon.sock";') && code.includes("UnixListener::bind(&path)") && code.includes("libc::SO_PEERCRED"), "canonical daemon ingress is not the exact local peer-credential socket");
        requireValue(!/\b(?:TcpStream|TcpListener|UdpSocket|ToSocketAddrs)\b/u.test(code), "canonical app logger contains an external network transport");
        code = code.replace(/\b(?:net|UnixListener|UnixStream)\b/gu, (value) => " ".repeat(value.length));
    }
    if (label === "daemon/src/ota_transport.rs") {
        requireValue(
            code.includes('pub const ABSTRACT_SOCKET_NAME: &str = "voboost.ota.v1";') &&
                code.includes("libc::AF_UNIX") &&
                code.includes("libc::SCM_RIGHTS") &&
                code.includes("libc::SO_PEERCRED"),
            "OTA transport is not the exact local descriptor socket",
        );
        requireValue(
            !/\b(?:TcpStream|TcpListener|UdpSocket|ToSocketAddrs)\b/u.test(code),
            "OTA transport contains an external network transport",
        );
        code = code.replace(/\b(?:net|UnixStream|socket|accept4|listen)\b/gu, (value) =>
            " ".repeat(value.length),
        );
    }
    const helperCommands = [...code.matchAll(INTERNAL_HELPER_COMMAND)];
    requireValue(helperCommands.length <= 1, `duplicate internal inject helper command in ${label}`);
    code = code.replace(INTERNAL_HELPER_COMMAND, (value) => " ".repeat(value.length));
    const constants = new Map([...code.matchAll(/\bconst\s+([A-Za-z_][A-Za-z0-9_]*)\s*:\s*&(?:'static\s+)?str\s*=\s*("(?:\\.|[^"\\])*")\s*;/g)].map((match) => [match[1], decodeString(match[2])]));
    const commandSpans: Array<[number, number]> = [];
    for (const match of code.matchAll(/std\s*::\s*process\s*::\s*Command\s*::\s*new\s*\(\s*("(?:\\.|[^"\\])*"|[A-Za-z_][A-Za-z0-9_]*)/g)) {
        commandSpans.push([match.index!, match.index! + match[0].length]);
        const executable = match[1].startsWith('"') ? decodeString(match[1]) : constants.get(match[1]);
        requireValue(executable && ALLOWED_COMMANDS.has(executable), `unapproved or dynamic process executable ${match[1]} in ${label}`);
    }
    for (const match of code.matchAll(/link_name\s*=\s*((?:b?r)(#{0,16})"[\s\S]*?"\2|b?"(?:\\.|[^"\\])*")/g)) {
        const symbol = decodeString(match[1]);
        requireValue(!NETWORK.has(symbol) && !PROCESS.has(symbol), `forbidden raw FFI link name ${symbol} in ${label}`);
    }
    const withoutLiterals = code.replace(/(?:b?r)(#{0,16})"[\s\S]*?"\1|b?"(?:\\.|[^"\\])*"/g, (value) => " ".repeat(value.length));
    for (const match of withoutLiterals.matchAll(/\b[A-Za-z_][A-Za-z0-9_]*\b/g)) {
        const token = match[0];
        if (token === "Command" && commandSpans.some(([start, end]) => start <= match.index! && match.index! < end)) continue;
        if (token === "Command") {
            const before = withoutLiterals.slice(0, match.index!).trimEnd(), after = withoutLiterals.slice(match.index! + token.length);
            const typePosition = /(?:(?<!:):|[<&(]|->)\s*$/u.test(before);
            const variant = /^\s*::\s*[A-Z][A-Za-z0-9_]*\b/u.test(after);
            const structure = protocol.structure && /^\s*\{/u.test(after);
            requireValue(protocol.typed && (typePosition || variant || structure), `aliased, re-exported or dynamic process Command in ${label}`);
        }
        requireValue(!NETWORK.has(token), `forbidden entry point token ${token} in ${label}`);
        requireValue(!/^(?:SYS|__NR)_(?:socket|connect|accept|listen)/.test(token), `forbidden raw network syscall ${token} in ${label}`);
    }
    requireValue(!/https?\s*:\/\//.test(withoutLiterals), `HTTP client endpoint literal in ${label}`);
    for (const processEntry of PROCESS) {
        requireValue(!new RegExp(`(?:extern[\\s\\S]{0,200}\\bfn\\s+|libc\\s*::\\s*)${processEntry}\\b`).test(withoutLiterals), `forbidden process entry point ${processEntry} in ${label}`);
    }
    if (label === "daemon/build.rs") {
        const literals = [...code.matchAll(/(?:b?r)(#{0,16})"[\s\S]*?"\1|b?"(?:\\.|[^"\\])*"/g)].map((match) => decodeString(match[0]));
        for (const literal of literals) for (const token of literal.match(/[A-Za-z_][A-Za-z0-9_]*/g) ?? []) requireValue(!NETWORK.has(token), `generated source text contains network token ${token}`);
        for (let index = 0; index + 1 < literals.length; index += 1) requireValue(!NETWORK.has(`${literals[index]}${literals[index + 1]}`), "split generated network token");
    }
}

export function splitRegressionCases(): Array<[string,string,string]> {
    const read=(label:string)=>readFileSync(resolve(ROOT,label),"utf8").replace(/#\[cfg\(test\)\]\s*mod\s+[A-Za-z0-9_]+\s*\{[\s\S]*\n\}\n(?!\s*\})/u,"");
    const owner="daemon/src/owner/io.rs",client="daemon/src/owner/client.rs",inject="daemon/src/owner_client.rs",listener="daemon/src/owner/main.rs",qnx="daemon/src/cluster_uninstall_transport.rs",ota="daemon/src/ota_transport.rs";
    const o=read(owner),c=read(client),i=read(inject),l=read(listener),q=read(qnx),t=read(ota);
    const can="daemon/src/owner/native/can.rs", n=read(can);
    return [
        ["CAN remote family",can,n.replaceAll("libc::AF_NETLINK","libc::AF_INET")],
        ["CAN blocking descriptor",can,n.replace(" | libc::SOCK_NONBLOCK","")],
        ["CAN different protocol",can,n.replace("21,","22,")],
        ["CAN foreign group",can,n.replace("address.nl_groups = 1;","address.nl_groups = 2;")],
        ["CAN untrusted sender",can,n.replace("sender_pid != 0","sender_pid != 1")],
        ["CAN truncated frames accepted",can,n.replace("libc::MSG_CTRUNC","0")],
        ["CAN extra remote socket",can,n+' fn x(){ unsafe {libc::socket(libc::AF_INET,libc::SOCK_STREAM,0)}; }'],
        ["owner AF_INET",owner,o.replaceAll("libc::AF_UNIX","libc::AF_INET")],
        ["owner dynamic socket family",owner,o.replace("libc::socket(libc::AF_UNIX,","libc::socket(domain,")],
        ["owner second raw socket",owner,o+' fn x(){ unsafe {libc::socket(libc::AF_UNIX,libc::SOCK_STREAM,0)}; }'],
        ["owner raw socket alias",owner,o+' use libc::socket as make_socket;'],
        ["owner raw FFI link alias",owner,o+' unsafe extern "C" { #[link_name="socket"] fn make_socket(a:i32,b:i32,c:i32)->i32; }'],
        ["owner second raw connect",owner,o+' fn x(){ unsafe {libc::connect(fd,&address as *const _ as *const libc::sockaddr,length)}; }'],
        ["owner extra local stream",owner,o+' fn x(){ let _=UnixStream::pair(); }'],
        ["owner peer signature removed",client,c.replace("crate::peer::verify(","crate::peer::unverified(")],
        ["owner foreign socket path",client,c.replace("run/owner.sock","run/foreign.sock")],
        ["inject foreign socket path",inject,i.replace('"owner.sock"','"foreign.sock"')],
        ["inject peer signature removed",inject,i.replace("crate::owner_peer::verify(","crate::owner_peer::unverified(")],
        ["typed Command process alias",client,c+' use std::process::Command as Process; fn x(){Process::new("curl");}'],
        ["typed Command grouped alias",client,c+' use std::process::{Command as Process}; fn x(){Process::new("curl");}'],
        ["typed Command new method",client,c+' fn x(){Command::new("curl");}'],
        ["typed Command shell process",client,c+' fn x(){std::process::Command::new("/bin/sh");}'],
        ["owner extra listener",listener,l+' fn x(){ let _=UnixListener::bind("/tmp/foreign"); }'],
        ["owner redirected listener",listener,l.replace('join("owner.sock")','join("foreign.sock")')],
        ["QNX foreign endpoint",qnx,q.replace("172.16.100.22:8000","127.0.0.1:8000")],
        ["QNX dynamic endpoint",qnx,q.replace("let address: SocketAddr = ENDPOINT","let address: SocketAddr = environment")],
        ["QNX unbounded connect",qnx,q.replace("TcpStream::connect_timeout","TcpStream::connect")],
        ["QNX second client alias",qnx,q+' use std::net::TcpStream as Other; fn x(){Other::connect_timeout(&other,limit);}'],
        ["QNX extra raw network",qnx,q+' fn x(){ unsafe {libc::socket(libc::AF_INET,libc::SOCK_STREAM,0)}; }'],
        ["QNX extra shell launch",qnx,q+' fn x(wire:Qconn<S,S>){ wire.launch("/bin/sh", &["-c","foreign"]); }'],
        ["QNX escaped shell receipt",qnx,q.replace("launch_receipt(executable, argv)",'launch_receipt("/bin/\\x73h", &["-c","foreign"])')],
        ["OTA foreign family",ota,t.replaceAll("libc::AF_UNIX","libc::AF_INET")],
        ["OTA raw socket alias",ota,t+' use libc::socket as make_socket;'],
        ["OTA raw FFI socket alias",ota,t+' unsafe extern "C" { #[link_name="socket"] fn make_socket(a:i32,b:i32,c:i32)->i32; }'],
        ["generic HTTP client",client,c+' fn x(){ let _ = reqwest::get("https://foreign"); }'],
        ["generic TCP client",client,c+' fn x(){ let _ = std::net::TcpStream::connect("foreign:80"); }'],
        ["generic raw network syscall",owner,o+' fn x(){ unsafe {libc::syscall(libc::SYS_socket,2,1,0)}; }'],
    ];
}
export function auditSplitRegressions(): void {
    for(const [name,label,source] of splitRegressionCases()) {
        let rejected=false;try{auditSource(label,source);}catch{rejected=true;}
        requireValue(rejected,`split transport bypass accepted: ${name}`);
    }
}

export function auditRepository(): void {
    const metadata = JSON.parse(runText("cargo", ["metadata", "--offline", "--locked", "--no-deps", "--format-version", "1"])) as { packages: CargoPackage[] };
    auditDependencies(metadata.packages);
    auditDependencyRegressions(metadata.packages);
    auditProductionSources();
}
export function auditDependencies(packages: CargoPackage[]): void {
    const daemon = packages.find((item) => item.name === "voboost-daemon");
    requireValue(daemon, "daemon package missing from Cargo metadata");
    for (const kind of ["normal", "build", "dev"] as const) {
        const actual = daemon.dependencies.filter((item) => (item.kind ?? "normal") === kind);
        requireValue(JSON.stringify(actual.map((item) => item.name).sort()) === JSON.stringify(Object.keys(EXPECTED[kind]).sort()), `${kind} dependency inventory differs`);
        for (const dependency of actual) {
            const firstParty = dependency.name.startsWith("voboost-");
            if(dependency.name === "voboost-qconn") requireValue(dependency.path === resolve(ROOT,"common/qconn"), "qconn must resolve to the exact first-party transport owner");
            requireValue(
                !dependency.rename && !dependency.optional && dependency.uses_default_features &&
                    (firstParty ? dependency.source === null : dependency.source?.startsWith("registry+")),
                `${kind}.${dependency.name} uses unsupported indirection, source or defaults`,
            );
            requireValue(JSON.stringify([...dependency.features].sort()) === JSON.stringify([...EXPECTED[kind][dependency.name]].sort()), `${kind}.${dependency.name} features differ`);
        }
    }
}
export function auditDependencyRegressions(packages: CargoPackage[]): void {
    const cases:Array<[string,(values:CargoPackage[])=>void]>=[
        ["foreign client dependency",values=>values.find(p=>p.name==="voboost-daemon")!.dependencies.push({name:"reqwest",kind:null,rename:null,optional:false,uses_default_features:true,features:[],source:"registry+https://github.com/rust-lang/crates.io-index"})],
        ["missing qconn owner",values=>{const p=values.find(p=>p.name==="voboost-daemon")!;p.dependencies=p.dependencies.filter(d=>d.name!=="voboost-qconn");}],
        ["old package alias",values=>{values.find(p=>p.name==="voboost-daemon")!.name="voboost-inject";}],
        ...([
            ["qconn foreign path",{path:resolve(ROOT,"foreign/qconn")}],
            ["qconn registry replacement",{source:"registry+https://github.com/rust-lang/crates.io-index"}],
            ["qconn dependency alias",{rename:"foreign_transport"}],
            ["qconn optional dependency",{optional:true}],
            ["qconn changed defaults",{uses_default_features:false}],
            ["qconn extra features",{features:["net"]}],
        ] as Array<[string,Partial<CargoDependency>]>).map(([name,change]):[string,(values:CargoPackage[])=>void]=>[name,values=>Object.assign(values.find(p=>p.name==="voboost-daemon")!.dependencies.find(d=>d.name==="voboost-qconn")!,change)]),
        ["nix network feature",values=>values.find(p=>p.name==="voboost-daemon")!.dependencies.find(d=>d.name==="nix")!.features.push("net")],
    ];
    auditDependencies(packages);
    for(const [name,mutate] of cases) {
        const changed=structuredClone(packages);mutate(changed);let rejected=false;try{auditDependencies(changed);}catch{rejected=true;}
        requireValue(rejected,`dependency bypass accepted: ${name}`);
    }
}

export function auditProductionSources(): void {
    const entrypoint = readFileSync(resolve(ROOT, "daemon/src/main.rs"), "utf8");
    // A separately compiled host driver is outside production only while its
    // owning Rust module declaration is explicitly test-only. Removing that
    // cfg puts the file back into the full token audit.
    const driverIsTestOnly = /#\[cfg\(test\)\]\s*pub mod oem_test_driver;/u.test(entrypoint);
    const driverPath = resolve(ROOT, "daemon/src/oem_test_driver.rs");
    const sourceFiles = files(resolve(ROOT, "daemon")).filter((path) =>
        !path.includes(`${resolve(ROOT, "daemon/tests")}/`) &&
        !(driverIsTestOnly && path === driverPath) &&
        [".rs", ".in", ".tmpl", ".template"].includes(extname(path)));
    sourceFiles.push(resolve(ROOT, "shared/src/uninstall_contract.rs"));
    // The closed-process execution surfaces live in every shared module the
    // daemon links; the generic fixed-process engine itself is audited via
    // the daemon and uninstall translations (arguments are caller-owned).
    sourceFiles.push(resolve(ROOT, "shared/src/installed_apk.rs"));
    sourceFiles.push(resolve(ROOT, "shared/src/lifecycle_file.rs"));
    sourceFiles.push(resolve(ROOT, "shared/src/self_executable.rs"));
    sourceFiles.push(resolve(ROOT, "shared/src/native_executable_signature.rs"));
    for (const path of sourceFiles) {
        // The scan audits production code; Rust #[cfg(test)] unit modules
        // (e.g. child-reaping helpers) are outside its threat model.
        const stripped = readFileSync(path, "utf8").replace(/#\[cfg\(test\)\]\s*mod\s+[A-Za-z0-9_]+\s*\{[\s\S]*\n\}\n(?!\s*\})/u, "");
        auditSource(path.slice(ROOT.length + 1), stripped);
    }
    const helper = 'fn spawn_internal_inject_helper() -> std::io::Result<std::process::Child> { std::process::Command::new("/data/voboost/voboost-inject").arg("--internal-inject-helper").env_clear().env("VOBOOST_HELPER_DEBUG", if log::is_debug() { "1" } else { "0" }).stdin(std::process::Stdio::piped()).stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::piped()).spawn() }';
    auditSource("fixed internal helper", helper);
    for (const [label, hostile] of [
        ["inherited helper environment", helper.replace(".env_clear()", "")],
        ["extra helper environment", helper.replace(".env_clear()", '.env_clear().env("LD_PRELOAD", "foreign.so")')],
        ["foreign helper environment key", helper.replace("VOBOOST_HELPER_DEBUG", "FOREIGN_DEBUG")],
        ["dynamic helper debug value", helper.replace('if log::is_debug() { "1" } else { "0" }', 'std::env::var("DEBUG").unwrap()')],
        ["nonboolean helper debug value", helper.replace('else { "0" }', 'else { "2" }')],
        ["foreign helper executable", helper.replace("/data/voboost/voboost-inject", "curl")],
        ["foreign helper argument", helper.replace("--internal-inject-helper", "--network-client")],
        ["additional helper argument", helper.replace(".env_clear()", '.arg("--extra").env_clear()')],
        ["changed helper stderr", helper.replace(".stderr(std::process::Stdio::piped())", ".stderr(std::process::Stdio::null())")],
        ["external client beside helper", helper + ' fn external() { let _ = std::net::TcpStream::connect("localhost:80"); }'],
        ["duplicate helper command", helper + helper],
    ]) {
        let rejected = false;
        try { auditSource(label, hostile); } catch { rejected = true; }
        requireValue(rejected, `internal helper bypass was accepted: ${label}`);
    }
    const ingress = readFileSync(resolve(ROOT, "daemon/src/canonical_log.rs"), "utf8")
        .replace(/#\[cfg\(test\)\]\s*mod\s+[A-Za-z0-9_]+\s*\{[\s\S]*\n\}\n(?!\s*\})/u, "");
    for (const hostile of [
        ingress.replace("/data/voboost/run/daemon.sock", "/data/voboost/run/foreign.sock"),
        ingress.replaceAll("libc::SO_PEERCRED", "libc::SO_PASSCRED"),
        ingress + "\nfn external() { let _ = std::net::TcpStream::connect(\"localhost:80\"); }\n",
    ]) {
        let rejected = false;
        try { auditSource("daemon/src/canonical_log.rs", hostile); } catch { rejected = true; }
        requireValue(rejected, "daemon ingress accepted a foreign path, missing peer credentials or external transport");
    }
    for (const [label, source] of [
        ["libc socket alias", "use libc::{socket as open_channel};"],
        ["raw extern connect", 'unsafe extern "C" { fn connect(fd: i32) -> i32; }'],
        ["curl process", 'fn x() { std::process::Command::new("curl"); }'],
        ["dynamic helper executable", 'fn spawn_internal_inject_helper() -> std::io::Result<std::process::Child> { std::process::Command::new(path).arg("--internal-inject-helper").env_clear().stdin(std::process::Stdio::piped()).stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::null()).spawn() }'],
        ["dynamic helper argument", 'fn spawn_internal_inject_helper() -> std::io::Result<std::process::Child> { std::process::Command::new("/data/voboost/voboost-inject").arg(arg).env_clear().stdin(std::process::Stdio::piped()).stdout(std::process::Stdio::piped()).stderr(std::process::Stdio::null()).spawn() }'],
    ]) {
        try { auditSource(label, source); } catch { continue; }
        throw new Error(`bypass regression was accepted: ${label}`);
    }
    auditSplitRegressions();
    console.log("no-network-client: exact dependencies/features, source tokens, raw FFI/syscalls and closed process executables OK");
}
if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) main(auditRepository, "no-network-client");
