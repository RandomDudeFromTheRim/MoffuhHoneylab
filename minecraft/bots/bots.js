// Three fake "regulars" for the bait Minecraft server (zgw-mcbots.service).
// They connect directly to the configured local bait server, wander, greet newcomers, and can
// answer chat through an optional OpenAI-compatible endpoint. Keep this service on the bait host.
// mcbait.py leaves their names out of the wreck stats (BOTS there must match NAMES here).
"use strict";
const mineflayer = require("mineflayer");
const { pathfinder, Movements, goals } = require("mineflayer-pathfinder");

const HOST = process.env.MCBAIT_HOST || "127.0.0.1";
const PORT = Number(process.env.MCBAIT_PORT || 25567);
const VERSION = "1.21.4";
// Configure LLM values only in a protected EnvironmentFile; no LLM call is made without all settings.
const API_KEY = process.env.ROUTERAI_API_KEY || "";
const BASE = process.env.HONEYPOT_LLM_BASE_URL || "";
const MODEL = process.env.HONEYPOT_LLM_MODEL || "";

const PERSONAS = {
  LabPlayerOne: { aliases: ["builder", "castle"],
                  who: "a casual builder who talks about a half-finished castle near spawn" },
  LabPlayerTwo: { aliases: ["miner", "tools"],
                  who: "a casual player who likes exploring caves and gathering materials" },
  LabFarmer: { aliases: ["farm", "wheat"],
               who: "a quiet player who farms wheat and speaks briefly" },
};
const NAMES = Object.keys(PERSONAS);
const GREETS = ["yo", "hey", "o/", "hi", "sup", "hello new guy"];

// LLM budget: no more than this many calls per hour across all bots (dirt cheap, but bots can be spammed)
const MAX_CALLS_PER_HOUR = 60;
const MAX_LLM_RESPONSE_BYTES = 1 << 20;
let calls = [];
const history = [];          // chat lines seen on the server, once each: "name: text"
const online = new Map();    // name -> bot, while logged in and spawned
const greeted = new Map();   // visitor -> time one bot greeted them
let lastSeen = "";           // dedupe: every bot receives every chat line
let lastReplyAt = 0;         // unprompted replies at most every 6 s overall

const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const rand = (a, b) => a + Math.random() * (b - a);
const pick = (xs) => xs[Math.floor(Math.random() * xs.length)];
const log = (...a) => console.log(new Date().toISOString().slice(11, 19), ...a);

function remember(line) {
  history.push(String(line).slice(0, 300));
  if (history.length > 50) history.splice(0, history.length - 50);
}

async function llm(name, situation) {
  const now = Date.now();
  calls = calls.filter((t) => now - t < 3600e3);
  if (!API_KEY || !BASE || !MODEL || calls.length >= MAX_CALLS_PER_HOUR) return null;
  calls.push(now);
  const prompt =
    `You are ${name}, ${PERSONAS[name].who}, on a small Minecraft survival server. You type in game chat. ` +
    `Write ONE chat message, under 70 characters, lowercase, casual, like a real player; typos are fine. ` +
    `No emoji, no hashtags, no quotes around it, no exclamation spam, nothing corny, never start with '/'. ` +
    `Never say or hint that you are a bot or an AI; if accused, brush it off like a human would. ` +
    `Stay in Minecraft; don't share personal info; don't be hateful.\n\n` +
    `Recent chat:\n${history.slice(-10).join("\n") || "(quiet)"}\n\nSituation: ${situation}\nYour message:`;
  const t0 = Date.now();
  try {
    const r = await fetch(`${BASE}/chat/completions`, {
      method: "POST",
      headers: { "Content-Type": "application/json", Authorization: `Bearer ${API_KEY}` },
      body: JSON.stringify({ model: MODEL, messages: [{ role: "user", content: prompt }], max_tokens: 2500 }),
      signal: AbortSignal.timeout(60000),
    });
    if (!r.body) throw new Error("LLM response has no body");
    const reader = r.body.getReader();
    const chunks = [];
    let size = 0;
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      size += value.byteLength;
      if (size > MAX_LLM_RESPONSE_BYTES) {
        await reader.cancel();
        throw new Error("LLM response exceeded 1 MiB");
      }
      chunks.push(Buffer.from(value));
    }
    const j = JSON.parse(Buffer.concat(chunks, size).toString("utf8"));
    let text = ((j.choices || [])[0] || {}).message?.content || "";
    text = text.split("\n").map((s) => s.trim()).filter(Boolean)[0] || "";
    text = text.replace(/^["'`]+|["'`]+$/g, "").replace(new RegExp(`^${name}:\\s*`, "i"), "").replace(/^\/+/, "");
    log(name, `llm ${((Date.now() - t0) / 1000).toFixed(1)}s:`, text || `(empty, status ${r.status})`);
    return text.slice(0, 100) || null;
  } catch (e) {
    log(name, "llm failed:", e.name);
    return null;
  }
}

function say(name, text) {
  const bot = online.get(name);
  if (!text || !bot || !bot.entity) return;
  bot.chat(text);
  remember(`${name}: ${text}`);
}

// Every bot hears every chat line; only the first copy is handled, and one bot answers it.
async function onChat(from, message) {
  if (NAMES.includes(from)) return;
  from = String(from).slice(0, 32);
  message = String(message).slice(0, 200);
  const key = `${from}\u0000${message}`;
  if (key === lastSeen) return;
  lastSeen = key;
  remember(`${from}: ${message}`);
  const low = message.toLowerCase();
  const named = NAMES.filter((n) => online.has(n) && PERSONAS[n].aliases.some((a) => low.includes(a)));
  let who = named[0];
  if (!who) {
    if (Date.now() - lastReplyAt < 6000 || Math.random() > 0.5 || !online.size) return;
    who = pick([...online.keys()]);
  }
  lastReplyAt = Date.now();
  const [text] = await Promise.all([
    llm(who, `${from} just said "${message}"${named.length ? " to you" : ""}. Reply.`),
    sleep(rand(1500, 3500)),   // "typing"
  ]);
  say(who, text);
}

async function onJoin(visitor) {
  if (NAMES.includes(visitor) || Date.now() - (greeted.get(visitor) || 0) < 600e3 || !online.size) return;
  greeted.set(visitor, Date.now());
  if (greeted.size > 1000) greeted.delete(greeted.keys().next().value);
  await sleep(rand(3000, 9000));
  const who = pick([...online.keys()]);
  say(who, Math.random() < 0.5 ? pick(GREETS) : await llm(who, `${visitor} just joined the server. Greet them or not.`));
}

function startBot(name) {
  const bot = mineflayer.createBot({ host: HOST, port: PORT, username: name, version: VERSION, auth: "offline",
                                     hideErrors: true });
  bot.loadPlugin(pathfinder);
  let alive = true, home = null, spawnedAt = 0, threat = null;

  bot.once("spawn", () => {
    log(name, "spawned");
    spawnedAt = Date.now();
    online.set(name, bot);
    home = bot.entity.position.clone();
    const moves = new Movements(bot);
    moves.canDig = false;          // don't wreck the world ourselves
    moves.allow1by1towers = false;
    bot.pathfinder.setMovements(moves);
    wander();
    lookAround();
  });

  async function wander() {
    while (alive) {
      await sleep(rand(15000, 50000));
      if (!alive || !bot.entity || !home) continue;
      const g = new goals.GoalNear(home.x + rand(-18, 18), home.y, home.z + rand(-18, 18), 2);
      try { await bot.pathfinder.goto(g); } catch { /* blocked: try again later */ }
      if (Math.random() < 0.15) { bot.setControlState("jump", true); await sleep(400); bot.setControlState("jump", false); }
    }
  }

  async function lookAround() {
    while (alive) {
      await sleep(1500);
      if (!bot.entity) continue;
      const p = bot.nearestEntity((e) => e.type === "player" && e.position.distanceTo(bot.entity.position) < 10);
      if (p) bot.lookAt(p.position.offset(0, 1.6, 0)).catch(() => {});
    }
  }

  bot.on("chat", (from, message) => onChat(from, message));

  // the tab list replays everyone already online right after our own login: not a real join
  bot.on("playerJoined", (p) => { if (spawnedAt && Date.now() - spawnedAt > 10000) onJoin(p.username); });

  // remember which visitor was next to us when we got hurt, so a death can be blamed on them
  bot.on("health", () => {
    if (!bot.entity) return;
    const p = bot.nearestEntity((e) => e.type === "player" && !NAMES.includes(e.username) &&
                                       e.position.distanceTo(bot.entity.position) < 6);
    if (p) threat = { who: p.username, at: Date.now() };
  });

  bot.on("death", async () => {
    log(name, "died", threat ? `(${threat.who} nearby)` : "");
    if (!threat || Date.now() - threat.at > 10000) return;   // fell, drowned...: not worth a word
    const who = threat.who;
    threat = null;
    await sleep(rand(2000, 5000));
    say(name, await llm(name, `${who} just killed you. React.`));
  });

  bot.on("kicked", (reason) => log(name, "kicked:", String(reason).slice(0, 120)));
  bot.on("error", (e) => log(name, "error:", e.code || e.message));
  bot.on("end", (reason) => {
    alive = false;
    online.delete(name);
    log(name, "disconnected:", reason, "- reconnecting soon");
    setTimeout(() => startBot(name), rand(30000, 60000));   // server wipes take ~60 s
  });
}

log(`starting ${NAMES.join(", ")} -> ${HOST}:${PORT}, llm ${API_KEY && BASE && MODEL ? MODEL : "OFF (not configured)"}`);
NAMES.forEach((n, i) => setTimeout(() => startBot(n), i * 8000 + rand(0, 3000)));
