#!/usr/bin/env bun
/**
 * Run locally to capture Twitter session cookies.
 * Usage: bun run scripts/capture-twitter-cookies.ts
 *
 * Then set the output as a Fly secret:
 *   fly secrets set TWITTER_COOKIES='<output>'
 */
import { Scraper } from 'agent-twitter-client';

const username = process.env.TWITTER_USERNAME ?? '';
const password = process.env.TWITTER_PASSWORD ?? '';
const email    = process.env.TWITTER_EMAIL    ?? '';

if (!username || !password) {
  console.error('Set TWITTER_USERNAME and TWITTER_PASSWORD in your .env first');
  process.exit(1);
}

console.log(`Logging in as @${username}...`);
const scraper = new Scraper();
await scraper.login(username, password, email || undefined);

const cookies = await scraper.getCookies();
const cookieJson = JSON.stringify(cookies.map((c) => c.toJSON()));

console.log('\n✅ Cookies captured. Run this command:\n');
console.log(`fly secrets set TWITTER_COOKIES='${cookieJson}'\n`);
