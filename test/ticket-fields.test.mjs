// NewSessionTicket (RFC 8446 §4.6.1) fields, checked against Wireshark.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { loadSession } from '../src/session.js';
import { decryptSession } from '../src/tls/decrypt.js';
import { parseHandshake } from '../src/tls/handshake-fields.js';
import { find } from '../src/fields.js';

const json = (name) => JSON.parse(readFileSync(new URL(`./fixtures/github-robots/${name}`, import.meta.url), 'utf8'));
const expected = json('expected.json').tls.newSessionTickets;
const { server } = decryptSession(loadSession(json('session.json')).tls);
const NEW_SESSION_TICKET = 4;
const tickets = server.messages.filter((m) => m.type === NEW_SESSION_TICKET).map((m) => parseHandshake(server.handshake, m));

test('one field tree per ticket, none broken', () => {
  assert.equal(tickets.length, expected.length);
  assert.ok(tickets.every((t) => t.problem === undefined && t.children.length > 0));
});

test('lifetime, age_add, nonce and ticket size match Wireshark', () => {
  tickets.forEach((t, i) => {
    assert.equal(find(t, 'ticket_lifetime').value, expected[i].lifetime);
    assert.equal(find(t, 'ticket_age_add').value, expected[i].ageAdd);
    assert.equal(find(t, 'ticket_nonce').value, expected[i].nonce);
    assert.equal(find(t, 'ticket').length - 2, expected[i].ticketLength); // minus the u16 length
  });
});

test('the ticket ends with its (possibly empty) extensions block', () => {
  for (const t of tickets) {
    const ext = find(t, 'extensions');
    assert.equal(ext.offset + ext.length, t.offset + t.length);
  }
});
