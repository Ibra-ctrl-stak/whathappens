// capture.json: what a live capture's pcapng cannot say about itself (how dumpcap ran), saved next
// to capture.pcapng. Bound to that file by size and SHA-256, so it is never applied to another one.
// Only what the diagnostics need: no dumpcap path, command line, PIDs or raw stderr.
import { sha256 } from '../session.js';
import { STOP_REASONS } from './dumpcap.js';

export const CAPTURE_RUN_FORMAT = 1;
export const CAPTURE_RUN_FILE = 'capture.json';
export const CAPTURE_RUN_MAX_BYTES = 64 * 1024;
const MAX_WARNINGS = 32;
const MAX_TEXT = 1000;

/** The capture.json content for a live capture: { iface, stopReason, warnings } and its pcapng bytes. */
export function captureRunRecord({ iface, stopReason, warnings }, data) {
  return {
    format: CAPTURE_RUN_FORMAT, tool: 'dumpcap', iface, stopReason, warnings: [...warnings],
    capture: { file: 'capture.pcapng', bytes: data.length, sha256: sha256(data) },
  };
}

const text = (v) => typeof v === 'string' && v.length <= MAX_TEXT;

/**
 * capture.json text + the pcapng it should describe -> a run for captureCompleteness():
 * { status: 'saved', iface, stopReason, warnings } or { status: 'invalid' | 'mismatch', problem }.
 */
export function readCaptureRun(json, data) {
  let run;
  try { run = JSON.parse(json); } catch { return { status: 'invalid', problem: `${CAPTURE_RUN_FILE} is not valid JSON` }; }
  const valid = run && run.format === CAPTURE_RUN_FORMAT && run.tool === 'dumpcap' && text(run.iface)
    && STOP_REASONS.includes(run.stopReason) && Array.isArray(run.warnings) && run.warnings.length <= MAX_WARNINGS
    && run.warnings.every(text) && Number.isSafeInteger(run.capture?.bytes) && /^[0-9a-f]{64}$/.test(run.capture?.sha256 ?? '');
  if (!valid) return { status: 'invalid', problem: `${CAPTURE_RUN_FILE} is not a format ${CAPTURE_RUN_FORMAT} capture record` };
  if (run.capture.bytes !== data.length || run.capture.sha256 !== sha256(data)) {
    return { status: 'mismatch', problem: `${CAPTURE_RUN_FILE} describes another capture file (size or SHA-256 differs)` };
  }
  return { status: 'saved', iface: run.iface, stopReason: run.stopReason, warnings: [...run.warnings] };
}
