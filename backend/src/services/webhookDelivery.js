/**
 * src/services/webhookDelivery.js
 * Delivers a signed POST notification to a registered webhook URL.
 * Failures are logged but never thrown — the monitor must not crash.
 *
 * Delivery is deliberately bounded so an attacker-controlled (or simply
 * unresponsive) webhook endpoint cannot exhaust backend resources or hang the
 * monitor. Four boundaries are enforced (see DEFAULT_LIMITS):
 *   - connectTimeoutMs : max time to reach the endpoint and receive the first
 *                        response headers.
 *   - totalTimeoutMs   : hard cap over the whole delivery, including the body
 *                        read and any redirects that are followed.
 *   - maxRedirects     : max number of HTTP redirects we will follow.
 *   - maxResponseBytes : max number of response body bytes we will read.
 *
 * Any delivery that breaches a boundary is aborted immediately and classified
 * as an over-limit error (WebhookResourceLimitError). The caller receives a
 * structured outcome so the abort can be recorded, and network/over-limit
 * errors are logged but never re-thrown.
 */

"use strict";

const http = require("http");
const https = require("https");

const logger = require("../utils/logger");
const { generateWebhookSignature } = require("../utils/webhookSignature");

// ---------------------------------------------------------------------------
// Resource limits
// ---------------------------------------------------------------------------
const DEFAULT_LIMITS = Object.freeze({
  connectTimeoutMs: 5_000,
  totalTimeoutMs: 15_000,
  maxRedirects: 5,
  maxResponseBytes: 1024 * 1024, // 1 MiB
});

const REDIRECT_STATUSES = new Set([301, 302, 303, 307, 308]);

/**
 * Error raised when a delivery breaches a configured resource boundary.
 * Carries a stable `code` so the abort can be classified explicitly:
 *   "connect_timeout" | "total_timeout" | "too_many_redirects" | "response_too_large"
 */
class WebhookResourceLimitError extends Error {
  /**
   * @param {string} message
   * @param {string} code
   * @param {number} limit the limit that was breached
   */
  constructor(message, code, limit) {
    super(message);
    this.name = "WebhookResourceLimitError";
    this.code = code;
    this.limit = limit;
    /** Always true — marks this error as an over-limit abort. */
    this.overLimit = true;
  }
}

/**
 * Merge caller-provided overrides with the built-in defaults.
 * @param {object} [overrides]
 * @returns {typeof DEFAULT_LIMITS}
 */
function resolveLimits(overrides = {}) {
  return {
    connectTimeoutMs:
      overrides.connectTimeoutMs ?? DEFAULT_LIMITS.connectTimeoutMs,
    totalTimeoutMs: overrides.totalTimeoutMs ?? DEFAULT_LIMITS.totalTimeoutMs,
    maxRedirects: overrides.maxRedirects ?? DEFAULT_LIMITS.maxRedirects,
    maxResponseBytes:
      overrides.maxResponseBytes ?? DEFAULT_LIMITS.maxResponseBytes,
  };
}

/**
 * Issue a single bounded HTTP(S) request (redirects are NOT followed here —
 * the caller resolves redirect chains against maxRedirects).
 *
 * Resolves with `{ status, headers, body }` where `body` is a Buffer whose
 * size never exceeds `limits.maxResponseBytes`. Rejects with a
 * WebhookResourceLimitError on connect/total timeout or on an oversized body.
 *
 * @param {string} url
 * @param {{ method: string, headers: object, body?: string, limits: typeof DEFAULT_LIMITS, signal?: AbortSignal }} options
 * @returns {Promise<{ status: number, headers: object, body: Buffer }>}
 */
function requestOnce(url, { method, headers, body, limits, signal }) {
  return new Promise((resolve, reject) => {
    const parsed = new URL(url);
    const transport = parsed.protocol === "https:" ? https : http;

    let connectTimer = null;
    let onTotalAbort = null;
    let settled = false;

    const finish = (fn, arg) => {
      if (settled) return;
      settled = true;
      if (connectTimer) clearTimeout(connectTimer);
      if (onTotalAbort && signal) signal.removeEventListener("abort", onTotalAbort);
      fn(arg);
    };

    const totalTimeoutError = () =>
      new WebhookResourceLimitError(
        "webhook total delivery time exceeded.",
        "total_timeout",
        limits.totalTimeoutMs
      );

    const req = transport.request(parsed, { method, headers }, (res) => {
      // Response headers received — the connect phase is complete.
      if (connectTimer) {
        clearTimeout(connectTimer);
        connectTimer = null;
      }

      const chunks = [];
      let received = 0;

      res.on("data", (chunk) => {
        received += chunk.length;
        if (received > limits.maxResponseBytes) {
          const err = new WebhookResourceLimitError(
            "webhook response exceeded maximum allowed size.",
            "response_too_large",
            limits.maxResponseBytes
          );
          finish(reject, err);
          req.destroy();
          return;
        }
        chunks.push(chunk);
      });

      res.on("end", () =>
        finish(resolve, {
          status: res.statusCode,
          headers: res.headers,
          body: Buffer.concat(chunks),
        })
      );
      res.on("error", (err) => finish(reject, err));
    });

    // Connect timeout: fires if response headers have not arrived in time.
    connectTimer = setTimeout(() => {
      const err = new WebhookResourceLimitError(
        "webhook connection timed out.",
        "connect_timeout",
        limits.connectTimeoutMs
      );
      req.destroy(err);
    }, limits.connectTimeoutMs);

    // Total timeout: aborts the request once the overall deadline passes.
    onTotalAbort = () => req.destroy(totalTimeoutError());
    signal?.addEventListener("abort", onTotalAbort, { once: true });

    req.on("error", (err) => finish(reject, err));

    if (body != null) req.write(body);
    req.end();
  });
}

/**
 * Deliver a webhook notification.
 * Signs the body with HMAC-SHA256 and POSTs to webhook.url, bounding the
 * request with connect/total timeouts, a redirect cap and a response-size cap.
 *
 * Never throws. Returns a structured outcome so the result — including
 * over-limit aborts — can be recorded by the caller.
 *
 * @param {import('./webhookStore').Webhook} webhook
 * @param {import('./paymentMonitor').PaymentPayload} payload
 * @param {{ limits?: Partial<typeof DEFAULT_LIMITS> }} [options]
 * @returns {Promise<{ ok: boolean, status: number|null, error: object|null }>}
 */
async function deliverWebhook(webhook, payload, options = {}) {
  const limits = resolveLimits(options.limits);
  const body = JSON.stringify(payload);
  const sig = generateWebhookSignature(body, webhook.secret);

  const totalController = new AbortController();
  const totalTimer = setTimeout(
    () => totalController.abort(),
    limits.totalTimeoutMs
  );

  try {
    let currentUrl = webhook.url;
    let method = "POST";
    let currentBody = body;
    let redirectsFollowed = 0;

    for (;;) {
      const res = await requestOnce(currentUrl, {
        method,
        headers: {
          "Content-Type": "application/json",
          "Content-Length": Buffer.byteLength(currentBody),
          "X-Stellar-Signature": `sha256=${sig}`,
          "X-Webhook-ID": webhook.id,
        },
        body: currentBody,
        limits,
        signal: totalController.signal,
      });

      const location = res.headers && res.headers.location;
      if (REDIRECT_STATUSES.has(res.status) && location) {
        if (redirectsFollowed >= limits.maxRedirects) {
          throw new WebhookResourceLimitError(
            `webhook exceeded maximum redirects of ${limits.maxRedirects}.`,
            "too_many_redirects",
            limits.maxRedirects
          );
        }
        redirectsFollowed += 1;
        currentUrl = new URL(location, currentUrl).toString();

        // Per the HTTP spec: 303 (and conventionally 301/302) switch to GET
        // without a body, while 307/308 replay the original POST body.
        if (res.status === 303 || res.status === 301 || res.status === 302) {
          method = "GET";
          currentBody = "";
        }
        continue;
      }

      const ok = res.status >= 200 && res.status < 300;
      if (!ok) {
        logger.error(
          { webhookId: webhook.id, url: webhook.url, status: res.status },
          `[webhook] delivery failed for ${webhook.id}: HTTP ${res.status}`
        );
      }
      return {
        ok,
        status: res.status,
        error: ok
          ? null
          : { code: "http_error", status: res.status, message: `HTTP ${res.status}` },
      };
    }
  } catch (err) {
    const code = err && err.code;
    logger.error(
      { webhookId: webhook.id, url: webhook.url, code, err: err },
      `[webhook] delivery failed for ${webhook.id}: ${err.message}`
    );
    return {
      ok: false,
      status: null,
      error: {
        code: code || "network_error",
        message: err.message || "webhook delivery failed",
        overLimit: Boolean(err && err.overLimit),
      },
    };
  } finally {
    clearTimeout(totalTimer);
  }
}

module.exports = {
  deliverWebhook,
  requestOnce,
  WebhookResourceLimitError,
  DEFAULT_LIMITS,
  resolveLimits,
};