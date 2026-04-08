export interface Env {
  REPO_BUCKET: R2Bucket;
  ALPINE_PREFIX?: string;
  DIRTY_PREFIX?: string;
}

type R2ObjectEvent = {
  action?: string;
  eventTime?: string;
  object?: {
    key?: string;
    eTag?: string;
    size?: number;
  };
};

function normalizePrefix(value: string, fallback: string): string {
  const trimmed = value.trim().replace(/^\/+|\/+$/g, "");
  if (!trimmed) {
    return fallback;
  }
  return `${trimmed}/`;
}

function markerKeyForEvent(
  event: R2ObjectEvent,
  alpinePrefix: string,
  dirtyPrefix: string,
): { markerKey: string; objectKey: string } | null {
  const objectKey = event.object?.key;
  if (!objectKey || typeof objectKey !== "string") {
    return null;
  }

  if (!objectKey.startsWith(alpinePrefix)) {
    return null;
  }

  if (!objectKey.endsWith(".apk")) {
    return null;
  }

  const lastSlash = objectKey.lastIndexOf("/");
  if (lastSlash <= 0) {
    return null;
  }

  const repoPath = objectKey.slice(0, lastSlash);
  return {
    markerKey: `${dirtyPrefix}${repoPath}.dirty`,
    objectKey,
  };
}

export default {
  async queue(batch: MessageBatch<R2ObjectEvent>, env: Env): Promise<void> {
    const alpinePrefix = normalizePrefix(env.ALPINE_PREFIX ?? "alpine/", "alpine/");
    const dirtyPrefix = normalizePrefix(env.DIRTY_PREFIX ?? "_state/dirty/", "_state/dirty/");

    const updates = new Map<string, R2ObjectEvent>();

    for (const message of batch.messages) {
      const event = message.body;
      const marker = markerKeyForEvent(event, alpinePrefix, dirtyPrefix);
      if (!marker) {
        continue;
      }
      updates.set(marker.markerKey, event);
    }

    if (updates.size === 0) {
      return;
    }

    const now = new Date().toISOString();
    const writes: Promise<unknown>[] = [];

    for (const [markerKey, event] of updates.entries()) {
      const payload = JSON.stringify({
        dirty: true,
        updated_at: event.eventTime ?? now,
        action: event.action ?? "unknown",
        object_key: event.object?.key ?? null,
        object_etag: event.object?.eTag ?? null,
      });

      writes.push(
        env.REPO_BUCKET.put(markerKey, payload, {
          httpMetadata: {
            contentType: "application/json",
          },
        }),
      );
    }

    await Promise.all(writes);
  },
};
