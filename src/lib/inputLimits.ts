/**
 * Size limits for tool arguments. Oversized inputs are rejected before any
 * search, file access or outbound request happens.
 *
 *   MCP_MAX_QUERY_LENGTH  max characters of free-text `query` (default 2000)
 *   MCP_MAX_ID_LENGTH     max characters of `id` / `library_id` / `serviceId` (default 1024)
 */

function intEnv(name: string, fallback: number): number {
  const parsed = Number.parseInt(process.env[name] ?? "", 10);
  return Number.isSafeInteger(parsed) && parsed > 0 ? parsed : fallback;
}

export const INPUT_LIMITS = {
  query: intEnv("MCP_MAX_QUERY_LENGTH", 2000),
  id: intEnv("MCP_MAX_ID_LENGTH", 1024),
  code: 200_000, // abap_lint source code (the HTTP body limit also applies)
  string: 1000, // any other string argument
  arrayItems: 100,
  arrayItemLength: 200,
  uri: 2048,
};

const ID_ARGS = new Set(["id", "library_id", "topic", "serviceId", "object_name"]);

function limitFor(key: string): number {
  if (key === "query" || key === "error_message") return INPUT_LIMITS.query;
  if (key === "code") return INPUT_LIMITS.code;
  if (ID_ARGS.has(key)) return INPUT_LIMITS.id;
  return INPUT_LIMITS.string;
}

/** Returns an error message when an argument exceeds its limit, else null. */
export function validateToolArguments(args: unknown): string | null {
  if (args === undefined || args === null) return null;
  if (typeof args !== "object" || Array.isArray(args)) return "Invalid arguments: expected an object.";
  for (const [key, value] of Object.entries(args as Record<string, unknown>)) {
    if (typeof value === "string") {
      const max = limitFor(key);
      if (value.length > max) return `Argument '${key}' is too long (${value.length} > ${max} characters).`;
    } else if (Array.isArray(value)) {
      if (value.length > INPUT_LIMITS.arrayItems) {
        return `Argument '${key}' has too many items (${value.length} > ${INPUT_LIMITS.arrayItems}).`;
      }
      for (const item of value) {
        if (typeof item === "string" && item.length > INPUT_LIMITS.arrayItemLength) {
          return `Argument '${key}' contains an item that is too long (> ${INPUT_LIMITS.arrayItemLength} characters).`;
        }
        if (item !== null && typeof item === "object") return `Argument '${key}' must contain only scalar values.`;
      }
    } else if (value !== null && typeof value === "object") {
      return `Argument '${key}' must not be an object.`;
    }
  }
  return null;
}
