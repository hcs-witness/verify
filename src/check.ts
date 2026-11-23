/**
 * Évaluateur JSON Schema minimal : couvre exactement les constructions
 * des schémas exportés (type, const, anyOf, properties, required,
 * additionalProperties, patternProperties, items, pattern, minLength,
 * minimum, uniqueItems). Ce n'est PAS un moteur JSON Schema général — les schémas
 * sont fixes et internes au format de preuve HCS Witness.
 */

export interface JsonSchema {
  readonly type?: string;
  readonly const?: unknown;
  readonly anyOf?: readonly JsonSchema[];
  readonly properties?: Record<string, JsonSchema>;
  readonly required?: readonly string[];
  readonly additionalProperties?: boolean;
  readonly patternProperties?: Record<string, JsonSchema>;
  readonly items?: JsonSchema;
  /** Unicité des items — couvre les items primitifs (chaînes). */
  readonly uniqueItems?: boolean;
  readonly pattern?: string;
  readonly minLength?: number;
  readonly minimum?: number;
}

const regexCache = new Map<string, RegExp>();

function regex(pattern: string): RegExp {
  let r = regexCache.get(pattern);
  if (r === undefined) {
    r = new RegExp(pattern);
    regexCache.set(pattern, r);
  }
  return r;
}

function isObject(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

function checkType(type: string, value: unknown): boolean {
  switch (type) {
    case "object":
      return isObject(value);
    case "array":
      return Array.isArray(value);
    case "string":
      return typeof value === "string";
    case "integer":
      return typeof value === "number" && Number.isInteger(value);
    case "number":
      return typeof value === "number";
    case "boolean":
      return typeof value === "boolean";
    case "null":
      return value === null;
    default:
      return false;
  }
}

export function checkSchema(schema: JsonSchema, value: unknown): boolean {
  if (schema.anyOf !== undefined) {
    return schema.anyOf.some((s) => checkSchema(s, value));
  }
  if (schema.const !== undefined && value !== schema.const) {
    return false;
  }
  if (schema.type !== undefined && !checkType(schema.type, value)) {
    return false;
  }
  if (typeof value === "string") {
    if (schema.minLength !== undefined && value.length < schema.minLength) {
      return false;
    }
    if (schema.pattern !== undefined && !regex(schema.pattern).test(value)) {
      return false;
    }
  }
  if (typeof value === "number") {
    if (schema.minimum !== undefined && value < schema.minimum) {
      return false;
    }
  }
  if (Array.isArray(value)) {
    const items = schema.items;
    if (
      items !== undefined &&
      !value.every((item) => checkSchema(items, item))
    ) {
      return false;
    }
    if (schema.uniqueItems === true && new Set(value).size !== value.length) {
      return false;
    }
  }
  if (isObject(value)) {
    for (const key of schema.required ?? []) {
      if (!(key in value)) return false;
    }
    const props = schema.properties ?? {};
    const patterns = Object.entries(schema.patternProperties ?? {}).map(
      ([p, s]) => ({ r: regex(p), s }),
    );
    const strict = schema.additionalProperties === false;
    for (const [key, member] of Object.entries(value)) {
      const known = Object.hasOwn(props, key);
      let matched = false;
      if (known) {
        const sub = props[key];
        if (sub !== undefined && !checkSchema(sub, member)) {
          return false;
        }
      }
      for (const { r, s } of patterns) {
        if (r.test(key)) {
          matched = true;
          if (!checkSchema(s, member)) return false;
        }
      }
      if (!known && !matched && strict) {
        return false;
      }
    }
  }
  return true;
}
