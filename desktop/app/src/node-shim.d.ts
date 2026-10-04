// Tests read source files with node:fs; only this one call is needed, so
// declare it instead of pulling in all of @types/node.
declare module "node:fs" {
  export function readFileSync(path: string | URL, encoding: "utf8"): string;
}
