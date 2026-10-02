/** Identify the walkthrough dump by the server's hash of the completed upload. */
export const EXAMPLE_DUMP_SHA256 =
  "777d71d7106e5ded19592c075058da12049bfcd658221e70f0579ad4bbd9cff4";

export function isExampleDump(file: { name: string; sha256?: string | null }): boolean {
  return (file.sha256 ?? "").toLowerCase() === EXAMPLE_DUMP_SHA256;
}
