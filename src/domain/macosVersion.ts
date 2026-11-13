/** Components of a complete dotted numeric macOS version, such as `12.4.1`. */
const macosVersionComponents = (
  version: string | undefined,
): readonly number[] | undefined => {
  if (version === undefined || !/^\d+(?:\.\d+)*$/u.test(version))
    return undefined;
  const components = version.split(".").map(Number);
  return components.every((component) => Number.isSafeInteger(component))
    ? components
    : undefined;
};

/** Parse the major release only when the complete macOS probe is a dotted numeric version. */
export const macosMajorVersion = (
  version: string | undefined,
): number | undefined => macosVersionComponents(version)?.[0];
