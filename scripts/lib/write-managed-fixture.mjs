// Generates the pinned managed test fixture from source; run under tsx.
import { writeFile } from "node:fs/promises";

import { buildManagedPeFixture } from "../../src/dotnet/ManagedPe.fixture.js";

await writeFile(process.argv[2], buildManagedPeFixture());
