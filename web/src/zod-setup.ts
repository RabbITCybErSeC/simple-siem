import { z } from "zod";

// Zod probes Function("") for its optional JIT; the production CSP blocks eval.
z.config({ jitless: true });
