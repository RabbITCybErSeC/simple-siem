import reactHooks from "eslint-plugin-react-hooks";
import tseslint from "typescript-eslint";

export default tseslint.config(
  { ignores: ["dist", "src/components/ui", "src/lib/utils.ts"] },
  ...tseslint.configs.recommended,
  reactHooks.configs.flat.recommended,
);
