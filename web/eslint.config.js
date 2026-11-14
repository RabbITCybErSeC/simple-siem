import reactHooks from "eslint-plugin-react-hooks";
import tseslint from "typescript-eslint";

export default tseslint.config(
  { ignores: ["dist", "test-results", "playwright-report", "src/components/ui"] },
  ...tseslint.configs.recommended,
  reactHooks.configs.flat.recommended,
);
