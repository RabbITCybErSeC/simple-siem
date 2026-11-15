import { describe, expect, it } from "vitest";
import stylesheet from "../index.css?raw";

type Theme = "light" | "dark";

interface Oklch {
  l: number;
  c: number;
  h: number;
  alpha: number;
}

/** Gamma-encoded sRGB, each channel in [0, 1]. */
interface Rgb {
  r: number;
  g: number;
  b: number;
}

const tokensByTheme: Record<Theme, Map<string, Oklch>> = {
  light: parseThemeTokens(stylesheet, ":root"),
  dark: parseThemeTokens(stylesheet, ".dark"),
};

const pairsAt45 = [
  ["foreground", "background"],
  ["muted-foreground", "background"],
  ["primary", "background"],
  ["card-foreground", "card"],
  ["popover-foreground", "popover"],
  ["muted-foreground", "muted"],
  ["primary-foreground", "primary"],
  ["secondary-foreground", "secondary"],
  ["accent-foreground", "accent"],
  ["severity-high-foreground", "severity-high"],
  ["severity-medium-foreground", "severity-medium"],
  ["severity-low-foreground", "severity-low"],
  ["severity-high", "background"],
  ["severity-medium", "background"],
  ["severity-low", "background"],
] as const;

const pairsAt3 = [["destructive", "background"]] as const;

// The vendored controls draw the ring at half alpha until the unlayered rule
// in index.css raises it to the full token.
const FULL_ALPHA_RING_RULE =
  /\[data-slot\]:focus-visible:not\(\[aria-invalid="true"\]\)\s*\{[^}]*--tw-ring-color:\s*var\(--ring\)/;
const ringAlpha = FULL_ALPHA_RING_RULE.test(stylesheet) ? 1 : 0.5;

const cases = (["light", "dark"] as const).flatMap((theme) => [
  ...pairsAt45.map(([foreground, background]) => ({
    label: `${theme}: ${foreground} on ${background}`,
    theme,
    foreground,
    background,
    minimum: 4.5,
  })),
  ...pairsAt3.map(([foreground, background]) => ({
    label: `${theme}: ${foreground} on ${background}`,
    theme,
    foreground,
    background,
    minimum: 3,
  })),
]);

describe("design token contrast", () => {
  it.each(cases)(
    "$label",
    ({ label, theme, foreground, background, minimum }) => {
      const ratio = contrastRatio(
        resolveToken(theme, foreground),
        resolveToken(theme, background),
      );

      expect(
        ratio,
        `${label} is ${ratio.toFixed(2)}:1, needs at least ${minimum}:1`,
      ).toBeGreaterThanOrEqual(minimum);
    },
  );
});

describe("focus ring contrast as rendered", () => {
  it.each(["light", "dark"] as const)(
    "%s: ring on background",
    (theme) => {
      const background = resolveToken(theme, "background");
      const ring = compositeOver(
        resolveToken(theme, "ring"),
        background,
        ringAlpha,
      );
      const ratio = contrastRatio(ring, background);

      expect(
        ratio,
        `${theme}: ring on background at ${ringAlpha * 100}% alpha is ${ratio.toFixed(2)}:1, needs at least 3:1`,
      ).toBeGreaterThanOrEqual(3);
    },
  );
});

describe("OKLCH to sRGB conversion", () => {
  it("maps oklch(1 0 0) to white", () => {
    const white = oklchToSrgb({ l: 1, c: 0, h: 0, alpha: 1 });

    expect(white.r).toBeCloseTo(1, 5);
    expect(white.g).toBeCloseTo(1, 5);
    expect(white.b).toBeCloseTo(1, 5);
    expect(relativeLuminance(white)).toBeCloseTo(1, 5);
    expect(contrastRatio(white, white)).toBeCloseTo(1, 5);
  });

  it("maps oklch(0 0 0) to black", () => {
    const black = oklchToSrgb({ l: 0, c: 0, h: 0, alpha: 1 });

    expect(black.r).toBeCloseTo(0, 5);
    expect(black.g).toBeCloseTo(0, 5);
    expect(black.b).toBeCloseTo(0, 5);
    expect(relativeLuminance(black)).toBeCloseTo(0, 5);
  });

  it("measures white on black as 21:1", () => {
    const white = oklchToSrgb({ l: 1, c: 0, h: 0, alpha: 1 });
    const black = oklchToSrgb({ l: 0, c: 0, h: 0, alpha: 1 });

    expect(contrastRatio(white, black)).toBeCloseTo(21, 2);
  });

  it("composites a translucent colour over its background", () => {
    const white = oklchToSrgb({ l: 1, c: 0, h: 0, alpha: 1 });
    const black = oklchToSrgb({ l: 0, c: 0, h: 0, alpha: 1 });

    const composite = compositeOver(white, black, 0.5);

    expect(composite.r).toBeCloseTo(0.5, 5);
    expect(composite.g).toBeCloseTo(0.5, 5);
    expect(composite.b).toBeCloseTo(0.5, 5);
  });
});

function parseThemeTokens(source: string, selector: string): Map<string, Oklch> {
  const escapedSelector = selector.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
  const block = new RegExp(`${escapedSelector}\\s*\\{([^}]*)\\}`).exec(source);
  if (!block) {
    throw new Error(`src/index.css is missing the ${selector} block`);
  }

  const tokens = new Map<string, Oklch>();
  const tokenPattern =
    /(--[\w-]+)\s*:\s*oklch\(\s*([\d.]+)\s+([\d.]+)\s+([\d.]+)\s*(?:\/\s*([\d.]+)%)?\s*\)/g;

  for (const match of block[1].matchAll(tokenPattern)) {
    tokens.set(match[1], {
      l: Number(match[2]),
      c: Number(match[3]),
      h: Number(match[4]),
      alpha: match[5] === undefined ? 1 : Number(match[5]) / 100,
    });
  }

  return tokens;
}

function resolveToken(theme: Theme, name: string): Rgb {
  const tokens = tokensByTheme[theme];
  const token = tokens.get(`--${name}`);
  if (!token) {
    throw new Error(`Theme "${theme}" is missing the --${name} token`);
  }

  const color = oklchToSrgb(token);
  if (token.alpha === 1) {
    return color;
  }

  const background = tokens.get("--background");
  if (!background) {
    throw new Error(`Theme "${theme}" is missing the --background token`);
  }

  return compositeOver(color, oklchToSrgb(background), token.alpha);
}

function oklchToSrgb({ l, c, h }: Oklch): Rgb {
  const hueRadians = (h * Math.PI) / 180;
  const a = c * Math.cos(hueRadians);
  const b = c * Math.sin(hueRadians);

  const lPrime = l + 0.3963377774 * a + 0.2158037573 * b;
  const mPrime = l - 0.1055613458 * a - 0.0638541728 * b;
  const sPrime = l - 0.0894841775 * a - 1.291485548 * b;

  const lCube = lPrime ** 3;
  const mCube = mPrime ** 3;
  const sCube = sPrime ** 3;

  const linear = {
    r: 4.0767416621 * lCube - 3.3077115913 * mCube + 0.2309699292 * sCube,
    g: -1.2684380046 * lCube + 2.6097574011 * mCube - 0.3413193965 * sCube,
    b: -0.0041960863 * lCube - 0.7034186147 * mCube + 1.707614701 * sCube,
  };

  return {
    r: gammaEncode(clamp(linear.r)),
    g: gammaEncode(clamp(linear.g)),
    b: gammaEncode(clamp(linear.b)),
  };
}

function compositeOver(color: Rgb, background: Rgb, alpha: number): Rgb {
  return {
    r: alpha * color.r + (1 - alpha) * background.r,
    g: alpha * color.g + (1 - alpha) * background.g,
    b: alpha * color.b + (1 - alpha) * background.b,
  };
}

function relativeLuminance({ r, g, b }: Rgb): number {
  return 0.2126 * gammaDecode(r) + 0.7152 * gammaDecode(g) + 0.0722 * gammaDecode(b);
}

function contrastRatio(first: Rgb, second: Rgb): number {
  const firstLuminance = relativeLuminance(first);
  const secondLuminance = relativeLuminance(second);
  const lighter = Math.max(firstLuminance, secondLuminance);
  const darker = Math.min(firstLuminance, secondLuminance);
  return (lighter + 0.05) / (darker + 0.05);
}

function clamp(value: number): number {
  return Math.min(1, Math.max(0, value));
}

function gammaEncode(value: number): number {
  return value <= 0.0031308 ? 12.92 * value : 1.055 * value ** (1 / 2.4) - 0.055;
}

function gammaDecode(value: number): number {
  return value <= 0.04045 ? value / 12.92 : ((value + 0.055) / 1.055) ** 2.4;
}
