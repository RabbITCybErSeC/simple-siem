import { zodResolver } from "@hookform/resolvers/zod";
import { ShieldCheckIcon } from "lucide-react";
import { useState } from "react";
import { useForm } from "react-hook-form";
import { Navigate, useSearchParams } from "react-router";
import { z } from "zod";
import { ApiError } from "../../api/client";
import { Button } from "../../components/ui/button";
import {
  Field,
  FieldError,
  FieldGroup,
} from "../../components/ui/field";
import { Input } from "../../components/ui/input";
import { Label } from "../../components/ui/label";
import { safeNextPath, useCurrentUser, useSignIn } from "./session";
import "./login-waves.css";

const loginSchema = z.object({
  email: z.email("Enter a valid email address."),
  password: z.string().min(1, "Enter your password."),
});

type LoginValues = z.infer<typeof loginSchema>;

// One period is 1440 units wide; the path holds two so translate(-50%) loops.
const WAVE_PATH =
  "M0 160 C240 100 480 100 720 160 S1200 220 1440 160 S1920 100 2160 160 S2640 220 2880 160 V320 H0 Z";

export function LoginPage() {
  const [searchParams] = useSearchParams();
  const currentUser = useCurrentUser();
  const signIn = useSignIn();
  const [serverMessage, setServerMessage] = useState<string | null>(null);
  const next = searchParams.get("next");

  const form = useForm<LoginValues>({
    resolver: zodResolver(loginSchema),
    defaultValues: { email: "", password: "" },
    shouldFocusError: true,
  });
  const { errors } = form.formState;

  if (currentUser.data) {
    return <Navigate to={safeNextPath(next)} replace />;
  }

  const sessionMessage =
    serverMessage === null && searchParams.get("reason") === "expired"
      ? "Your session ended. Sign in again."
      : null;

  const onSubmit = form.handleSubmit(async (values) => {
    setServerMessage(null);
    try {
      await signIn.mutateAsync(values);
    } catch (error) {
      setServerMessage(loginErrorMessage(error));
      form.resetField("password");
    }
  });

  return (
    <main className="relative isolate flex min-h-svh flex-col items-center justify-center p-4 text-foreground sm:p-6">
      <title>Sign in · Simple SIEM</title>

      <div aria-hidden="true" className="login-backdrop -z-10">
        {(["back", "middle", "front"] as const).map((layer) => (
          <svg
            key={layer}
            className={`login-wave login-wave--${layer}`}
            viewBox="0 0 2880 320"
            preserveAspectRatio="none"
            focusable="false"
          >
            <path d={WAVE_PATH} />
          </svg>
        ))}
      </div>

      <div className="mb-6 flex items-center gap-2.5">
        <span className="flex size-9 items-center justify-center rounded-xl bg-primary text-primary-foreground shadow-sm">
          <ShieldCheckIcon aria-hidden="true" className="size-5" />
        </span>
        <span className="text-base font-semibold tracking-tight">
          Simple SIEM
        </span>
      </div>

      <section className="w-full max-w-sm rounded-xl border bg-card text-card-foreground shadow-lg shadow-foreground/5">
        <div className="space-y-1 px-6 pt-6 sm:px-8 sm:pt-8">
          <h1 className="text-xl font-semibold tracking-tight">
            Sign in to Simple SIEM
          </h1>
          <p className="text-sm text-muted-foreground">
            Use your work email and password.
          </p>
        </div>

        <form
          className="px-6 pt-6 pb-6 sm:px-8 sm:pb-8"
          onSubmit={onSubmit}
          noValidate
        >
          <FieldGroup className="gap-4">
            <Field data-invalid={errors.email !== undefined}>
              <Label htmlFor="email">Email</Label>
              <Input
                id="email"
                type="email"
                autoComplete="username"
                className="h-9"
                aria-invalid={errors.email !== undefined}
                aria-describedby={errors.email ? "email-error" : undefined}
                {...form.register("email")}
              />
              <FieldError
                id="email-error"
                errors={errors.email ? [errors.email] : []}
              />
            </Field>
            <Field data-invalid={errors.password !== undefined}>
              <Label htmlFor="password">Password</Label>
              <Input
                id="password"
                type="password"
                autoComplete="current-password"
                className="h-9"
                aria-invalid={errors.password !== undefined}
                aria-describedby={
                  errors.password ? "password-error" : undefined
                }
                {...form.register("password")}
              />
              <FieldError
                id="password-error"
                errors={errors.password ? [errors.password] : []}
              />
            </Field>
          </FieldGroup>
          {serverMessage !== null && (
            <div
              role="alert"
              className="mt-4 rounded-lg border border-destructive/30 bg-destructive/10 px-3 py-2 text-sm text-foreground"
            >
              {serverMessage}
            </div>
          )}
          {sessionMessage !== null && (
            <p
              role="status"
              className="mt-4 rounded-lg bg-muted px-3 py-2 text-sm text-foreground"
            >
              {sessionMessage}
            </p>
          )}
          <Button
            type="submit"
            size="lg"
            className="mt-6 w-full"
            disabled={signIn.isPending}
          >
            Sign in
          </Button>
        </form>
      </section>
    </main>
  );
}

function loginErrorMessage(error: unknown): string {
  if (error instanceof ApiError) {
    if (error.status === 401) {
      return "Email or password is incorrect.";
    }
    if (error.status === 429) {
      return "Too many attempts. Wait a minute and try again.";
    }
  }
  return "Something went wrong. Try again.";
}
