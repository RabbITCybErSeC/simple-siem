import { zodResolver } from "@hookform/resolvers/zod";
import { useState } from "react";
import { useForm } from "react-hook-form";
import { Navigate, useNavigate, useSearchParams } from "react-router";
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

const loginSchema = z.object({
  email: z.email("Enter a valid email address."),
  password: z.string().min(1, "Enter your password."),
});

type LoginValues = z.infer<typeof loginSchema>;

export function LoginPage() {
  const [searchParams] = useSearchParams();
  const navigate = useNavigate();
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
      void navigate(safeNextPath(next), { replace: true });
    } catch (error) {
      setServerMessage(loginErrorMessage(error));
      form.resetField("password");
    }
  });

  return (
    <main className="flex min-h-svh items-center justify-center bg-background p-6 text-foreground">
      <title>Sign in · Simple SIEM</title>
      <section className="w-full max-w-sm rounded-xl border border-border bg-card p-8 text-card-foreground shadow-sm">
        <h1 className="text-2xl font-semibold tracking-tight">
          Sign in to Simple SIEM
        </h1>
        <form className="mt-6" onSubmit={onSubmit} noValidate>
          <FieldGroup>
            <Field data-invalid={errors.email !== undefined}>
              <Label htmlFor="email">Email</Label>
              <Input
                id="email"
                type="email"
                autoComplete="username"
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
              className="mt-4 rounded-lg border border-destructive/30 bg-destructive/10 p-3 text-sm text-foreground"
            >
              {serverMessage}
            </div>
          )}
          {sessionMessage !== null && (
            <p role="status" className="mt-4 text-sm text-muted-foreground">
              {sessionMessage}
            </p>
          )}
          <Button
            type="submit"
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
