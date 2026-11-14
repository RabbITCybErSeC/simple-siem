import { afterEach, describe, expect, it, vi } from "vitest";
import { ApiError, apiRequest, get, post } from "./client";

type FetchFunction = (input: string, init: RequestInit) => Promise<Response>;

function stubFetch(response: Response) {
  const fetchMock = vi.fn<FetchFunction>().mockResolvedValue(response);
  vi.stubGlobal("fetch", fetchMock);
  return fetchMock;
}

function stubRejectedFetch(error: Error) {
  const fetchMock = vi.fn<FetchFunction>().mockRejectedValue(error);
  vi.stubGlobal("fetch", fetchMock);
  return fetchMock;
}

function jsonResponse(body: unknown, status = 200): Response {
  return new Response(JSON.stringify(body), {
    status,
    headers: { "Content-Type": "application/json" },
  });
}

function requestInit(
  fetchMock: ReturnType<typeof stubFetch>,
  call = 0,
): RequestInit {
  const init = fetchMock.mock.calls[call]?.[1];
  if (!init) {
    throw new Error(`fetch call ${call} has no init`);
  }
  return init;
}

function headersOf(init: RequestInit): Record<string, string> {
  return init.headers as Record<string, string>;
}

afterEach(() => {
  vi.unstubAllGlobals();
});

describe("apiRequest", () => {
  it("prefixes the path and sends same-origin credentials", async () => {
    const fetchMock = stubFetch(jsonResponse({}));

    await apiRequest("GET", "/users");

    const [url, init] = fetchMock.mock.calls[0];
    expect(url).toBe("/api/v1/users");
    expect(init.method).toBe("GET");
    expect(init.credentials).toBe("same-origin");
  });

  it("sends the console headers without an Authorization header on GET", async () => {
    const fetchMock = stubFetch(jsonResponse({}));

    await apiRequest("GET", "/me");

    const init = requestInit(fetchMock);
    const headers = headersOf(init);
    expect(headers).toMatchObject({
      Accept: "application/json",
      "X-Requested-With": "simple-siem",
    });
    expect(headers).not.toHaveProperty("Content-Type");
    expect(headers).not.toHaveProperty("Authorization");
    expect(init.body).toBeUndefined();
  });

  it("sends JSON content type and body on a POST with a body", async () => {
    const fetchMock = stubFetch(jsonResponse({}));

    await apiRequest("POST", "/auth/login", { email: "analyst@example.test" });

    const init = requestInit(fetchMock);
    const headers = headersOf(init);
    expect(headers).toMatchObject({
      "Content-Type": "application/json",
      "X-Requested-With": "simple-siem",
    });
    expect(headers).not.toHaveProperty("Authorization");
    expect(init.body).toBe(
      JSON.stringify({ email: "analyst@example.test" }),
    );
  });

  it("sends no content type on a POST without a body", async () => {
    const fetchMock = stubFetch(jsonResponse({}));

    await apiRequest("POST", "/auth/logout");

    const init = requestInit(fetchMock);
    const headers = headersOf(init);
    expect(headers).not.toHaveProperty("Content-Type");
    expect(headers["X-Requested-With"]).toBe("simple-siem");
    expect(init.body).toBeUndefined();
  });

  it("returns the parsed JSON body", async () => {
    stubFetch(jsonResponse({ id: "user_123", displayName: "Analyst" }));

    await expect(apiRequest("GET", "/me")).resolves.toEqual({
      id: "user_123",
      displayName: "Analyst",
    });
  });

  it("returns undefined for a 204 response", async () => {
    stubFetch(new Response(null, { status: 204 }));

    await expect(apiRequest("DELETE", "/me/sessions/1")).resolves.toBeUndefined();
  });

  it("returns undefined for an empty success body", async () => {
    stubFetch(new Response("", { status: 200 }));

    await expect(apiRequest("GET", "/me")).resolves.toBeUndefined();
  });

  it("throws the API error envelope as an ApiError", async () => {
    stubFetch(
      jsonResponse(
        {
          error: {
            code: "VERSION_CONFLICT",
            message: "stale",
            details: { version: 3 },
          },
        },
        409,
      ),
    );

    const request = apiRequest("PATCH", "/cases/1", { version: 2 });
    await expect(request).rejects.toBeInstanceOf(ApiError);
    await expect(request).rejects.toMatchObject({
      status: 409,
      code: "VERSION_CONFLICT",
      message: "stale",
      details: { version: 3 },
    });
  });

  it("defaults error details to an empty object", async () => {
    stubFetch(
      jsonResponse(
        { error: { code: "NOT_FOUND", message: "missing" } },
        404,
      ),
    );

    await expect(apiRequest("GET", "/cases/1")).rejects.toMatchObject({
      status: 404,
      code: "NOT_FOUND",
      details: {},
    });
  });

  it.each([
    ["an HTML proxy page", "<html>Bad gateway</html>"],
    ["invalid JSON", "not json"],
    ["an empty body", ""],
    ["a malformed envelope", JSON.stringify({ error: { code: 502 } })],
  ])("maps %s to INTERNAL_ERROR without exposing it", async (_label, body) => {
    stubFetch(new Response(body, { status: 502 }));

    const request = apiRequest("GET", "/users");
    await expect(request).rejects.toMatchObject({
      status: 502,
      code: "INTERNAL_ERROR",
      message: "Unexpected response from the server",
    });
    await request.catch((error: unknown) => {
      expect(error).toBeInstanceOf(ApiError);
      expect((error as ApiError).message).not.toContain("Bad gateway");
    });
  });

  it("maps a rejected fetch to NETWORK_ERROR", async () => {
    stubRejectedFetch(new TypeError("Failed to fetch"));

    const request = apiRequest("GET", "/me");
    await expect(request).rejects.toBeInstanceOf(ApiError);
    await expect(request).rejects.toMatchObject({
      status: 0,
      code: "NETWORK_ERROR",
      message: "Network request failed",
    });
  });
});

describe("request helpers", () => {
  it("get and post select their methods", async () => {
    const fetchMock = vi
      .fn<FetchFunction>()
      .mockImplementation(async () => jsonResponse({}));
    vi.stubGlobal("fetch", fetchMock);

    await get("/me");
    await post("/auth/logout");

    expect(fetchMock.mock.calls[0][1].method).toBe("GET");
    expect(fetchMock.mock.calls[1][1].method).toBe("POST");
  });
});
