import { afterEach, beforeEach, describe, expect, it, vi } from "vitest";
import { render, screen } from "@testing-library/react";
import { useProject } from "@/platform/project";
import { useWebPreview } from "./browsers";
import { WebEditor } from "./WebEditor";

const web = vi.hoisted(() => ({ url: vi.fn() }));

vi.mock("./browsers", async (importOriginal) => {
  const original = await importOriginal<typeof import("./browsers")>();
  return { ...original, webUrl: web.url };
});

vi.mock("@/platform/ipc", async (importOriginal) => {
  const original = await importOriginal<typeof import("@/platform/ipc")>();
  return { ...original, onIdeEvent: () => () => {} };
});

vi.mock("@/ui", () => ({ FloatingToolbar: () => null, IconButton: () => null, hasIcon: () => false }));

describe("HTML preview sandbox", () => {
  beforeEach(() => {
    web.url.mockResolvedValue("http://127.0.0.1:63342/token/project/index.html");
    useWebPreview.setState({ "/project/index.html": true });
  });

  afterEach(() => {
    useWebPreview.setState({});
    useProject.setState({ project: null, settings: null, opening: false, lightEdit: false });
    vi.clearAllMocks();
  });

  it("keeps Restricted Mode preview with only script execution enabled", async () => {
    useProject.setState({ project: { root: "/project", trusted: false } as never });
    render(<WebEditor path="/project/index.html" tabId="index" children={null} />);

    expect(await screen.findByTitle("HTML preview")).toHaveAttribute("sandbox", "allow-scripts");
  });

  it("retains the existing sandbox permissions for trusted projects", async () => {
    useProject.setState({ project: { root: "/project", trusted: true } as never });
    render(<WebEditor path="/project/index.html" tabId="index" children={null} />);

    expect(await screen.findByTitle("HTML preview")).toHaveAttribute(
      "sandbox",
      "allow-scripts allow-same-origin allow-forms allow-modals allow-popups",
    );
  });

  it("uses the Restricted Mode sandbox until trust is explicitly known", async () => {
    useProject.setState({ project: null });
    render(<WebEditor path="/project/index.html" tabId="index" children={null} />);

    expect(await screen.findByTitle("HTML preview")).toHaveAttribute("sandbox", "allow-scripts");
  });
});
