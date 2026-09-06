import { apiInitializer } from "discourse/lib/api";

export default apiInitializer("1.14.0", (api) => {
  let mounted = false;
  const mount = () => {
    if (mounted || !document.body) return;
    mounted = true;
    const frame = document.createElement("iframe");
    frame.hidden = true;
    frame.setAttribute("aria-hidden", "true");
    frame.src = "/discourse-arz-tools/sso-bootstrap";
    document.body.appendChild(frame);
    setTimeout(() => frame.remove(), 12000);
  };

  window.addEventListener("message", (event) => {
    if (event.origin !== window.location.origin || event.source === window) return;
    if (event.data?.namespace !== "arz-sso" || event.data?.version !== 1 || event.data?.action !== "arz-sso:reload") return;
    window.location.reload();
  });

  api.onPageChange(mount);
});
