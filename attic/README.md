# attic — superseded, kept for reference

None of this is wired to anything. It is the hosting scaffolding from when REDCELL was a local
Python server plus a browser console, before the Cloudflare Worker became the product.

It is kept rather than deleted because the engines it wrapped are still live (as `redcell_*.py`,
vendorable from `/src/`), and because the deploy scripts document how the NIM key was handled
without ever printing it — which is worth keeping if the live engine is ever hosted again.

| File | Was |
|---|---|
| `server.py` | stdlib HTTP server on 127.0.0.1 serving the console and the live engine |
| `console.html` | the browser UI it served |
| `Dockerfile`, `docker-compose.yml`, `.dockerignore` | container build for that server |
| `fly.toml`, `deploy_fly.sh`, `set_fly_key.sh` | Fly.io deploy path |
| `render.yaml` | Render blueprint |
| `run.sh`, `run_public.sh` | local launchers |
| `HUGGINGFACE.md`, `CLOUDFLARE_WORKER.md` | notes for hosting routes not taken |

`fly.toml` names the app `redcell`. **That name is not ours** — `redcell.fly.dev` resolves to a
different product on a different stack, and flyctl has never been installed on this machine.
Anything here that implies we run on Fly is wrong; see DEPLOY.md.

The live deploy path is `npx wrangler deploy`. The current backend that is built but unhosted is
`services/api/`, not this.
