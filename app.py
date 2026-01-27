import modal
import os
import hmac
import hashlib
import logging
import httpx
import json
import time
import re
import yaml
import asyncio
from urllib.parse import urlparse
from collections import deque
from dataclasses import dataclass, field
from typing import Optional
from fastapi import Request, HTTPException

# Configure logging
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("modal-github-runner")

# =============================================================================
# CONFIGURATION
# =============================================================================

# Runner version - configurable via environment for security updates
RUNNER_VERSION = os.environ.get("RUNNER_VERSION", "2.311.0")

# Sandbox timeout
TIMEOUT_SECONDS = 3600

# Request body size limit (1MB)
MAX_BODY_SIZE = 1_000_000

# Rate limiting - in-memory deduplication
JOB_DEDUP_WINDOW_SECONDS = 300  # 5 minutes
MAX_PROCESSED_CACHE_SIZE = 10000

# Replay protection - delivery ID cache
DELIVERY_CACHE_MAX_SIZE = 10000

# Repository allowlist (comma-separated, empty = allow all)
# Set via environment: ALLOWED_REPOS="owner/repo1,owner/repo2"
ALLOWED_REPOS_STR = os.environ.get("ALLOWED_REPOS", "")
ALLOWED_REPOS = [r.strip() for r in ALLOWED_REPOS_STR.split(",") if r.strip()]

# HTTP client timeout
HTTP_TIMEOUT_SECONDS = 30.0

# Stale run cleanup threshold (24 hours)
RUN_STALE_THRESHOLD_SECONDS = 86400

# =============================================================================
# DATA STRUCTURES
# =============================================================================


@dataclass
class QueuedJob:
    """A job waiting in the queue for a slot to open."""

    job_id: str
    jit_config: str
    provider: str
    run_id: str
    repo_full_name: str
    created_at: float = field(default_factory=time.time)


@dataclass
class RunConfig:
    """Configuration for a single workflow run, including queue and limits."""

    max_parallel: int
    active_count: int = 0
    queue: deque[QueuedJob] = field(default_factory=deque)
    workflow_name: str = ""
    created_at: float = field(default_factory=time.time)


@dataclass
class ActiveJob:
    """A job currently running in a sandbox."""

    sandbox: modal.Sandbox
    run_id: str
    created_at: float = field(default_factory=time.time)


# =============================================================================
# MODAL APP CONFIGURATION
# =============================================================================

# Pinned dependency versions for reproducibility and supply chain security
runner_image = (
    modal.Image.debian_slim()
    .apt_install("curl", "git", "ca-certificates", "sudo", "jq")
    .pip_install("fastapi==0.115.0", "httpx==0.27.0", "pyyaml")
    .run_commands(
        "mkdir -p /actions-runner",
        f"curl -L https://github.com/actions/runner/releases/download/v{RUNNER_VERSION}/actions-runner-linux-x64-{RUNNER_VERSION}.tar.gz | tar -xz -C /actions-runner",
        "/actions-runner/bin/installdependencies.sh",
    )
)

app = modal.App("modal-github-runner")

# Secrets should contain GITHUB_TOKEN, WEBHOOK_SECRET, and optionally ALLOWED_REPOS
github_secret = modal.Secret.from_name("github-secret")


# =============================================================================
# HELPER FUNCTIONS
# =============================================================================


def _validate_github_url(url: str) -> bool:
    """Validate URL is a legitimate GitHub API URL."""
    if not url:
        return False
    try:
        parsed = urlparse(url)
        # Only allow github.com and api.github.com
        # Also support GitHub Enterprise with custom domains if needed
        allowed_domains = {"github.com", "api.github.com"}
        github_enterprise_domain = os.environ.get("GITHUB_ENTERPRISE_DOMAIN", "")
        if github_enterprise_domain:
            allowed_domains.add(github_enterprise_domain)
            allowed_domains.add(f"api.{github_enterprise_domain}")

        return parsed.netloc in allowed_domains and parsed.scheme == "https"
    except Exception:
        return False


def _sanitize_error_message(error_text: str, max_length: int = 200) -> str:
    """Sanitize error messages to prevent information disclosure."""
    if not error_text:
        return "[empty response]"

    # Remove potential sensitive patterns
    sanitized = re.sub(
        r'(token|key|secret|password|auth)["\']?\s*[:=]\s*["\']?[^"\'\s]+',
        r"\1=[REDACTED]",
        error_text,
        flags=re.IGNORECASE,
    )

    # Truncate to prevent log flooding
    if len(sanitized) > max_length:
        sanitized = sanitized[:max_length] + "...[truncated]"

    return sanitized


async def verify_signature(request: Request, body: bytes) -> str | None:
    """
    Verify GitHub webhook signature using HMAC-SHA256.
    Returns the X-GitHub-Delivery header value if valid, for replay protection.
    """
    webhook_secret = os.environ.get("WEBHOOK_SECRET")
    if not webhook_secret:
        logger.error("Webhook secret not configured")
        raise HTTPException(status_code=500, detail="Internal server error")

    # Validate Content-Type
    content_type = request.headers.get("Content-Type", "")
    if "application/json" not in content_type:
        logger.warning(f"Invalid Content-Type: {content_type}")
        raise HTTPException(status_code=400, detail="Invalid Content-Type")

    signature = request.headers.get("X-Hub-Signature-256")
    if not signature:
        logger.error("Missing X-Hub-Signature-256 header")
        raise HTTPException(status_code=403, detail="Signature missing")

    # Get delivery ID for replay protection
    delivery_id = request.headers.get("X-GitHub-Delivery")
    if not delivery_id:
        logger.warning("Missing X-GitHub-Delivery header")
        raise HTTPException(status_code=400, detail="Missing delivery ID")

    hash_object = hmac.new(webhook_secret.encode(), msg=body, digestmod=hashlib.sha256)
    expected_signature = "sha256=" + hash_object.hexdigest()

    if not hmac.compare_digest(expected_signature, signature):
        logger.error("Invalid signature")
        raise HTTPException(status_code=403, detail="Invalid signature")

    return delivery_id


async def fetch_workflow_max_parallel(
    repo_url: str, workflow_name: str, github_token: str
) -> int:
    """
    Fetch the max-parallel setting from a workflow YAML file.
    Returns the max-parallel value if found, or a sensible default (2).
    """
    try:
        headers = {
            "Authorization": f"Bearer {github_token}",
            "Accept": "application/vnd.github+json",
            "X-GitHub-Api-Version": "2022-11-28",
        }

        async with httpx.AsyncClient(timeout=HTTP_TIMEOUT_SECONDS) as client:
            # List workflow runs to get the workflow file path
            response = await client.get(
                f"{repo_url}/actions/workflows",
                headers=headers,
            )
            response.raise_for_status()

            workflows = response.json().get("workflows", [])
            workflow_file = None
            for wf in workflows:
                if wf.get("name") == workflow_name:
                    workflow_file = wf.get("path")
                    break

            if not workflow_file:
                logger.warning(f"Could not find workflow file for: {workflow_name}")
                return 2  # Default

            # Fetch the workflow YAML content
            response = await client.get(
                f"{repo_url}/contents/{workflow_file}",
                headers=headers,
            )
            response.raise_for_status()

            import base64

            content = base64.b64decode(response.json()["content"]).decode("utf-8")

            # Parse YAML to find max-parallel
            config = yaml.safe_load(content)

            # Check job-level max-parallel
            jobs = config.get("jobs", {})
            for job_name, job_config in jobs.items():
                if isinstance(job_config, dict):
                    strategy = job_config.get("strategy", {})
                    max_parallel = strategy.get("max-parallel")
                    if max_parallel is not None:
                        logger.info(
                            f"Found max-parallel={max_parallel} for job '{job_name}' "
                            f"in workflow '{workflow_name}'"
                        )
                        return int(max_parallel)

            # Check global strategy max-parallel
            global_strategy = config.get("strategy", {})
            max_parallel = global_strategy.get("max-parallel")
            if max_parallel is not None:
                logger.info(
                    f"Found global max-parallel={max_parallel} in workflow '{workflow_name}'"
                )
                return int(max_parallel)

            logger.info(f"No max-parallel found in '{workflow_name}', using default: 2")
            return 2  # Default if not specified

    except Exception as e:
        logger.warning(f"Failed to fetch max-parallel for '{workflow_name}': {e}")
        return 2  # Default on any error


# =============================================================================
# GITHUB RUNNER CLASS (SINGLETON)
# =============================================================================


@app.cls(
    image=runner_image,
    secrets=[github_secret],
    concurrency_limit=1,  # Force singleton to maintain queue state
    keep_warm=1,  # Keep container alive to preserve queue state
)
class GitHubRunner:
    # Per-run configuration (keyed by run_id)
    _run_configs: dict[str, RunConfig] = field(default_factory=dict)

    # Active jobs (keyed by job_id for cancellation lookup)
    _active_jobs: dict[str, ActiveJob] = field(default_factory=dict)

    # Dedup caches
    _processed_jobs: dict[str, float] = field(default_factory=dict)
    _processed_deliveries: set[str] = field(default_factory=set)

    def __enter__(self):
        # Initialize containers when the class starts
        self._run_configs = {}
        self._active_jobs = {}
        self._processed_jobs = {}
        self._processed_deliveries = set()

    def _cleanup_job_cache(self):
        """Remove expired entries from job deduplication cache."""
        if len(self._processed_jobs) > MAX_PROCESSED_CACHE_SIZE:
            current_time = time.time()
            self._processed_jobs = {
                job_id: timestamp
                for job_id, timestamp in self._processed_jobs.items()
                if current_time - timestamp < JOB_DEDUP_WINDOW_SECONDS
            }

    def _cleanup_delivery_cache(self):
        """Limit delivery cache size to prevent memory issues."""
        if len(self._processed_deliveries) > DELIVERY_CACHE_MAX_SIZE:
            self._processed_deliveries = set(
                list(self._processed_deliveries)[DELIVERY_CACHE_MAX_SIZE // 2 :]
            )

    def _cleanup_stale_runs(self):
        """Remove run configs that have been inactive for too long."""
        current_time = time.time()
        stale_run_ids = [
            run_id
            for run_id, config in self._run_configs.items()
            if current_time - config.created_at > RUN_STALE_THRESHOLD_SECONDS
        ]
        for run_id in stale_run_ids:
            logger.info(f"Cleaning up stale run config: {run_id}")
            del self._run_configs[run_id]

    async def _spawn_sandbox(
        self,
        jit_config: str,
        job_id: str,
        run_id: str,
    ) -> modal.Sandbox:
        """Create a Modal sandbox with the given JIT config."""
        cmd = "cd /actions-runner && export RUNNER_ALLOW_RUNASROOT=1 && ./run.sh --jitconfig $GHA_JIT_CONFIG"

        sandbox = modal.Sandbox.create(
            "bash",
            "-c",
            cmd,
            image=runner_image,
            app=app,
            timeout=TIMEOUT_SECONDS,
            env={"GHA_JIT_CONFIG": jit_config},
        )

        # Tag sandbox for cancellation handling
        sandbox.set_tags({"job_id": str(job_id)})

        return sandbox

    async def _try_process_queue(self, run_id: str) -> Optional[modal.Sandbox]:
        """Try to spawn a job from the queue for the given run."""
        if run_id not in self._run_configs:
            return None

        config = self._run_configs[run_id]

        # Check if we have capacity and queued jobs
        if config.active_count >= config.max_parallel:
            return None

        if not config.queue:
            return None

        # Get oldest queued job
        queued_job = config.queue.popleft()

        try:
            # Create sandbox for the dequeued job
            sandbox = await self._spawn_sandbox(
                queued_job.jit_config, queued_job.job_id, run_id
            )

            # Track it
            self._active_jobs[str(queued_job.job_id)] = ActiveJob(
                sandbox=sandbox, run_id=run_id
            )
            config.active_count += 1

            logger.info(
                f"Dequeued and spawned job {queued_job.job_id} for run {run_id} "
                f"(active: {config.active_count}/{config.max_parallel}, queue remaining: {len(config.queue)})"
            )
            return sandbox
        except Exception as e:
            logger.error(f"Failed to spawn dequeued job {queued_job.job_id}: {e}")
            # Put it back at the front of the queue
            config.queue.appendleft(queued_job)
            return None

    @modal.fastapi_endpoint(method="POST")
    async def github_webhook(self, request: Request):
        # Check body size before reading
        content_length = request.headers.get("Content-Length")
        if content_length:
            try:
                if int(content_length) > MAX_BODY_SIZE:
                    logger.warning(f"Request body too large: {content_length} bytes")
                    raise HTTPException(status_code=413, detail="Payload too large")
            except ValueError:
                pass

        body = await request.body()

        # Verify actual body size
        if len(body) > MAX_BODY_SIZE:
            logger.warning(f"Request body too large: {len(body)} bytes")
            raise HTTPException(status_code=413, detail="Payload too large")

        # Verify signature and get delivery ID
        delivery_id = await verify_signature(request, body)

        if not delivery_id:
            raise HTTPException(status_code=400, detail="Missing delivery ID")

        if delivery_id in self._processed_deliveries:
            logger.warning(f"Duplicate delivery ID detected: {delivery_id}")
            return {"status": "duplicate", "message": "Request already processed"}

        self._cleanup_delivery_cache()
        self._processed_deliveries.add(delivery_id)

        try:
            payload = json.loads(body)
        except Exception as e:
            logger.error(f"Failed to parse JSON payload: {type(e).__name__}")
            raise HTTPException(status_code=400, detail="Invalid JSON")

        # Process webhook
        action = payload.get("action")
        workflow_run = payload.get("workflow_run", {})
        workflow_job = payload.get("workflow_job", {})
        run_id = str(workflow_run.get("id", "unknown"))
        job_id = str(workflow_job.get("id", "unknown"))
        job_name = workflow_job.get("name", "unknown")

        # Handle non-queued actions (cancellation, completion)
        if action != "queued":
            if action == "completed":
                conclusion = workflow_job.get("conclusion", "")

                if conclusion == "cancelled":
                    removed_from_queue = False

                    # Check if job was in the queue - remove it if found
                    if run_id in self._run_configs:
                        queue = self._run_configs[run_id].queue
                        for i, queued_job in enumerate(queue):
                            if queued_job.job_id == job_id:
                                del queue[i]
                                logger.info(
                                    f"Removed cancelled job {job_id} from queue"
                                )
                                removed_from_queue = True
                                break

                    # Check if job was in active jobs - terminate sandbox
                    if job_id in self._active_jobs:
                        try:
                            self._active_jobs[job_id].sandbox.terminate()
                            logger.info(
                                f"Terminated sandbox for cancelled job {job_id}"
                            )
                        except Exception as e:
                            logger.error(
                                f"Failed to terminate sandbox for job {job_id}: {type(e).__name__}"
                            )
                        finally:
                            del self._active_jobs[job_id]
                            # Decrement active count and try to process queue
                            if run_id in self._run_configs:
                                self._run_configs[run_id].active_count = max(
                                    0, self._run_configs[run_id].active_count - 1
                                )
                                await self._try_process_queue(run_id)

                    # Fallback: also check by tag for robustness
                    elif not removed_from_queue:
                        for sb in modal.Sandbox.list(
                            app_id=app.app_id, tags={"job_id": job_id}
                        ):
                            if sb.poll() is None:
                                logger.info(
                                    f"Terminating sandbox for cancelled job {job_id}"
                                )
                                try:
                                    sb.terminate()
                                except Exception as e:
                                    logger.error(
                                        f"Failed to terminate sandbox for job {job_id}: {type(e).__name__}"
                                    )

                    return {"status": "terminated", "job_id": job_id}

                # Normal completion
                if job_id in self._active_jobs:
                    del self._active_jobs[job_id]
                    if run_id in self._run_configs:
                        self._run_configs[run_id].active_count = max(
                            0, self._run_configs[run_id].active_count - 1
                        )
                        await self._try_process_queue(run_id)
                    logger.info(
                        f"Job {job_id} completed, active count: {self._run_configs[run_id].active_count}"
                    )

                return {"status": "completed", "job_id": job_id}

            logger.debug(
                f"Ignoring action '{action}' - only processing queued/completed jobs"
            )
            return {"status": "ignored"}

        # Handle queued action
        repo_url = payload.get("repository", {}).get("url")
        repo_full_name = payload.get("repository", {}).get("full_name", "")
        job_labels = workflow_job.get("labels", [])
        workflow_name = workflow_run.get("name", "")

        if "modal" not in job_labels:
            logger.info(
                f"Ignoring job {job_id} without 'modal' label (labels: {job_labels})"
            )
            return {"status": "ignored", "reason": "no modal label"}

        if ALLOWED_REPOS and repo_full_name not in ALLOWED_REPOS:
            logger.warning(f"Rejected webhook from unauthorized repo: {repo_full_name}")
            raise HTTPException(status_code=403, detail="Repository not authorized")

        if not repo_url:
            logger.error("Missing repository URL in payload")
            raise HTTPException(status_code=400, detail="Missing repository URL")

        if not _validate_github_url(repo_url):
            logger.error(
                f"Invalid repository URL domain: {urlparse(repo_url).netloc if repo_url else 'empty'}"
            )
            raise HTTPException(status_code=400, detail="Invalid repository URL")

        # Dedup
        current_time = time.time()
        if str(job_id) in self._processed_jobs:
            last_processed = self._processed_jobs[str(job_id)]
            if current_time - last_processed < JOB_DEDUP_WINDOW_SECONDS:
                logger.warning(f"Duplicate job ID detected: {job_id}")
                return {"status": "duplicate", "job_id": job_id}

        self._cleanup_job_cache()
        self._processed_jobs[str(job_id)] = current_time

        # Initialize run config
        if run_id not in self._run_configs:
            # We are inside the singleton actor, but multiple requests *might* interleave if we had concurrency > 1.
            # But with concurrency_limit=1, this is strictly sequential.
            # However, fetch is async, so we should still be careful if we ever increase concurrency.
            # But for now, simple check is fine.
            max_parallel = await fetch_workflow_max_parallel(
                repo_url, workflow_name, os.environ["GITHUB_TOKEN"]
            )
            self._run_configs[run_id] = RunConfig(
                max_parallel=max_parallel,
                workflow_name=workflow_name,
            )
            logger.info(
                f"Created run config for {repo_full_name}/{workflow_name} (run_id={run_id}) with max_parallel={max_parallel}"
            )

        run_config = self._run_configs[run_id]
        queue_position = len(run_config.queue) + run_config.active_count + 1

        runner_group_id = int(os.environ.get("RUNNER_GROUP_ID", 1))
        runner_labels = job_labels

        logger.info(
            f"Requesting JIT config for job {job_id} (run {run_id}, queue position: {queue_position})"
        )

        headers = {
            "Authorization": f"Bearer {os.environ['GITHUB_TOKEN']}",
            "Accept": "application/vnd.github+json",
        }
        data = {
            "name": f"modal-runner-{job_id}",
            "runner_group_id": runner_group_id,
            "labels": runner_labels,
            "work_directory": "_work",
        }

        async with httpx.AsyncClient(timeout=HTTP_TIMEOUT_SECONDS) as client:
            try:
                response = await client.post(
                    f"{repo_url}/actions/runners/generate-jitconfig",
                    headers=headers,
                    json=data,
                )
                response.raise_for_status()
                jit_config = response.json()["encoded_jit_config"]
            except Exception as e:
                logger.error(f"Failed to generate JIT config for job {job_id}: {e}")
                raise HTTPException(status_code=500, detail="Internal server error")

        # Provision or Queue
        if run_config.active_count < run_config.max_parallel:
            try:
                sandbox = await self._spawn_sandbox(jit_config, job_id, run_id)
                self._active_jobs[str(job_id)] = ActiveJob(
                    sandbox=sandbox, run_id=run_id
                )
                run_config.active_count += 1
                logger.info(
                    f"Provisioned runner for job {job_id} (active: {run_config.active_count}/{run_config.max_parallel})"
                )
                return {
                    "status": "provisioned",
                    "job_id": job_id,
                    "active_count": run_config.active_count,
                }
            except Exception as e:
                logger.error(f"Failed to create sandbox: {e}")
                raise HTTPException(
                    status_code=500, detail="Failed to spawn runner sandbox"
                )
        else:
            queued_job = QueuedJob(
                job_id=job_id,
                jit_config=jit_config,
                provider=job_name,
                run_id=run_id,
                repo_full_name=repo_full_name,
            )
            run_config.queue.append(queued_job)
            logger.info(
                f"Queued job {job_id} for run {run_id} (position: {len(run_config.queue)})"
            )
            return {
                "status": "queued",
                "job_id": job_id,
                "queue_position": len(run_config.queue),
                "active_count": run_config.active_count,
                "max_parallel": run_config.max_parallel,
            }
