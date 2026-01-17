import modal
import os
import requests
from fastapi import Request

# Define the image directly in this file
runner_image = modal.Image.debian_slim().apt_install(
    'curl',
    'git',
    'ca-certificates',
    'sudo',
    'jq'
).pip_install("fastapi", "requests").run_commands(
    'mkdir /actions-runner',
    'curl -L https://github.com/actions/runner/releases/download/v2.311.0/actions-runner-linux-x64-2.311.0.tar.gz | tar -xz -C /actions-runner',
    '/actions-runner/bin/installdependencies.sh',
    # Create a non-root user to run the runner
    'useradd -m runner',
    'chown -R runner:runner /actions-runner'
)

app = modal.App("modal-github-runner")

github_secret = modal.Secret.from_name("github-secret")

@app.function(image=runner_image, secrets=[github_secret])
@modal.fastapi_endpoint(method="POST")
async def github_webhook(request: Request):
    payload = await request.json()

    if payload.get("action") != "queued":
        return {"status": "ignored"}

    workflow_job = payload.get("workflow_job", {})
    repo_url = payload["repository"]["url"]
    job_id = workflow_job.get("id", "unknown")

    headers = {
        "Authorization": f"Bearer {os.environ['GITHUB_TOKEN']}",
        "Accept": "application/vnd.github+json",
    }
    
    data = {
        "name": f"modal-runner-{job_id}",
        "runner_group_id": 1,
        "labels": ["self-hosted", "modal"],
        "work_directory": "_work",
    }
    
    print(f"Requesting JIT config for job {job_id}...")
    response = requests.post(f"{repo_url}/actions/runners/generate-jitconfig", headers=headers, json=data)
    response.raise_for_status()

    jit_config = response.json()['encoded_jit_config']

    print(f"Spawning sandbox for job {job_id}...")
    
    # Run as the 'runner' user to avoid root issues
    # We use a completely fresh working directory inside the runner's home
    modal.Sandbox.create(
        "bash", "-c", f"cp -r /actions-runner/* ~/ && ./run.sh --jitconfig {jit_config}",
        image=runner_image,
        app=app,
        user="runner",
        workdir="/home/runner",
        timeout=3600
    )

    return {"status": "provisioned", "job_id": job_id}
